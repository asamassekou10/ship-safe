import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL || 'http://localhost:4099';
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;

/**
 * POST /api/agents/[id]/chat
 * Body: { message: string, runId?: string }
 *
 * Creates/continues an AgentRun, saves user ChatMessage, then proxies
 * the SSE stream from the agent container back to the browser.
 * Collects the full response in the background and saves it to DB.
 */
export async function POST(req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;

  // Load agent + active deployment
  const agent = await prisma.agent.findFirst({
    where: { id, userId: session.user.id },
    include: {
      deployments: {
        where: { status: 'running' },
        orderBy: { createdAt: 'desc' },
        take: 1,
      },
    },
  });

  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const deployment = agent.deployments[0];
  if (!deployment) {
    return NextResponse.json({ error: 'Agent is not running. Deploy it first.' }, { status: 400 });
  }

  const body = await req.json();
  const message = (body.message || '').trim();
  if (!message) return NextResponse.json({ error: 'message is required' }, { status: 400 });

  // Create or reuse AgentRun (session)
  let run;
  if (body.runId) {
    run = await prisma.agentRun.findFirst({
      where: { id: body.runId, deploymentId: deployment.id },
    });
  }
  if (!run) {
    run = await prisma.agentRun.create({
      data: { deploymentId: deployment.id, status: 'running' },
    });
  }

  // Save user message
  await prisma.chatMessage.create({
    data: { runId: run.id, role: 'user', content: message },
  });

  // Route through the orchestrator proxy (port 4099, already open in firewall).
  // Agent containers bind to 127.0.0.1 so they're only reachable from the VPS itself.
  const agentUrl = `${ORCHESTRATOR_URL}/chat/${deployment.port}`;

  // Fetch from agent container
  let agentRes: Response;
  try {
    agentRes = await fetch(agentUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(ORCHESTRATOR_SECRET ? { 'X-Agent-Secret': ORCHESTRATOR_SECRET } : {}),
      },
      body: JSON.stringify({ message, sessionId: run.id }),
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Agent unreachable';
    await prisma.agentRun.update({ where: { id: run.id }, data: { status: 'error' } });
    return NextResponse.json({ error: msg }, { status: 502 });
  }

  if (!agentRes.ok || !agentRes.body) {
    return NextResponse.json({ error: 'Agent returned an error' }, { status: 502 });
  }

  // Stream back to browser while collecting response in background
  const [browserStream, collectorStream] = agentRes.body.tee();

  // Background: parse SSE stream and save assistant message to DB
  (async () => {
    try {
      const reader    = collectorStream.getReader();
      const decoder   = new TextDecoder();
      let   fullText  = '';
      let   tokens    = 0;
      const toolCalls: Array<{ tool: string; args: unknown; result?: string }> = [];
      let   pending   = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        pending += decoder.decode(value, { stream: true });

        const lines = pending.split('\n');
        pending = lines.pop() ?? '';

        let currentEvent = '';
        for (const line of lines) {
          if (line.startsWith('event: '))      { currentEvent = line.slice(7).trim(); }
          else if (line.startsWith('data: '))  {
            const raw = line.slice(6);
            try {
              const parsed = JSON.parse(raw);
              if (currentEvent === 'token' && typeof parsed === 'string') {
                fullText += parsed;
              } else if (currentEvent === 'tool_call') {
                toolCalls.push({ tool: parsed.tool, args: parsed.args });
              } else if (currentEvent === 'tool_result') {
                const last = toolCalls[toolCalls.length - 1];
                if (last && last.tool === parsed.tool) last.result = parsed.result;
              } else if (currentEvent === 'done') {
                tokens = parsed.tokensUsed ?? 0;
              }
            } catch {}
          }
        }
      }

      // Save assistant reply
      await prisma.chatMessage.create({
        data: {
          runId:     run.id,
          role:      'assistant',
          content:   fullText,
          toolCalls: toolCalls.length > 0 ? (toolCalls as object[]) : undefined,
          tokensUsed: tokens,
        },
      });

      await prisma.agentRun.update({
        where: { id: run.id },
        data: {
          status:     'completed',
          completedAt: new Date(),
          tokensUsed: { increment: tokens },
        },
      });
    } catch { /* background — don't affect the stream */ }
  })();

  // Inject runId as first SSE event so client knows the session
  const runIdChunk = new TextEncoder().encode(`event: run\ndata: ${JSON.stringify({ runId: run.id })}\n\n`);

  const merged = new ReadableStream({
    async start(controller) {
      controller.enqueue(runIdChunk);
      const reader = browserStream.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) { controller.close(); break; }
        controller.enqueue(value);
      }
    },
  });

  return new NextResponse(merged, {
    status: 200,
    headers: {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}

/**
 * GET /api/agents/[id]/chat?runId=xxx
 * Returns message history for a run.
 */
export async function GET(req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const runId  = req.nextUrl.searchParams.get('runId');

  const agent = await prisma.agent.findFirst({
    where: { id, userId: session.user.id },
    select: { id: true },
  });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  // List runs or fetch a specific run's messages
  if (runId) {
    const messages = await prisma.chatMessage.findMany({
      where: { runId },
      orderBy: { createdAt: 'asc' },
    });
    return NextResponse.json({ messages });
  }

  const runs = await prisma.agentRun.findMany({
    where: { deployment: { agentId: id } },
    orderBy: { startedAt: 'desc' },
    take: 20,
    select: {
      id: true, status: true, tokensUsed: true, startedAt: true, completedAt: true,
      messages: { orderBy: { createdAt: 'asc' }, take: 1, select: { content: true } },
    },
  });
  return NextResponse.json({ runs });
}
