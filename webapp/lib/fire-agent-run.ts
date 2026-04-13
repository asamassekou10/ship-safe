/**
 * fire-agent-run.ts
 *
 * Shared helper: POST a message to an agent container, collect the full SSE
 * stream, and persist the assistant reply + run completion to the DB.
 *
 * Used by both the chat route (alongside a browser stream) and the trigger
 * route (fire-and-forget, no browser involved).
 */

import { prisma } from '@/lib/prisma';

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL    || 'http://localhost:4099';
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;

interface ToolCallEntry {
  tool: string;
  args: unknown;
  result?: string;
}

/**
 * Fire the agent container for a given run, collect the response, and save it.
 * Returns once the run is complete (or failed).
 */
export async function fireAgentRun(opts: {
  runId:        string;
  deploymentPort: number;
  message:      string;
}): Promise<void> {
  const { runId, deploymentPort, message } = opts;

  let agentRes: Response;
  try {
    agentRes = await fetch(`${ORCHESTRATOR_URL}/chat/${deploymentPort}`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(ORCHESTRATOR_SECRET ? { Authorization: `Bearer ${ORCHESTRATOR_SECRET}` } : {}),
      },
      body: JSON.stringify({ message, sessionId: runId }),
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Agent unreachable';
    await prisma.agentRun.update({ where: { id: runId }, data: { status: 'error', completedAt: new Date() } });
    await prisma.chatMessage.create({ data: { runId, role: 'assistant', content: `Error: ${msg}` } });
    return;
  }

  if (!agentRes.ok || !agentRes.body) {
    await prisma.agentRun.update({ where: { id: runId }, data: { status: 'error', completedAt: new Date() } });
    await prisma.chatMessage.create({ data: { runId, role: 'assistant', content: 'Agent returned an error.' } });
    return;
  }

  // Collect SSE stream
  const reader    = agentRes.body.getReader();
  const decoder   = new TextDecoder();
  let   fullText  = '';
  let   tokens    = 0;
  const toolCalls: ToolCallEntry[] = [];
  let   pending   = '';
  let   currentEvent = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    pending += decoder.decode(value, { stream: true });

    const lines = pending.split('\n');
    pending = lines.pop() ?? '';

    for (const line of lines) {
      if (line.startsWith('event: '))     { currentEvent = line.slice(7).trim(); continue; }
      if (!line.startsWith('data: '))      continue;

      const raw = line.slice(6);
      let parsed: unknown;
      try { parsed = JSON.parse(raw); } catch { parsed = raw; }

      if (currentEvent === 'token') {
        fullText += typeof parsed === 'string' ? parsed : '';
      } else if (currentEvent === 'tool_call' && parsed && typeof parsed === 'object') {
        const tc = parsed as { tool: string; args: unknown };
        toolCalls.push({ tool: tc.tool, args: tc.args });
      } else if (currentEvent === 'tool_result' && parsed && typeof parsed === 'object') {
        const tr = parsed as { tool: string; result: string };
        const last = toolCalls[toolCalls.length - 1];
        if (last && last.tool === tr.tool) last.result = tr.result;
      } else if (currentEvent === 'done' && parsed && typeof parsed === 'object') {
        tokens = (parsed as { tokensUsed?: number }).tokensUsed ?? 0;
      }
    }
  }

  await prisma.chatMessage.create({
    data: {
      runId,
      role:      'assistant',
      content:   fullText,
      toolCalls: toolCalls.length > 0 ? (toolCalls as object[]) : undefined,
      tokensUsed: tokens,
    },
  });

  await prisma.agentRun.update({
    where: { id: runId },
    data: {
      status:     'completed',
      completedAt: new Date(),
      tokensUsed: { increment: tokens },
    },
  });
}
