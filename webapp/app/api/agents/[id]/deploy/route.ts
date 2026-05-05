import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

export const maxDuration = 15;

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL;
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;
const SUBDOMAIN_BASE      = process.env.VPS_SUBDOMAIN_BASE || 'agents.shipsafecli.com';

async function readJsonOrThrow<T>(res: Response, label: string): Promise<T> {
  const contentType = res.headers.get('content-type') ?? '';
  const text = await res.text();

  if (!contentType.includes('application/json')) {
    const preview = text.replace(/\s+/g, ' ').slice(0, 220);
    throw new Error(`${label} returned ${res.status} ${contentType || 'unknown content-type'} instead of JSON. Check ORCHESTRATOR_URL. Preview: ${preview}`);
  }

  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${label} returned invalid JSON. Check ORCHESTRATOR_URL and orchestrator logs.`);
  }
}

/** POST /api/agents/[id]/deploy */
export async function POST(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  if (!ORCHESTRATOR_URL || !ORCHESTRATOR_SECRET) {
    return NextResponse.json({ error: 'Deployment not configured on this server' }, { status: 503 });
  }

  const LLM_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY', 'MOONSHOT_API_KEY', 'XAI_API_KEY'];

  const { id } = await params;
  const agent = await prisma.agent.findFirst({
    where: { id, userId: session.user.id },
  });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  // Block deploy if no LLM key — agent won't function without one
  const envVars = agent.envVars as Record<string, string>;
  const hasLLMKey = LLM_KEYS.some(k => envVars[k]?.trim());
  if (!hasLLMKey) {
    return NextResponse.json({
      error: 'Add an LLM API key before deploying. Go to Edit and add ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, DEEPSEEK_API_KEY, MOONSHOT_API_KEY, or XAI_API_KEY.',
    }, { status: 400 });
  }

  // Determine next deployment version
  const lastDeploy = await prisma.deployment.findFirst({
    where: { agentId: id },
    orderBy: { createdAt: 'desc' },
    select: { version: true },
  });
  const version = (lastDeploy?.version ?? 0) + 1;

  // Create a pending deployment record
  const deployment = await prisma.deployment.create({
    data: {
      agentId: id,
      version,
      status: 'pending',
      subdomain: agent.slug,
    },
  });

  // Update agent status
  await prisma.agent.update({ where: { id }, data: { status: 'deploying' } });

  // Start the VPS deployment job. The status route polls the orchestrator and
  // finalizes this pending deployment once Docker/nginx/certbot complete.
  try {
    const orchRes = await fetch(`${ORCHESTRATOR_URL}/deploy-async`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ORCHESTRATOR_SECRET}`,
      },
      body: JSON.stringify({
        deploymentId:   deployment.id,
        agentId:        id,
        slug:           agent.slug,
        tools:          agent.tools,
        memoryProvider: agent.memoryProvider,
        maxDepth:       agent.maxDepth,
        envVars:        agent.envVars,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!orchRes.ok) {
      const err = await readJsonOrThrow<{ error?: string }>(orchRes, 'Orchestrator deploy').catch((error) => ({ error: error instanceof Error ? error.message : 'Orchestrator error' }));
      const message = orchRes.status === 404
        ? 'The VPS orchestrator needs the latest async deploy update. Redeploy the orchestrator, then try again.'
        : err.error ?? 'Deploy failed';
      await prisma.deployment.update({
        where: { id: deployment.id },
        data: { status: 'failed', deployLog: message },
      });
      await prisma.agent.update({ where: { id }, data: { status: 'failed' } });
      return NextResponse.json({ error: message }, { status: 502 });
    }

    const result = await readJsonOrThrow<{ jobId: string; status: string }>(orchRes, 'Orchestrator deploy');

    return NextResponse.json({
      deployment: {
        id:          deployment.id,
        version,
        status:      'pending',
        jobId:       result.jobId,
        subdomain:   agent.slug,
        url:         `https://${agent.slug}.${SUBDOMAIN_BASE}`,
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Unknown error';
    await prisma.deployment.update({
      where: { id: deployment.id },
      data: { status: 'failed', deployLog: msg },
    });
    await prisma.agent.update({ where: { id }, data: { status: 'failed' } });
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
