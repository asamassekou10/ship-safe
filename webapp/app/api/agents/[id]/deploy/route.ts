import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL;
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;
const SUBDOMAIN_BASE      = process.env.VPS_SUBDOMAIN_BASE || 'agents.shipsafecli.com';

/** POST /api/agents/[id]/deploy */
export async function POST(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  if (!ORCHESTRATOR_URL || !ORCHESTRATOR_SECRET) {
    return NextResponse.json({ error: 'Deployment not configured on this server' }, { status: 503 });
  }

  const { id } = await params;
  const agent = await prisma.agent.findFirst({
    where: { id, userId: session.user.id },
  });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

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

  // Call the VPS orchestrator
  try {
    const orchRes = await fetch(`${ORCHESTRATOR_URL}/deploy`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ORCHESTRATOR_SECRET}`,
      },
      body: JSON.stringify({
        agentId:        id,
        slug:           agent.slug,
        tools:          agent.tools,
        memoryProvider: agent.memoryProvider,
        maxDepth:       agent.maxDepth,
        envVars:        agent.envVars,
      }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!orchRes.ok) {
      const err = await orchRes.json().catch(() => ({ error: 'Orchestrator error' }));
      await prisma.deployment.update({
        where: { id: deployment.id },
        data: { status: 'failed', deployLog: err.error ?? 'Deploy failed' },
      });
      await prisma.agent.update({ where: { id }, data: { status: 'failed' } });
      return NextResponse.json({ error: err.error ?? 'Deploy failed' }, { status: 502 });
    }

    const result = await orchRes.json() as {
      containerId: string;
      containerName: string;
      port: number;
      subdomain: string;
    };

    // Mark deployment as running
    await prisma.deployment.update({
      where: { id: deployment.id },
      data: {
        status:      'running',
        containerId: result.containerId,
        port:        result.port,
        subdomain:   result.subdomain,
        startedAt:   new Date(),
      },
    });
    await prisma.agent.update({ where: { id }, data: { status: 'deployed' } });

    return NextResponse.json({
      deployment: {
        id:          deployment.id,
        version,
        status:      'running',
        containerId: result.containerId,
        subdomain:   result.subdomain,
        url:         `https://${result.subdomain}.${SUBDOMAIN_BASE}`,
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
