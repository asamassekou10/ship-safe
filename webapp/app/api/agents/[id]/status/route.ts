import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL;
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;

async function tryReadJson<T>(res: Response): Promise<T | null> {
  const contentType = res.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) return null;
  try {
    return await res.json() as T;
  } catch {
    return null;
  }
}

/** GET /api/agents/[id]/status — latest deployment status */
export async function GET(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const agent = await prisma.agent.findFirst({
    where: { id, userId: session.user.id },
    select: { id: true, status: true, slug: true },
  });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const deploy = await prisma.deployment.findFirst({
    where: { agentId: id },
    orderBy: { createdAt: 'desc' },
    select: { id: true, status: true, containerId: true, port: true, subdomain: true, securityScore: true, deployLog: true },
  });

  // If no orchestrator or no running deployment, return DB state only
  if (!ORCHESTRATOR_URL || !ORCHESTRATOR_SECRET || !deploy) {
    return NextResponse.json({ agentStatus: agent.status, deployment: deploy ?? null });
  }

  if (deploy.status === 'pending') {
    try {
      const jobRes = await fetch(`${ORCHESTRATOR_URL}/deploy-status/${deploy.id}`, {
        headers: { 'Authorization': `Bearer ${ORCHESTRATOR_SECRET}` },
        signal: AbortSignal.timeout(5_000),
      });

      if (jobRes.ok) {
        const job = await tryReadJson<{
          status: 'running' | 'completed' | 'failed';
          error?: string | null;
          result?: {
            containerId: string;
            containerName: string;
            port: number;
            subdomain: string;
          } | null;
        }>(jobRes);

        if (job?.status === 'completed' && job.result) {
          const updated = await prisma.deployment.update({
            where: { id: deploy.id },
            data: {
              status:      'running',
              containerId: job.result.containerId,
              port:        job.result.port,
              subdomain:   job.result.subdomain,
              startedAt:   new Date(),
            },
            select: { id: true, status: true, containerId: true, port: true, subdomain: true, securityScore: true, deployLog: true },
          });
          await prisma.agent.update({ where: { id }, data: { status: 'deployed' } });
          return NextResponse.json({ agentStatus: 'deployed', deployment: updated, live: { running: true, status: 'running' } });
        }

        if (job?.status === 'failed') {
          const message = job.error || 'Deploy failed';
          const updated = await prisma.deployment.update({
            where: { id: deploy.id },
            data: { status: 'failed', deployLog: message },
            select: { id: true, status: true, containerId: true, port: true, subdomain: true, securityScore: true, deployLog: true },
          });
          await prisma.agent.update({ where: { id }, data: { status: 'failed' } });
          return NextResponse.json({ agentStatus: 'failed', deployment: updated, live: { running: false, status: 'failed' } });
        }
      }
    } catch {
      // Orchestrator unreachable or old orchestrator without job status.
    }

    return NextResponse.json({ agentStatus: agent.status, deployment: deploy, live: { running: false, status: 'deploying' } });
  }

  if (!deploy.containerId) {
    return NextResponse.json({ agentStatus: agent.status, deployment: deploy });
  }

  // Check live container status from orchestrator
  try {
    const containerName = `hermes-${id}`;
    const orchRes = await fetch(`${ORCHESTRATOR_URL}/status/${containerName}`, {
      headers: { 'Authorization': `Bearer ${ORCHESTRATOR_SECRET}` },
      signal: AbortSignal.timeout(5_000),
    });

    if (orchRes.ok) {
      const live = await tryReadJson<{ running: boolean; status: string }>(orchRes);
      if (!live) return NextResponse.json({ agentStatus: agent.status, deployment: deploy });

      // Sync DB if container stopped unexpectedly
      if (!live.running && deploy.status === 'running') {
        await prisma.deployment.update({
          where: { id: deploy.id },
          data: { status: 'stopped', stoppedAt: new Date() },
        });
        await prisma.agent.update({ where: { id }, data: { status: 'stopped' } });
        return NextResponse.json({ agentStatus: 'stopped', deployment: { ...deploy, status: 'stopped' }, live });
      }

      return NextResponse.json({ agentStatus: agent.status, deployment: deploy, live });
    }
  } catch {
    // Orchestrator unreachable — return DB state
  }

  return NextResponse.json({ agentStatus: agent.status, deployment: deploy });
}
