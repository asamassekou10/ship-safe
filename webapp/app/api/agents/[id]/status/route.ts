import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL;
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;

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
    select: { id: true, status: true, containerId: true, subdomain: true, securityScore: true },
  });

  // If no orchestrator or no running deployment, return DB state only
  if (!ORCHESTRATOR_URL || !ORCHESTRATOR_SECRET || !deploy?.containerId) {
    return NextResponse.json({ agentStatus: agent.status, deployment: deploy ?? null });
  }

  // Check live container status from orchestrator
  try {
    const containerName = `hermes-${id}`;
    const orchRes = await fetch(`${ORCHESTRATOR_URL}/status/${containerName}`, {
      headers: { 'Authorization': `Bearer ${ORCHESTRATOR_SECRET}` },
      signal: AbortSignal.timeout(5_000),
    });

    if (orchRes.ok) {
      const live = await orchRes.json() as { running: boolean; status: string };

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
