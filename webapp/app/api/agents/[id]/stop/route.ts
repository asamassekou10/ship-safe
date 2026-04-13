import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

const ORCHESTRATOR_URL    = process.env.ORCHESTRATOR_URL;
const ORCHESTRATOR_SECRET = process.env.ORCHESTRATOR_SECRET;

/** POST /api/agents/[id]/stop */
export async function POST(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  if (!ORCHESTRATOR_URL || !ORCHESTRATOR_SECRET) {
    return NextResponse.json({ error: 'Deployment not configured on this server' }, { status: 503 });
  }

  const { id } = await params;
  const agent = await prisma.agent.findFirst({ where: { id, userId: session.user.id } });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const deploy = await prisma.deployment.findFirst({
    where: { agentId: id, status: 'running' },
    orderBy: { createdAt: 'desc' },
  });

  if (!deploy) {
    return NextResponse.json({ error: 'No running deployment found' }, { status: 400 });
  }

  try {
    const orchRes = await fetch(`${ORCHESTRATOR_URL}/stop`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ORCHESTRATOR_SECRET}`,
      },
      body: JSON.stringify({
        agentId:       id,
        slug:          agent.slug,
        containerName: `hermes-${id}`,
      }),
      signal: AbortSignal.timeout(15_000),
    });

    // Best-effort: update DB regardless of orchestrator response
    await prisma.deployment.update({
      where: { id: deploy.id },
      data: { status: 'stopped', stoppedAt: new Date() },
    });
    await prisma.agent.update({ where: { id }, data: { status: 'stopped' } });

    if (!orchRes.ok) {
      const err = await orchRes.json().catch(() => ({}));
      return NextResponse.json({ warning: 'Container may not have stopped cleanly', detail: err }, { status: 207 });
    }

    return NextResponse.json({ ok: true });
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Unknown error';
    // Still mark as stopped in DB
    await prisma.deployment.update({
      where: { id: deploy.id },
      data: { status: 'stopped', stoppedAt: new Date() },
    }).catch(() => {});
    await prisma.agent.update({ where: { id }, data: { status: 'stopped' } }).catch(() => {});
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
