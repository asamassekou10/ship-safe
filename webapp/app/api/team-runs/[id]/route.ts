import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string }> };

/**
 * GET /api/team-runs/[id]
 *
 * Returns the full team run state: status, phase, report,
 * and all agent runs organized as a tree.
 */
export async function GET(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;

  const teamRun = await prisma.teamRun.findFirst({
    where: { id, userId: session.user.id },
    include: {
      team: { select: { id: true, name: true } },
      agentRuns: {
        orderBy: { startedAt: 'asc' },
        select: {
          id:          true,
          role:        true,
          status:      true,
          parentRunId: true,
          startedAt:   true,
          completedAt: true,
          tokensUsed:  true,
          deployment: {
            select: {
              agent: { select: { id: true, name: true } },
            },
          },
          _count: { select: { messages: true, findings: true } },
        },
      },
    },
  });

  if (!teamRun) return NextResponse.json({ error: 'Not found' }, { status: 404 });
  return NextResponse.json({ teamRun });
}

/**
 * DELETE /api/team-runs/[id]
 * Cancel a running team run.
 */
export async function DELETE(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;

  const updated = await prisma.teamRun.updateMany({
    where: { id, userId: session.user.id, status: 'running' },
    data:  { status: 'error', phase: 'done', completedAt: new Date(), report: 'Cancelled by user.' },
  });

  if (updated.count === 0) return NextResponse.json({ error: 'Run not found or already complete' }, { status: 404 });

  await prisma.agentRun.updateMany({
    where: { teamRunId: id, status: 'running' },
    data:  { status: 'error', completedAt: new Date() },
  });

  return NextResponse.json({ ok: true });
}
