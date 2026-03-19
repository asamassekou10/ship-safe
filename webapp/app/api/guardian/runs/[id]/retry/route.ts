import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { appendTimeline, advanceRun } from '@/lib/guardian/pipeline';

/**
 * POST /api/guardian/runs/[id]/retry — Retry a failed or blocked Guardian run.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const run = await prisma.pRGuardianRun.findFirst({
    where: { id, userId: session.user.id, status: { in: ['failed', 'blocked'] } },
  });

  if (!run) return NextResponse.json({ error: 'Run not found or not retryable' }, { status: 404 });

  await appendTimeline(run.id, 'Manual retry', `Restarted by user`);
  await prisma.pRGuardianRun.update({
    where: { id: run.id },
    data: { status: 'analyzing' },
  });

  advanceRun(run.id).catch(console.error);

  return NextResponse.json({ ok: true, status: 'analyzing' });
}
