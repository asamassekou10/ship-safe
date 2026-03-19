import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

// GET — list monitored repos
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const repos = await prisma.monitoredRepo.findMany({
    where: { userId: session.user.id },
    orderBy: { updatedAt: 'desc' },
  });

  return NextResponse.json({ repos });
}

// POST — add a monitored repo
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { repo, branch = 'main', schedule, options = {} } = await req.json();
  if (!repo) return NextResponse.json({ error: 'repo is required' }, { status: 400 });

  // Validate cron expression (basic check)
  if (schedule && !/^[\d*,/-]+ [\d*,/-]+ [\d*,/-]+ [\d*,/-]+ [\d*,/-]+$/.test(schedule)) {
    return NextResponse.json({ error: 'Invalid cron expression' }, { status: 400 });
  }

  const existing = await prisma.monitoredRepo.findUnique({
    where: { userId_repo: { userId: session.user.id, repo } },
  });

  if (existing) {
    const updated = await prisma.monitoredRepo.update({
      where: { id: existing.id },
      data: { branch, schedule, options, enabled: true },
    });
    return NextResponse.json(updated);
  }

  const monitored = await prisma.monitoredRepo.create({
    data: { userId: session.user.id, repo, branch, schedule, options },
  });

  await logAudit({ userId: session.user.id, action: 'repo.monitored', target: repo, meta: { schedule } });

  return NextResponse.json(monitored, { status: 201 });
}

// DELETE — remove a monitored repo
export async function DELETE(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await req.json();
  await prisma.monitoredRepo.deleteMany({ where: { id, userId: session.user.id } });

  return NextResponse.json({ ok: true });
}
