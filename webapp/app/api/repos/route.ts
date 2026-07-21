import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const CRON_PATTERN = /^[\d*,/-]+ [\d*,/-]+ [\d*,/-]+ [\d*,/-]+ [\d*,/-]+$/;

function isValidSchedule(schedule: unknown): boolean {
  return schedule == null || (typeof schedule === 'string' && CRON_PATTERN.test(schedule));
}

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
  if (typeof repo !== 'string' || !REPO_PATTERN.test(repo)) {
    return NextResponse.json({ error: 'Enter a GitHub repository as owner/repo' }, { status: 400 });
  }

  if (!isValidSchedule(schedule)) {
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

// PATCH — update schedule, branch, or monitoring state
export async function PATCH(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json().catch(() => null) as {
    id?: unknown;
    branch?: unknown;
    schedule?: unknown;
    enabled?: unknown;
  } | null;
  const payload = body ?? {};
  const id = typeof payload.id === 'string' ? payload.id : '';
  if (!id) return NextResponse.json({ error: 'Repository id is required' }, { status: 400 });
  if (payload.schedule !== undefined && !isValidSchedule(payload.schedule)) {
    return NextResponse.json({ error: 'Invalid cron expression' }, { status: 400 });
  }
  if (payload.branch !== undefined && (typeof payload.branch !== 'string' || !payload.branch.trim())) {
    return NextResponse.json({ error: 'Branch is required' }, { status: 400 });
  }
  if (payload.enabled !== undefined && typeof payload.enabled !== 'boolean') {
    return NextResponse.json({ error: 'Invalid monitoring state' }, { status: 400 });
  }

  const existing = await prisma.monitoredRepo.findFirst({
    where: { id, userId: session.user.id },
    select: { id: true, repo: true },
  });
  if (!existing) return NextResponse.json({ error: 'Repository not found' }, { status: 404 });

  const updated = await prisma.monitoredRepo.update({
    where: { id },
    data: {
      ...(typeof payload.branch === 'string' ? { branch: payload.branch.trim() } : {}),
      ...(payload.schedule !== undefined ? { schedule: payload.schedule as string | null } : {}),
      ...(typeof payload.enabled === 'boolean' ? { enabled: payload.enabled } : {}),
    },
  });

  await logAudit({
    userId: session.user.id,
    action: payload.enabled === false ? 'repo.paused' : 'repo.updated',
    target: existing.repo,
    meta: { schedule: payload.schedule, enabled: payload.enabled },
  });

  return NextResponse.json(updated);
}

// DELETE — remove a monitored repo
export async function DELETE(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await req.json();
  await prisma.monitoredRepo.deleteMany({ where: { id, userId: session.user.id } });

  return NextResponse.json({ ok: true });
}
