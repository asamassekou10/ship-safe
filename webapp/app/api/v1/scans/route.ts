import { NextRequest, NextResponse } from 'next/server';
import { Prisma } from '@prisma/client';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { authenticateApiKey } from '@/lib/api-auth';
import { notifyScanComplete, notifyScanFailed } from '@/lib/notifications';
import { logAudit } from '@/lib/audit';
import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

const execAsync = promisify(exec);

async function resolveUser(req: NextRequest) {
  // Try API key first, then session
  const apiAuth = await authenticateApiKey(req);
  if (apiAuth) return apiAuth.userId;
  const session = await auth();
  return session?.user?.id ?? null;
}

// GET /api/v1/scans — list scans
export async function GET(req: NextRequest) {
  const userId = await resolveUser(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
  const cursor = url.searchParams.get('cursor') || undefined;
  const repo = url.searchParams.get('repo') || undefined;
  const status = url.searchParams.get('status') || undefined;

  const scans = await prisma.scan.findMany({
    where: {
      userId,
      ...(repo ? { repo: { contains: repo } } : {}),
      ...(status ? { status } : {}),
    },
    orderBy: { createdAt: 'desc' },
    take: limit + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    select: {
      id: true, repo: true, branch: true, status: true,
      score: true, grade: true, findings: true, secrets: true,
      vulns: true, cves: true, duration: true, trigger: true,
      createdAt: true,
    },
  });

  const hasMore = scans.length > limit;
  const data = hasMore ? scans.slice(0, limit) : scans;

  return NextResponse.json({
    data,
    pagination: {
      hasMore,
      nextCursor: hasMore ? data[data.length - 1].id : null,
    },
  });
}

// POST /api/v1/scans — create a scan
export async function POST(req: NextRequest) {
  const userId = await resolveUser(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const user = await prisma.user.findUnique({ where: { id: userId }, select: { plan: true } });
  if (user?.plan !== 'pro' && user?.plan !== 'team' && user?.plan !== 'enterprise') {
    return NextResponse.json(
      { error: 'Cloud scans require a Pro plan.' },
      { status: 403 },
    );
  }

  const body = await req.json();
  const { repo, branch = 'main', options = {} } = body;

  if (!repo) return NextResponse.json({ error: 'repo is required' }, { status: 400 });

  const scan = await prisma.scan.create({
    data: { userId, repo, branch, method: 'github', trigger: 'api', status: 'running', options },
  });

  await logAudit({ userId, action: 'scan.created', target: scan.id, meta: { repo, via: 'api' } });

  // Background scan
  runScanBackground(scan.id, userId, repo, branch, options).catch(console.error);

  return NextResponse.json({ id: scan.id, status: 'running', url: `/app/scans/${scan.id}` }, { status: 201 });
}

async function runScanBackground(scanId: string, userId: string, repo: string, branch: string, options: Record<string, boolean>) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-'));
  const startTime = Date.now();
  try {
    await execAsync(`git clone --depth 1 --branch ${branch} https://github.com/${repo}.git ${tmpDir}/repo`, { timeout: 60_000 });
    const flags: string[] = ['--json'];
    if (options.deep) flags.push('--deep');
    if (options.deps) flags.push('--deps');
    const { stdout } = await execAsync(`npx ship-safe audit ${tmpDir}/repo ${flags.join(' ')}`, { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
    const duration = (Date.now() - startTime) / 1000;
    let report: Record<string, unknown> = {};
    try { report = JSON.parse(stdout); } catch { report = { raw: stdout }; }
    const score = typeof report.score === 'number' ? report.score : null;
    const grade = typeof report.grade === 'string' ? report.grade : null;
    const findings = typeof report.totalFindings === 'number' ? report.totalFindings : 0;
    const cats = report.categories as Record<string, { findingCount?: number }> | undefined;
    const secrets = cats?.secrets?.findingCount ?? 0;
    const vulns = (cats?.injection?.findingCount ?? 0) + (cats?.auth?.findingCount ?? 0);
    const cves = typeof report.totalDepVulns === 'number' ? report.totalDepVulns : 0;
    const updated = await prisma.scan.update({ where: { id: scanId }, data: { status: 'done', score, grade, findings, secrets, vulns, cves, duration, report: report as Prisma.InputJsonValue } });
    await notifyScanComplete({ ...updated, userId });
  } catch (err) {
    const duration = (Date.now() - startTime) / 1000;
    const errorMsg = err instanceof Error ? err.message : String(err);
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'failed', duration, report: { error: errorMsg } as Prisma.InputJsonValue } });
    await notifyScanFailed({ id: scanId, repo, branch, score: null, grade: null, findings: 0, secrets: 0, vulns: 0, cves: 0, status: 'failed', userId }, errorMsg);
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
