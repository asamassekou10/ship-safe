import { NextRequest, NextResponse } from 'next/server';
import { Prisma } from '@prisma/client';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { authenticateApiKey } from '@/lib/api-auth';
import { notifyScanComplete, notifyScanFailed } from '@/lib/notifications';
import { logAudit } from '@/lib/audit';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { DISPLAY_HOST } from '@/lib/site';

const execFileAsync = promisify(execFile);

const REPO_RE   = /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/;
const BRANCH_RE = /^[a-zA-Z0-9/_.-]{1,256}$/;

const PAID_PLANS = ['pro', 'team', 'enterprise'];

const scanHits = new Map<string, { count: number; resetAt: number }>();
function checkScanRateLimit(userId: string): boolean {
  const now = Date.now();
  const entry = scanHits.get(userId);
  if (!entry || now >= entry.resetAt) {
    scanHits.set(userId, { count: 1, resetAt: now + 3_600_000 });
    return true;
  }
  if (entry.count >= 10) return false;
  entry.count++;
  return true;
}

async function resolveUser(
  req: NextRequest,
  scope: 'scan:read' | 'scan:write',
): Promise<{ userId: string; plan: string } | null> {
  const apiAuth = await authenticateApiKey(req, scope);
  if (apiAuth) {
    const user = await prisma.user.findUnique({ where: { id: apiAuth.userId }, select: { plan: true } });
    return { userId: apiAuth.userId, plan: user?.plan ?? 'free' };
  }
  const session = await auth();
  if (!session?.user?.id) return null;
  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  return { userId: session.user.id, plan };
}

// GET /api/v1/scans — list scans
export async function GET(req: NextRequest) {
  const resolved = await resolveUser(req, 'scan:read');
  if (!resolved) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const { userId, plan } = resolved;
  if (!PAID_PLANS.includes(plan)) {
    return NextResponse.json({ error: 'API access requires a Pro or Team plan. Upgrade at ${DISPLAY_HOST}/pricing' }, { status: 403 });
  }

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
  const resolved = await resolveUser(req, 'scan:write');
  if (!resolved) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const { userId, plan } = resolved;
  if (!PAID_PLANS.includes(plan)) {
    return NextResponse.json(
      { error: 'API access requires a Pro or Team plan. Upgrade at ${DISPLAY_HOST}/pricing' },
      { status: 403 },
    );
  }

  const body = await req.json();
  const { repo, branch = 'main', options = {} } = body;

  if (!repo) return NextResponse.json({ error: 'repo is required' }, { status: 400 });
  if (!REPO_RE.test(repo)) return NextResponse.json({ error: 'Invalid repo format (expected owner/name)' }, { status: 400 });
  if (!BRANCH_RE.test(branch)) return NextResponse.json({ error: 'Invalid branch name' }, { status: 400 });
  if (!checkScanRateLimit(userId)) return NextResponse.json({ error: 'Rate limit exceeded: 10 scans per hour' }, { status: 429 });

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
    await execFileAsync('git', ['clone', '--depth', '1', '--branch', branch, `https://github.com/${repo}.git`, `${tmpDir}/repo`], { timeout: 60_000 });
    const flags: string[] = ['--json'];
    if (options.deep) flags.push('--deep');
    if (options.deps) flags.push('--deps');
    const { stdout } = await execFileAsync('npx', ['ship-safe', 'audit', `${tmpDir}/repo`, ...flags], { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });
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
