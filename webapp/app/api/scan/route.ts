import { NextRequest, NextResponse } from 'next/server';
import { Prisma } from '@prisma/client';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { notifyScanComplete, notifyScanFailed } from '@/lib/notifications';
import { logAudit } from '@/lib/audit';
import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

const execAsync = promisify(exec);
const FREE_MONTHLY_LIMIT = 5;

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const userId = session.user.id;
  const plan = (session.user as Record<string, unknown>).plan as string;

  if (plan === 'free') {
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    const count = await prisma.scan.count({
      where: { userId, createdAt: { gte: monthStart } },
    });
    if (count >= FREE_MONTHLY_LIMIT) {
      return NextResponse.json(
        { error: 'Free plan limit reached (5 scans/month). Upgrade to Pro for unlimited scans.' },
        { status: 429 },
      );
    }
  }

  const body = await req.json();
  const { repo, branch = 'main', method = 'github', options = {} } = body;

  if (!repo) {
    return NextResponse.json({ error: 'repo is required' }, { status: 400 });
  }

  const scan = await prisma.scan.create({
    data: { userId, repo, branch, method, trigger: 'manual', status: 'running', options },
  });

  await logAudit({ userId, action: 'scan.created', target: scan.id, meta: { repo, branch, method } });

  runScan(scan.id, userId, repo, branch, method, options).catch(console.error);

  return NextResponse.json({ id: scan.id, status: 'running' });
}

async function runScan(
  scanId: string,
  userId: string,
  repo: string,
  branch: string,
  method: string,
  options: Record<string, boolean>,
) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-'));
  const startTime = Date.now();

  try {
    if (method === 'github' || method === 'url') {
      const repoUrl = method === 'github'
        ? `https://github.com/${repo}.git`
        : repo;
      // Clone default branch first (avoids failure when repo uses master vs main)
      await execAsync(`git clone --depth 1 ${repoUrl} ${tmpDir}/repo`, { timeout: 60_000 });
      // Checkout requested branch only if it differs from whatever was cloned
      if (branch) {
        await execAsync(
          `git -C ${tmpDir}/repo fetch --depth 1 origin ${branch} 2>/dev/null && git -C ${tmpDir}/repo checkout ${branch} 2>/dev/null || true`,
          { timeout: 20_000 },
        );
      }
    }

    const scanDir = join(tmpDir, 'repo');
    const flags: string[] = ['--json'];
    if (options.deep) flags.push('--deep');
    if (options.deps) flags.push('--deps');
    if (options.noAi) flags.push('--no-ai');

    const { stdout } = await execAsync(
      `node_modules/.bin/ship-safe audit ${scanDir} ${flags.join(' ')}`,
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024, cwd: process.cwd() },
    );

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

    const updated = await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'done', score, grade, findings, secrets, vulns, cves, duration, report: report as Prisma.InputJsonValue },
    });

    // Update monitored repo stats
    await prisma.monitoredRepo.updateMany({
      where: { userId, repo },
      data: { lastScanAt: new Date(), lastScore: score, lastGrade: grade },
    });

    // Notify
    await notifyScanComplete({ ...updated, userId });
  } catch (err) {
    const duration = (Date.now() - startTime) / 1000;
    const errorMsg = err instanceof Error ? err.message : String(err);
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'failed', duration, report: { error: errorMsg } },
    });
    await notifyScanFailed({ id: scanId, repo, branch, score: null, grade: null, findings: 0, secrets: 0, vulns: 0, cves: 0, status: 'failed', userId }, errorMsg);
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
