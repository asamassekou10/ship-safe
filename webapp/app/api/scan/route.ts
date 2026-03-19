import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm, writeFile } from 'fs/promises';
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

  // Enforce free plan limits
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

  // Create scan record
  const scan = await prisma.scan.create({
    data: { userId, repo, branch, method, status: 'running', options },
  });

  // Run scan in background (don't await — return immediately)
  runScan(scan.id, repo, branch, method, options).catch(console.error);

  return NextResponse.json({ id: scan.id, status: 'running' });
}

async function runScan(
  scanId: string,
  repo: string,
  branch: string,
  method: string,
  options: Record<string, boolean>,
) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-'));
  const startTime = Date.now();

  try {
    // Clone or prepare the repo
    if (method === 'github' || method === 'url') {
      const repoUrl = method === 'github'
        ? `https://github.com/${repo}.git`
        : repo;
      await execAsync(`git clone --depth 1 --branch ${branch} ${repoUrl} ${tmpDir}/repo`, {
        timeout: 60_000,
      });
    }

    const scanDir = join(tmpDir, 'repo');

    // Build CLI command
    const flags: string[] = ['--json'];
    if (options.deep) flags.push('--deep');
    if (options.deps) flags.push('--deps');
    if (options.noAi) flags.push('--no-ai');

    const { stdout } = await execAsync(
      `npx ship-safe audit ${scanDir} ${flags.join(' ')}`,
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
    );

    const duration = (Date.now() - startTime) / 1000;
    let report: Record<string, unknown> = {};

    try {
      report = JSON.parse(stdout);
    } catch {
      report = { raw: stdout };
    }

    const score = typeof report.score === 'number' ? report.score : null;
    const grade = typeof report.grade === 'string' ? report.grade : null;
    const findings = typeof report.totalFindings === 'number' ? report.totalFindings : 0;
    const cats = report.categories as Record<string, { findingCount?: number }> | undefined;
    const secrets = cats?.secrets?.findingCount ?? 0;
    const vulns = (cats?.injection?.findingCount ?? 0) + (cats?.auth?.findingCount ?? 0);
    const cves = typeof report.totalDepVulns === 'number' ? report.totalDepVulns : 0;

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'done', score, grade, findings, secrets, vulns, cves, duration, report },
    });
  } catch (err) {
    const duration = (Date.now() - startTime) / 1000;
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'failed',
        duration,
        report: { error: err instanceof Error ? err.message : String(err) },
      },
    });
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
