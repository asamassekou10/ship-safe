import { NextRequest, NextResponse } from 'next/server';
import { Prisma } from '@prisma/client';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { notifyScanComplete, notifyScanFailed } from '@/lib/notifications';
import { logAudit } from '@/lib/audit';
import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm, writeFile, mkdir } from 'fs/promises';
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
  const { repo, branch = '', method = 'github', options = {} } = body;

  if (!repo) {
    return NextResponse.json({ error: 'repo is required' }, { status: 400 });
  }

  // For URL method, extract GitHub owner/repo if it's a GitHub URL
  let resolvedRepo = repo;
  let resolvedMethod = method;
  if (method === 'url') {
    const ghMatch = (repo as string).match(/github\.com\/([^/]+\/[^/\s.]+)/);
    if (ghMatch) {
      resolvedRepo = ghMatch[1].replace(/\.git$/, '');
      resolvedMethod = 'github';
    } else {
      return NextResponse.json(
        { error: 'Only GitHub repositories are supported for cloud scans. Use the GitHub tab or upload a ZIP.' },
        { status: 400 },
      );
    }
  }

  const scan = await prisma.scan.create({
    data: { userId, repo: resolvedRepo, branch, method: resolvedMethod, trigger: 'manual', status: 'running', options },
  });

  await logAudit({ userId, action: 'scan.created', target: scan.id, meta: { repo: resolvedRepo, branch, method: resolvedMethod } });

  runScan(scan.id, userId, resolvedRepo, branch, options).catch(console.error);

  return NextResponse.json({ id: scan.id, status: 'running' });
}

/** Download a GitHub repo tarball and extract it — no git required */
async function fetchRepoTarball(owner: string, repo: string, ref: string, destDir: string) {
  // ref can be a branch, tag, or commit SHA; empty string → default branch
  const refSegment = ref || 'HEAD';
  const url = `https://api.github.com/repos/${owner}/${repo}/tarball/${refSegment}`;

  const headers: Record<string, string> = {
    'User-Agent': 'ship-safe-webapp',
    Accept: 'application/vnd.github.v3+json',
  };
  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const res = await fetch(url, { headers, redirect: 'follow' });

  if (res.status === 404) throw new Error('Repository not found or is private.');
  if (!res.ok) throw new Error(`GitHub API error ${res.status}: ${await res.text()}`);

  const tarPath = `${destDir}.tar.gz`;
  const buffer = Buffer.from(await res.arrayBuffer());
  await writeFile(tarPath, buffer);
  await mkdir(destDir, { recursive: true });

  // tar is available in Vercel's Lambda (Amazon Linux); git is not
  await execAsync(`tar -xzf "${tarPath}" -C "${destDir}" --strip-components=1`, { timeout: 30_000 });
}

async function runScan(
  scanId: string,
  userId: string,
  repo: string,         // owner/repo format
  branch: string,
  options: Record<string, boolean>,
) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-'));
  const startTime = Date.now();

  try {
    const [owner, repoName] = repo.split('/');
    await fetchRepoTarball(owner, repoName, branch, join(tmpDir, 'repo'));

    const scanDir = join(tmpDir, 'repo');
    const flags: string[] = ['--json'];
    if (options.deep) flags.push('--deep');
    if (options.deps) flags.push('--deps');
    if (options.noAi) flags.push('--no-ai');

    const { stdout } = await execAsync(
      `node_modules/.bin/ship-safe audit "${scanDir}" ${flags.join(' ')}`,
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

    await prisma.monitoredRepo.updateMany({
      where: { userId, repo },
      data: { lastScanAt: new Date(), lastScore: score, lastGrade: grade },
    });

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
