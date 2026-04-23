import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { fireAgentRun } from '@/lib/fire-agent-run';
import { Cron } from 'croner';
import { Prisma } from '@prisma/client';
import { notifyScanComplete, notifyScanFailed } from '@/lib/notifications';
import { mkdtemp, rm, writeFile, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import * as tar from 'tar';
import { auditCommand } from 'ship-safe';

/**
 * GET /api/cron
 *
 * Called every minute by Vercel Cron. Finds all enabled cron triggers
 * whose expression matches the current minute and fires them.
 *
 * Protected by CRON_SECRET (set in Vercel env vars).
 */
export async function GET(req: NextRequest) {
  // Vercel Cron sends its own Authorization header in production.
  // CRON_SECRET is REQUIRED — if unset, reject all requests to prevent
  // unauthenticated cron triggers (resource exhaustion vector).
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    console.error('[cron] CRON_SECRET env var is not set — refusing to run');
    return NextResponse.json({ error: 'Server misconfiguration' }, { status: 500 });
  }
  const auth = req.headers.get('authorization') ?? '';
  if (auth !== `Bearer ${secret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const now = new Date();

  // Fetch all enabled cron triggers with a running deployment
  const triggers = await prisma.trigger.findMany({
    where: { type: 'cron', enabled: true, cronExpr: { not: null } },
    include: {
      agent: {
        include: {
          deployments: {
            where:   { status: 'running' },
            orderBy: { createdAt: 'desc' },
            take: 1,
          },
        },
      },
    },
  });

  const fired: string[] = [];

  for (const trigger of triggers) {
    const deployment = trigger.agent.deployments[0];
    if (!deployment?.port || !trigger.cronExpr) continue;

    // Check if this trigger should fire right now.
    // croner's .nextRun(fromDate) gives the next scheduled time after `fromDate`.
    // We consider a trigger due if its last run was > 1 minute ago and the
    // next scheduled time falls within the current minute window.
    let isDue = false;
    try {
      const job = new Cron(trigger.cronExpr, { timezone: 'UTC' });
      // Next run from 1 minute ago
      const windowStart = new Date(now.getTime() - 60_000);
      const next = job.nextRun(windowStart);
      isDue = next !== null && next <= now;
    } catch {
      continue; // invalid cron expr — skip
    }

    if (!isDue) continue;

    // Build message
    const message = trigger.promptTpl.replace(
      '{payload}',
      `Scheduled run at ${now.toISOString()}`
    );

    const run = await prisma.agentRun.create({
      data: { deploymentId: deployment.id, triggerId: trigger.id, status: 'running' },
    });

    await prisma.chatMessage.create({
      data: { runId: run.id, role: 'user', content: message },
    });

    await prisma.trigger.update({
      where: { id: trigger.id },
      data:  { lastFiredAt: now },
    });

    // Fire in background
    fireAgentRun({
      runId:          run.id,
      deploymentPort: deployment.port,
      message,
    }).catch(() => {});

    fired.push(trigger.id);
  }

  // ── Scheduled repo scans ─────────────────────────────────────────────────────
  const repos = await prisma.monitoredRepo.findMany({
    where: { enabled: true, schedule: { not: null } },
  });

  const scannedRepos: string[] = [];

  for (const repo of repos) {
    if (!repo.schedule) continue;

    let isDue = false;
    try {
      const job = new Cron(repo.schedule, { timezone: 'UTC' });
      const windowStart = new Date(now.getTime() - 60_000);
      const next = job.nextRun(windowStart);
      isDue = next !== null && next <= now;
    } catch {
      continue;
    }

    if (!isDue) continue;

    const options = (repo.options as Record<string, boolean>) ?? {};
    const scan = await prisma.scan.create({
      data: {
        userId:  repo.userId,
        repo:    repo.repo,
        branch:  repo.branch,
        method:  'github',
        trigger: 'scheduled',
        status:  'running',
        options,
      },
    });

    runScheduledScan(scan.id, repo.userId, repo.repo, repo.branch, options).catch(() => {});
    scannedRepos.push(repo.repo);
  }

  // ── Stuck team-run cleanup ───────────────────────────────────────────────────
  // Any TeamRun still in 'running' after 12 minutes is stuck (Vercel killed it).
  // Mark it as error so the UI doesn't spin forever.
  const STUCK_AFTER_MS = 12 * 60 * 1000;
  const stuckCutoff = new Date(now.getTime() - STUCK_AFTER_MS);
  const stuckResult = await prisma.teamRun.updateMany({
    where: { status: 'running', startedAt: { lt: stuckCutoff } },
    data:  {
      status:      'error',
      phase:       'done',
      completedAt: now,
      report:      'Run timed out — the server did not complete within the allowed window. Try again with a smaller target or fewer agents.',
    },
  });

  // Same cleanup for individual AgentRuns stuck in 'running'
  await prisma.agentRun.updateMany({
    where: { status: 'running', startedAt: { lt: stuckCutoff } },
    data:  { status: 'error', completedAt: now },
  });

  return NextResponse.json({ fired, count: fired.length, scannedRepos, stuckTeamRunsCleaned: stuckResult.count, at: now.toISOString() });
}

// ── Scheduled repo scan runner ────────────────────────────────────────────────

async function fetchRepoTarball(owner: string, repo: string, ref: string, destDir: string) {
  const refSegment = ref || 'HEAD';
  const url = `https://api.github.com/repos/${owner}/${repo}/tarball/${refSegment}`;
  const headers: Record<string, string> = {
    'User-Agent': 'ship-safe-webapp',
    Accept: 'application/vnd.github.v3+json',
  };
  if (process.env.GITHUB_TOKEN) headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers, redirect: 'follow' }); // ship-safe-ignore — URL domain is hardcoded to api.github.com; only owner/repo/ref path segments are user-supplied
  if (res.status === 404) throw new Error('Repository not found or is private.');
  if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
  const tarPath = `${destDir}.tar.gz`;
  await writeFile(tarPath, Buffer.from(await res.arrayBuffer()));
  await mkdir(destDir, { recursive: true });
  await tar.extract({ file: tarPath, cwd: destDir, strip: 1 });
}

async function runScheduledScan(
  scanId: string,
  userId: string,
  repo: string,
  branch: string,
  options: Record<string, boolean>,
) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-sched-'));
  const startTime = Date.now();

  try {
    const [owner, repoName] = repo.split('/');
    await fetchRepoTarball(owner, repoName, branch, join(tmpDir, 'repo'));

    const lines: string[] = [];
    const origLog = console.log;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const origExit = (process as any).exit;
    console.log = (...args: unknown[]) => lines.push(args.join(' '));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process as any).exit = () => {};
    try {
      await auditCommand(join(tmpDir, 'repo'), { json: true, deep: options.deep ?? true, deps: options.deps !== false, noAi: options.noAi ?? false, cache: false });
    } finally {
      console.log = origLog;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process as any).exit = origExit;
    }

    const stdout = lines.join('\n');
    const duration = (Date.now() - startTime) / 1000;
    let report: Record<string, unknown> = {};
    try { report = JSON.parse(stdout); } catch { report = { raw: stdout }; }

    const score    = typeof report.score === 'number' ? report.score : null;
    const grade    = typeof report.grade === 'string' ? report.grade : null;
    const findings = typeof report.totalFindings === 'number' ? report.totalFindings : 0;
    const cats     = report.categories as Record<string, { findingCount?: number }> | undefined;
    const secrets  = cats?.secrets?.findingCount ?? 0;
    const vulns    = (cats?.injection?.findingCount ?? 0) + (cats?.auth?.findingCount ?? 0);
    const cves     = typeof report.totalDepVulns === 'number' ? report.totalDepVulns : 0;

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
