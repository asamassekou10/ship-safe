import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';
import crypto from 'crypto';

const GITHUB_APP_WEBHOOK_SECRET = process.env.GITHUB_APP_WEBHOOK_SECRET || '';

function verifySignature(payload: string, signature: string | null): boolean {
  if (!signature || !GITHUB_APP_WEBHOOK_SECRET) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', GITHUB_APP_WEBHOOK_SECRET).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

export async function POST(req: NextRequest) {
  const body = await req.text();
  const signature = req.headers.get('x-hub-signature-256');
  const event = req.headers.get('x-github-event');

  if (GITHUB_APP_WEBHOOK_SECRET && !verifySignature(body, signature)) {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
  }

  const payload = JSON.parse(body);

  switch (event) {
    case 'installation':
      await handleInstallation(payload);
      break;
    case 'installation_repositories':
      await handleRepoChange(payload);
      break;
    case 'pull_request':
      if (['opened', 'synchronize'].includes(payload.action)) {
        await handlePullRequest(payload);
      }
      break;
    case 'push':
      await handlePush(payload);
      break;
    case 'check_suite':
      if (payload.action === 'completed') {
        await handleCheckSuite(payload);
      }
      break;
  }

  return NextResponse.json({ ok: true });
}

async function handleInstallation(payload: Record<string, unknown>) {
  const installation = payload.installation as Record<string, unknown>;
  const account = installation.account as Record<string, unknown>;
  const action = payload.action as string;

  if (action === 'created') {
    await prisma.gitHubInstallation.upsert({
      where: { installationId: installation.id as number },
      create: {
        installationId: installation.id as number,
        accountLogin: account.login as string,
        accountType: account.type as string,
        targetType: installation.target_type as string,
        repositorySelection: (installation.repository_selection as string) || 'all',
        permissions: installation.permissions as Record<string, unknown>,
        events: installation.events as string[],
      },
      update: {
        accountLogin: account.login as string,
        repositorySelection: (installation.repository_selection as string) || 'all',
        permissions: installation.permissions as Record<string, unknown>,
        events: installation.events as string[],
      },
    });

    await logAudit({
      action: 'github.app.installed',
      target: account.login as string,
      meta: { installationId: installation.id, accountType: account.type },
    });
  } else if (action === 'deleted') {
    await prisma.gitHubInstallation.deleteMany({
      where: { installationId: installation.id as number },
    });
  }
}

async function handleRepoChange(payload: Record<string, unknown>) {
  // Log which repos were added/removed
  const installation = payload.installation as Record<string, unknown>;
  await logAudit({
    action: 'github.repos.changed',
    meta: {
      installationId: installation.id,
      action: payload.action,
      added: payload.repositories_added,
      removed: payload.repositories_removed,
    },
  });
}

async function handlePullRequest(payload: Record<string, unknown>) {
  const pr = payload.pull_request as Record<string, unknown>;
  const repo = payload.repository as Record<string, unknown>;
  const fullName = repo.full_name as string;
  const branch = (pr.head as Record<string, unknown>).ref as string;
  const prNumber = pr.number as number;

  // Find a user who has this repo monitored or has scanned it before
  const recentScan = await prisma.scan.findFirst({
    where: { repo: fullName },
    orderBy: { createdAt: 'desc' },
    select: { userId: true },
  });

  if (!recentScan) return; // No user associated with this repo

  // Create a scan triggered by PR
  const scan = await prisma.scan.create({
    data: {
      userId: recentScan.userId,
      repo: fullName,
      branch,
      method: 'github-app',
      trigger: 'pr',
      status: 'pending',
      prNumber,
    },
  });

  await logAudit({
    userId: recentScan.userId,
    action: 'scan.triggered.pr',
    target: scan.id,
    meta: { repo: fullName, prNumber, branch },
  });

  // The scan will be picked up by a background worker
  // For now, trigger it inline (same as manual scan)
  triggerScan(scan.id, recentScan.userId, fullName, branch).catch(console.error);
}

async function handlePush(payload: Record<string, unknown>) {
  const repo = payload.repository as Record<string, unknown>;
  const fullName = repo.full_name as string;
  const ref = payload.ref as string;
  const branch = ref.replace('refs/heads/', '');

  // Check if this repo has monitoring enabled with webhook trigger
  const monitored = await prisma.monitoredRepo.findFirst({
    where: { repo: fullName, branch, enabled: true },
  });

  if (!monitored) return;

  const scan = await prisma.scan.create({
    data: {
      userId: monitored.userId,
      orgId: monitored.orgId,
      repo: fullName,
      branch,
      method: 'github-app',
      trigger: 'webhook',
      status: 'pending',
    },
  });

  triggerScan(scan.id, monitored.userId, fullName, branch).catch(console.error);
}

async function handleCheckSuite(payload: Record<string, unknown>) {
  const checkSuite = payload.check_suite as Record<string, unknown>;
  const conclusion = checkSuite.conclusion as string; // success | failure | etc.
  const headBranch = checkSuite.head_branch as string;
  const repoData = payload.repository as Record<string, unknown>;
  const fullName = repoData.full_name as string;

  // Find any Guardian run in "verifying" state for this repo + branch
  const run = await prisma.pRGuardianRun.findFirst({
    where: {
      repo: fullName,
      prBranch: headBranch,
      status: 'verifying',
    },
    orderBy: { updatedAt: 'desc' },
  });

  if (!run) return;

  // Resume the Guardian pipeline
  const { appendTimeline, advanceRun } = await import('@/lib/guardian/pipeline');
  await appendTimeline(run.id, 'Check suite completed', `Conclusion: ${conclusion}`);
  await prisma.pRGuardianRun.update({
    where: { id: run.id },
    data: { ciStatus: conclusion },
  });
  advanceRun(run.id).catch(console.error);
}

async function triggerScan(scanId: string, userId: string, repo: string, branch: string) {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const { mkdtemp, rm } = await import('fs/promises');
  const { tmpdir } = await import('os');
  const { join } = await import('path');
  const { notifyScanComplete, notifyScanFailed } = await import('@/lib/notifications');

  const execAsync = promisify(exec);
  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-gh-'));
  const startTime = Date.now();

  await prisma.scan.update({ where: { id: scanId }, data: { status: 'running' } });

  try {
    await execAsync(`git clone --depth 1 --branch ${branch} https://github.com/${repo}.git ${tmpDir}/repo`, { timeout: 60_000 });
    const { stdout } = await execAsync(`npx ship-safe audit ${tmpDir}/repo --json --deps`, { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 });

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
      data: { status: 'done', score, grade, findings, secrets, vulns, cves, duration, report },
    });

    await notifyScanComplete({ ...updated, userId });

    // If this was a PR scan with findings, trigger Guardian pipeline
    if (updated.prNumber && updated.findings > 0) {
      const { startGuardianRun } = await import('@/lib/guardian/pipeline');
      const guardianConfig = await prisma.guardianConfig.findFirst({
        where: { userId, repo: { in: [repo, '*'] }, enabled: true },
      });
      if (guardianConfig) {
        startGuardianRun({
          userId,
          repo,
          prNumber: updated.prNumber,
          prBranch: branch,
          baseBranch: 'main',
          scanId,
        }).catch(console.error);
      }
    }
  } catch (err) {
    const duration = (Date.now() - startTime) / 1000;
    const errorMsg = err instanceof Error ? err.message : String(err);
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'failed', duration, report: { error: errorMsg } } });
    await notifyScanFailed({ id: scanId, repo, branch, score: null, grade: null, findings: 0, secrets: 0, vulns: 0, cves: 0, status: 'failed', userId }, errorMsg);
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
