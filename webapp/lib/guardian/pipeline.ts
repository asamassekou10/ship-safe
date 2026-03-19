import { prisma } from '@/lib/prisma';
import { analyzeCIFailure } from './analyze';
import { diagnoseFailure } from './diagnose';
import { applyFixes } from './fix';
import { checkVerification } from './verify';
import { attemptMerge } from './merge';

// ── Timeline Helper ─────────────────────────────────────────

export async function appendTimeline(runId: string, event: string, detail?: string) {
  const run = await prisma.pRGuardianRun.findUnique({ where: { id: runId }, select: { timeline: true } });
  const timeline = (run?.timeline as Array<{ timestamp: string; event: string; detail?: string }>) || [];
  timeline.push({ timestamp: new Date().toISOString(), event, detail: detail || '' });
  await prisma.pRGuardianRun.update({ where: { id: runId }, data: { timeline } });
}

// ── Start a Guardian Run ────────────────────────────────────

export interface StartGuardianParams {
  userId: string;
  orgId?: string;
  repo: string;
  prNumber: number;
  prTitle?: string;
  prBranch: string;
  baseBranch: string;
  scanId?: string;
}

export async function startGuardianRun(params: StartGuardianParams): Promise<string> {
  // Check if there's already an active run for this PR
  const existing = await prisma.pRGuardianRun.findFirst({
    where: {
      repo: params.repo,
      prNumber: params.prNumber,
      status: { in: ['watching', 'analyzing', 'diagnosing', 'fixing', 'verifying', 'merging'] },
    },
  });

  if (existing) {
    // Update the existing run with new scan info and restart
    await prisma.pRGuardianRun.update({
      where: { id: existing.id },
      data: { scanId: params.scanId, status: 'analyzing', attempts: existing.attempts },
    });
    await appendTimeline(existing.id, 'Pipeline restarted', `New scan triggered (${params.scanId})`);
    advanceRun(existing.id).catch(console.error);
    return existing.id;
  }

  const run = await prisma.pRGuardianRun.create({
    data: {
      userId: params.userId,
      orgId: params.orgId,
      repo: params.repo,
      prNumber: params.prNumber,
      prTitle: params.prTitle,
      prBranch: params.prBranch,
      baseBranch: params.baseBranch,
      scanId: params.scanId,
      status: 'analyzing',
      timeline: [{ timestamp: new Date().toISOString(), event: 'Guardian activated', detail: `PR #${params.prNumber} on ${params.repo}` }],
    },
  });

  advanceRun(run.id).catch(console.error);
  return run.id;
}

// ── State Machine ───────────────────────────────────────────

export async function advanceRun(runId: string) {
  const run = await prisma.pRGuardianRun.findUnique({ where: { id: runId } });
  if (!run) return;

  try {
    switch (run.status) {
      case 'analyzing':
        await analyzeCIFailure(run);
        break;
      case 'diagnosing':
        await diagnoseFailure(run);
        break;
      case 'fixing':
        await applyFixes(run);
        break;
      case 'verifying':
        await checkVerification(run);
        break;
      case 'merging':
        await attemptMerge(run);
        break;
      case 'merged':
      case 'failed':
      case 'blocked':
        // Terminal states — no-op
        break;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await appendTimeline(runId, 'Error', msg);
    await prisma.pRGuardianRun.update({ where: { id: runId }, data: { status: 'failed' } });
  }
}
