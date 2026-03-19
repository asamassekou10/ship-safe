import { prisma } from '@/lib/prisma';
import { getGitHubClient } from '@/lib/github';
import { appendTimeline, advanceRun } from './pipeline';

type Run = NonNullable<Awaited<ReturnType<typeof prisma.pRGuardianRun.findUnique>>>;

/**
 * Step 4: Check if CI passed after our fix commit.
 * Called by the check_suite webhook when CI completes.
 * Transitions: verifying → merging | analyzing (retry) | failed
 */
export async function checkVerification(run: Run) {
  const gh = await getGitHubClient(run.repo, run.userId);
  const [owner, repo] = run.repo.split('/');
  const sha = run.fixCommitSha || run.prBranch;

  // Get combined status for the commit
  const statusRes = await gh.fetch(`/repos/${owner}/${repo}/commits/${sha}/status`);
  if (!statusRes.ok) throw new Error(`Failed to get commit status: ${statusRes.status}`);
  const statusData = await statusRes.json();

  // Also check check suites (GitHub Actions uses check runs, not statuses)
  const checksRes = await gh.fetch(`/repos/${owner}/${repo}/commits/${sha}/check-suites`);
  const checksData = checksRes.ok ? await checksRes.json() : { check_suites: [] };
  const suites = (checksData.check_suites || []) as Array<Record<string, unknown>>;

  const allComplete = suites.every((s: Record<string, unknown>) => s.status === 'completed');
  const anyFailed = suites.some((s: Record<string, unknown>) => s.conclusion === 'failure');
  const allPassed = suites.length > 0 && allComplete && !anyFailed;
  const combinedState = statusData.state as string;

  // Load config for max attempts
  const config = await prisma.guardianConfig.findFirst({
    where: { userId: run.userId, repo: { in: [run.repo, '*'] } },
    orderBy: { repo: 'desc' },
  });
  const maxAttempts = config?.maxAttempts ?? 3;

  if (allPassed && combinedState !== 'failure') {
    await appendTimeline(run.id, 'CI passed', 'All checks green');
    await prisma.pRGuardianRun.update({
      where: { id: run.id },
      data: { status: 'merging', ciStatus: 'success' },
    });
    advanceRun(run.id).catch(console.error);
  } else if (!allComplete) {
    // CI still running — stay in verifying, webhook will call us again
    await appendTimeline(run.id, 'CI still running', 'Waiting...');
  } else if (anyFailed && run.attempts < maxAttempts) {
    // CI failed again — retry the pipeline
    await appendTimeline(run.id, 'CI failed again', `Attempt ${run.attempts}/${maxAttempts} — retrying analysis`);
    await prisma.pRGuardianRun.update({
      where: { id: run.id },
      data: { status: 'analyzing', ciStatus: 'failure' },
    });
    advanceRun(run.id).catch(console.error);
  } else {
    // Max attempts or unknown state
    await appendTimeline(run.id, 'CI verification failed', `Exhausted ${maxAttempts} attempts`);
    await prisma.pRGuardianRun.update({
      where: { id: run.id },
      data: { status: 'failed', ciStatus: anyFailed ? 'failure' : combinedState },
    });
  }
}
