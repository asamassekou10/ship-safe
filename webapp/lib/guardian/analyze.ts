import { prisma } from '@/lib/prisma';
import { getGitHubClient } from '@/lib/github';
import { appendTimeline, advanceRun } from './pipeline';

type Run = NonNullable<Awaited<ReturnType<typeof prisma.pRGuardianRun.findUnique>>>;

/**
 * Step 1: Fetch CI failure logs from GitHub Actions.
 * Transitions: analyzing → diagnosing
 */
export async function analyzeCIFailure(run: Run) {
  const gh = await getGitHubClient(run.repo, run.userId);
  const [owner, repo] = run.repo.split('/');

  await appendTimeline(run.id, 'Analyzing CI', 'Fetching Actions run logs...');

  // Find the latest failed workflow run on the PR branch
  const runsRes = await gh.fetch(
    `/repos/${owner}/${repo}/actions/runs?branch=${encodeURIComponent(run.prBranch)}&event=pull_request&status=failure&per_page=5`
  );

  if (!runsRes.ok) {
    // If we can't fetch runs, check if the scan itself has findings (skip CI analysis)
    if (run.scanId) {
      await appendTimeline(run.id, 'CI logs unavailable', 'Proceeding with scan-based diagnosis');
      await prisma.pRGuardianRun.update({
        where: { id: run.id },
        data: { status: 'diagnosing', failureType: 'shipsafe' },
      });
      advanceRun(run.id).catch(console.error);
      return;
    }
    throw new Error(`Failed to fetch workflow runs: ${runsRes.status}`);
  }

  const runsData = await runsRes.json();
  const workflowRuns = runsData.workflow_runs as Array<Record<string, unknown>>;

  if (workflowRuns.length === 0) {
    // No failed CI runs — might just be scan findings without CI failure
    if (run.scanId) {
      await appendTimeline(run.id, 'No CI failures found', 'Proceeding with scan-based diagnosis');
      await prisma.pRGuardianRun.update({
        where: { id: run.id },
        data: { status: 'diagnosing', failureType: 'shipsafe' },
      });
      advanceRun(run.id).catch(console.error);
      return;
    }
    await appendTimeline(run.id, 'No CI failures found', 'Nothing to fix');
    await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'merged' } });
    return;
  }

  const failedRun = workflowRuns[0];
  const runId = failedRun.id as number;

  // Fetch failed jobs
  const jobsRes = await gh.fetch(`/repos/${owner}/${repo}/actions/runs/${runId}/jobs`);
  if (!jobsRes.ok) throw new Error(`Failed to fetch jobs: ${jobsRes.status}`);

  const jobsData = await jobsRes.json();
  const failedJobs = (jobsData.jobs as Array<Record<string, unknown>>).filter(
    j => j.conclusion === 'failure'
  );

  // Fetch logs from failed jobs
  let allLogs = '';
  for (const job of failedJobs.slice(0, 3)) {
    const logRes = await gh.fetch(`/repos/${owner}/${repo}/actions/jobs/${job.id}/logs`);
    if (logRes.ok) {
      const text = await logRes.text();
      // Trim to last 500 lines per job to stay within DB limits
      const lines = text.split('\n');
      allLogs += `\n=== Job: ${job.name} ===\n${lines.slice(-500).join('\n')}\n`;
    }
  }

  // Classify the failure type from logs
  const failureType = classifyFailure(allLogs);

  await appendTimeline(run.id, 'CI failure detected', `Type: ${failureType} (run #${runId}, ${failedJobs.length} failed job(s))`);

  await prisma.pRGuardianRun.update({
    where: { id: run.id },
    data: {
      status: 'diagnosing',
      ciRunId: runId,
      ciStatus: 'failure',
      failureType,
      failureLogs: allLogs.slice(0, 50_000), // cap at 50KB
    },
  });

  advanceRun(run.id).catch(console.error);
}

/**
 * Classify failure type from CI log content.
 */
function classifyFailure(logs: string): string {
  const lower = logs.toLowerCase();

  // Ship-safe findings
  if (lower.includes('ship safe') || lower.includes('ship-safe') || lower.includes('found') && (lower.includes('secret') || lower.includes('vulnerability'))) {
    return 'shipsafe';
  }
  // Test failures
  if (lower.includes('test failed') || lower.includes('tests failed') || lower.includes('jest') && lower.includes('fail') || lower.includes('assert')) {
    return 'test';
  }
  // Build errors
  if (lower.includes('build failed') || lower.includes('compilation error') || lower.includes('type error') || lower.includes('typescript') && lower.includes('error ts')) {
    return 'build';
  }
  // Lint errors
  if (lower.includes('eslint') || lower.includes('prettier') || lower.includes('lint error')) {
    return 'lint';
  }

  return 'unknown';
}
