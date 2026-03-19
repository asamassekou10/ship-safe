import { prisma } from '@/lib/prisma';
import { getGitHubClient } from '@/lib/github';
import { appendTimeline } from './pipeline';

type Run = NonNullable<Awaited<ReturnType<typeof prisma.pRGuardianRun.findUnique>>>;

/**
 * Step 5: Merge the PR if config allows.
 * Transitions: merging → merged | blocked
 */
export async function attemptMerge(run: Run) {
  const config = await prisma.guardianConfig.findFirst({
    where: { userId: run.userId, repo: { in: [run.repo, '*'] } },
    orderBy: { repo: 'desc' },
  });

  // Check auto-merge is enabled
  if (!config?.autoMerge) {
    await appendTimeline(run.id, 'Auto-merge disabled', 'PR is ready — merge manually');
    await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
    return;
  }

  const gh = await getGitHubClient(run.repo, run.userId);
  const [owner, repo] = run.repo.split('/');

  // Check minimum score requirement
  if (config.minScoreToMerge > 0 && run.scanId) {
    const scan = await prisma.scan.findUnique({ where: { id: run.scanId }, select: { score: true } });
    if (scan?.score !== null && scan?.score !== undefined && scan.score < config.minScoreToMerge) {
      await appendTimeline(run.id, 'Score too low', `Score ${scan.score} < minimum ${config.minScoreToMerge}`);
      await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
      return;
    }
  }

  // Check approval requirement
  if (config.requireApproval) {
    const reviewsRes = await gh.fetch(`/repos/${owner}/${repo}/pulls/${run.prNumber}/reviews`);
    if (reviewsRes.ok) {
      const reviews = (await reviewsRes.json()) as Array<{ state: string }>;
      const hasApproval = reviews.some(r => r.state === 'APPROVED');
      if (!hasApproval) {
        await appendTimeline(run.id, 'Approval required', 'Waiting for PR review approval');
        await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
        return;
      }
    }
  }

  // Merge the PR
  const strategy = config.mergeStrategy || run.mergeStrategy || 'squash';
  const mergeRes = await gh.fetch(`/repos/${owner}/${repo}/pulls/${run.prNumber}/merge`, {
    method: 'PUT',
    body: JSON.stringify({
      merge_method: strategy,
      commit_title: `${run.prTitle || `PR #${run.prNumber}`} (#${run.prNumber})`,
      commit_message: `Auto-merged by Ship Safe PR Guardian\n\nFixes applied: ${run.fixSummary || 'none'}`,
    }),
  });

  if (!mergeRes.ok) {
    const err = await mergeRes.json().catch(() => ({ message: `HTTP ${mergeRes.status}` }));
    await appendTimeline(run.id, 'Merge failed', (err as { message?: string }).message || 'Unknown error');
    await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
    return;
  }

  const mergeData = await mergeRes.json();

  await appendTimeline(run.id, 'PR merged', `${strategy} merge — ${mergeData.sha?.slice(0, 7) || 'done'}`);

  await prisma.pRGuardianRun.update({
    where: { id: run.id },
    data: {
      status: 'merged',
      mergeSha: mergeData.sha || null,
      mergeStrategy: strategy,
    },
  });

  // Notify and post summary comment
  const { notifyGuardianComplete } = await import('@/lib/notifications');
  await notifyGuardianComplete({ ...run, status: 'merged', mergeSha: mergeData.sha });
  await postSummaryComment(gh, owner, repo, run);
}

async function postSummaryComment(
  gh: Awaited<ReturnType<typeof getGitHubClient>>,
  owner: string,
  repo: string,
  run: Run,
) {
  const timeline = (run.timeline as Array<{ timestamp: string; event: string; detail?: string }>) || [];
  const timelineText = timeline
    .map(e => `- **${e.event}** ${e.detail ? `— ${e.detail}` : ''} _(${new Date(e.timestamp).toLocaleTimeString()})_`)
    .join('\n');

  const body = `## 🛡️ Ship Safe PR Guardian — Summary

**Status:** Merged ✅
**Fixes applied:** ${run.fixSummary || 'None'}
**Attempts:** ${run.attempts}

### Timeline
${timelineText}

---
<sub>Auto-managed by [Ship Safe PR Guardian](https://shipsafe.dev)</sub>`;

  await gh.fetch(`/repos/${owner}/${repo}/issues/${run.prNumber}/comments`, {
    method: 'POST',
    body: JSON.stringify({ body }),
  }).catch(() => {}); // best effort
}
