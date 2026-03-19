import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { getGitHubClient } from '@/lib/github';
import { startGuardianRun } from '@/lib/guardian/pipeline';
import { logAudit } from '@/lib/audit';

/**
 * POST /api/guardian/trigger — Manually trigger Guardian for a PR.
 * Body: { repo: "owner/repo", prNumber: 123 }
 */
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string;
  if (plan === 'free') {
    return NextResponse.json({ error: 'PR Guardian requires Pro or Team plan' }, { status: 403 });
  }

  const { repo, prNumber } = await req.json();
  if (!repo || !prNumber) {
    return NextResponse.json({ error: 'repo and prNumber required' }, { status: 400 });
  }

  // Fetch PR details from GitHub
  const gh = await getGitHubClient(repo, session.user.id);
  const [owner, name] = repo.split('/');
  const prRes = await gh.fetch(`/repos/${owner}/${name}/pulls/${prNumber}`);

  if (!prRes.ok) {
    return NextResponse.json({ error: 'PR not found on GitHub' }, { status: 404 });
  }

  const pr = await prRes.json();

  const runId = await startGuardianRun({
    userId: session.user.id,
    repo,
    prNumber,
    prTitle: pr.title,
    prBranch: pr.head.ref,
    baseBranch: pr.base.ref,
  });

  await logAudit({
    userId: session.user.id,
    action: 'guardian.triggered',
    target: runId,
    meta: { repo, prNumber },
  });

  return NextResponse.json({ ok: true, runId });
}
