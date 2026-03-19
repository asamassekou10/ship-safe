import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

/**
 * GET /api/guardian/runs — List Guardian runs for the current user.
 * Query: ?repo=owner/repo&status=merged&limit=20&cursor=cuid
 */
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { searchParams } = req.nextUrl;
  const repo = searchParams.get('repo');
  const status = searchParams.get('status');
  const limit = Math.min(parseInt(searchParams.get('limit') || '20', 10), 50);
  const cursor = searchParams.get('cursor');

  const where: Record<string, unknown> = { userId: session.user.id };
  if (repo) where.repo = repo;
  if (status) where.status = status;

  const runs = await prisma.pRGuardianRun.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: limit + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
  });

  const hasMore = runs.length > limit;
  if (hasMore) runs.pop();

  return NextResponse.json({
    runs: runs.map(r => ({
      id: r.id,
      repo: r.repo,
      prNumber: r.prNumber,
      prTitle: r.prTitle,
      prBranch: r.prBranch,
      baseBranch: r.baseBranch,
      status: r.status,
      failureType: r.failureType,
      fixSummary: r.fixSummary,
      attempts: r.attempts,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    })),
    nextCursor: hasMore ? runs[runs.length - 1].id : null,
  });
}
