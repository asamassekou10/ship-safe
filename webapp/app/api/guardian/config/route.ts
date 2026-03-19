import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

/**
 * GET /api/guardian/config — Get Guardian configs for the current user.
 */
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const configs = await prisma.guardianConfig.findMany({
    where: { userId: session.user.id },
    orderBy: { repo: 'asc' },
  });

  return NextResponse.json({ configs });
}

/**
 * POST /api/guardian/config — Create or update a Guardian config.
 * Body: { repo, enabled?, autoFixFalsePositives?, autoFixRealIssues?,
 *         autoMerge?, mergeStrategy?, requireApproval?, minScoreToMerge?,
 *         maxAttempts?, fixCategories? }
 */
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string;
  if (plan === 'free') {
    return NextResponse.json({ error: 'PR Guardian requires Pro or Team plan' }, { status: 403 });
  }

  const body = await req.json();
  const { repo } = body;
  if (!repo) return NextResponse.json({ error: 'repo required' }, { status: 400 });

  const data: Record<string, unknown> = {};
  if (body.enabled !== undefined) data.enabled = Boolean(body.enabled);
  if (body.autoFixFalsePositives !== undefined) data.autoFixFalsePositives = Boolean(body.autoFixFalsePositives);
  if (body.autoFixRealIssues !== undefined) data.autoFixRealIssues = Boolean(body.autoFixRealIssues);
  if (body.autoMerge !== undefined) data.autoMerge = Boolean(body.autoMerge);
  if (body.mergeStrategy !== undefined && ['squash', 'merge', 'rebase'].includes(body.mergeStrategy)) {
    data.mergeStrategy = body.mergeStrategy;
  }
  if (body.requireApproval !== undefined) data.requireApproval = Boolean(body.requireApproval);
  if (body.minScoreToMerge !== undefined) data.minScoreToMerge = Math.max(0, Math.min(100, Number(body.minScoreToMerge)));
  if (body.maxAttempts !== undefined) data.maxAttempts = Math.max(1, Math.min(10, Number(body.maxAttempts)));
  if (body.fixCategories !== undefined && Array.isArray(body.fixCategories)) {
    data.fixCategories = body.fixCategories;
  }

  const config = await prisma.guardianConfig.upsert({
    where: { userId_repo: { userId: session.user.id, repo } },
    create: { userId: session.user.id, repo, ...data },
    update: data,
  });

  return NextResponse.json({ config });
}
