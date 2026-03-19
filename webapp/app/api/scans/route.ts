import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
  const cursor = url.searchParams.get('cursor') || undefined;

  const scans = await prisma.scan.findMany({
    where: { userId: session.user.id },
    orderBy: { createdAt: 'desc' },
    take: limit + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    select: {
      id: true,
      repo: true,
      branch: true,
      status: true,
      score: true,
      grade: true,
      findings: true,
      duration: true,
      createdAt: true,
    },
  });

  const hasMore = scans.length > limit;
  if (hasMore) scans.pop();

  return NextResponse.json({
    scans,
    nextCursor: hasMore ? scans[scans.length - 1]?.id : null,
  });
}
