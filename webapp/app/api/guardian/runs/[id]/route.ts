import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

/**
 * GET /api/guardian/runs/[id] — Get a specific Guardian run with full detail.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const run = await prisma.pRGuardianRun.findFirst({
    where: { id, userId: session.user.id },
  });

  if (!run) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  return NextResponse.json({ run });
}
