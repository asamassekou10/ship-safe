import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { authenticateApiKey } from '@/lib/api-auth';
import { DISPLAY_HOST } from '@/lib/site';

const PAID_PLANS = ['pro', 'team', 'enterprise'];

async function resolveUser(req: NextRequest): Promise<{ userId: string; plan: string } | null> {
  const apiAuth = await authenticateApiKey(req);
  if (apiAuth) {
    const user = await prisma.user.findUnique({ where: { id: apiAuth.userId }, select: { plan: true } });
    return { userId: apiAuth.userId, plan: user?.plan ?? 'free' };
  }
  const session = await auth();
  if (!session?.user?.id) return null;
  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  return { userId: session.user.id, plan };
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const resolved = await resolveUser(req);
  if (!resolved) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const { userId, plan } = resolved;
  if (!PAID_PLANS.includes(plan)) {
    return NextResponse.json({ error: 'API access requires a Pro or Team plan. Upgrade at ${DISPLAY_HOST}/pricing' }, { status: 403 });
  }

  const { id } = await params;
  const scan = await prisma.scan.findFirst({
    where: { id, userId },
  });

  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  return NextResponse.json(scan);
}
