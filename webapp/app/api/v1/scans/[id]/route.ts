import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { authenticateApiKey } from '@/lib/api-auth';

async function resolveUser(req: NextRequest) {
  const apiAuth = await authenticateApiKey(req);
  if (apiAuth) return apiAuth.userId;
  const session = await auth();
  return session?.user?.id ?? null;
}

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const userId = await resolveUser(req);
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const scan = await prisma.scan.findFirst({
    where: { id, userId },
  });

  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  return NextResponse.json(scan);
}
