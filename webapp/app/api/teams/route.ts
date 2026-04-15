import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

/** GET /api/teams — list teams for current user */
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const teams = await prisma.agentTeam.findMany({
    where: { userId: session.user.id },
    orderBy: { createdAt: 'desc' },
    include: {
      members: {
        orderBy: { order: 'asc' },
        include: {
          agent: {
            select: {
              id: true, name: true, status: true,
              deployments: {
                where: { status: 'running' },
                take:  1,
                select: { id: true, status: true },
              },
            },
          },
        },
      },
      _count: { select: { runs: true } },
    },
  });

  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  return NextResponse.json({ teams, plan });
}

/** POST /api/teams — create a new team */
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  if (!plan || plan === 'free') {
    return NextResponse.json(
      { error: '__TEAMS_LOCKED__', message: 'Agent Teams require a Pro or Team plan.' },
      { status: 403 },
    );
  }

  const { name, description } = await req.json();
  if (!name?.trim()) return NextResponse.json({ error: 'name is required' }, { status: 400 });

  const team = await prisma.agentTeam.create({
    data: {
      userId:      session.user.id,
      name:        name.trim().slice(0, 80),
      description: typeof description === 'string' ? description.trim().slice(0, 300) : null,
    },
  });

  return NextResponse.json({ team }, { status: 201 });
}
