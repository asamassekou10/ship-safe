import { NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

const VALID_GOALS = new Set(['scan', 'agent', 'guardian']);

export async function POST(request: Request) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const body = await request.json().catch(() => ({}));
  const goal = typeof body.goal === 'string' && VALID_GOALS.has(body.goal)
    ? body.goal
    : null;

  await prisma.user.update({
    where: { id: session.user.id },
    data: {
      onboardingCompleted: true,
      ...(goal ? { onboardingGoal: goal } : {}),
    },
  });

  return NextResponse.json({ ok: true });
}
