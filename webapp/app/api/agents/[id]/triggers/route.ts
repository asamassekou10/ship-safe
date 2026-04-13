import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { randomBytes } from 'crypto';

type Params = { params: Promise<{ id: string }> };

/** GET /api/agents/[id]/triggers — list triggers for this agent */
export async function GET(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const agent = await prisma.agent.findFirst({ where: { id, userId: session.user.id }, select: { id: true } });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const triggers = await prisma.trigger.findMany({
    where: { agentId: id },
    orderBy: { createdAt: 'asc' },
  });
  return NextResponse.json({ triggers });
}

/** POST /api/agents/[id]/triggers — create a new trigger */
export async function POST(req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const agent = await prisma.agent.findFirst({ where: { id, userId: session.user.id }, select: { id: true } });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const body = await req.json();
  const type: string = body.type === 'cron' ? 'cron' : 'webhook';
  const label: string = (body.label ?? '').trim();
  const cronExpr: string | null = type === 'cron' ? (body.cronExpr ?? '').trim() || null : null;
  const promptTpl: string = (body.promptTpl ?? '').trim() ||
    'You have been triggered. Here is the event context:\n\n{payload}';

  if (type === 'cron' && !cronExpr) {
    return NextResponse.json({ error: 'cronExpr is required for cron triggers' }, { status: 400 });
  }

  const secret = randomBytes(24).toString('hex');

  const trigger = await prisma.trigger.create({
    data: { agentId: id, type, label, secret, cronExpr, promptTpl },
  });

  return NextResponse.json({ trigger }, { status: 201 });
}
