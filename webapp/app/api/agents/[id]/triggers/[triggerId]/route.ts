import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ id: string; triggerId: string }> };

/** PATCH /api/agents/[id]/triggers/[triggerId] — update label, cronExpr, promptTpl, enabled */
export async function PATCH(req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id, triggerId } = await params;
  const agent = await prisma.agent.findFirst({ where: { id, userId: session.user.id }, select: { id: true } });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const body = await req.json();
  const data: Record<string, unknown> = {};
  if (body.label    !== undefined) data.label     = String(body.label).trim();
  if (body.cronExpr !== undefined) data.cronExpr  = body.cronExpr ? String(body.cronExpr).trim() : null;
  if (body.promptTpl !== undefined) data.promptTpl = String(body.promptTpl);
  if (body.enabled  !== undefined) data.enabled   = Boolean(body.enabled);

  const trigger = await prisma.trigger.updateMany({
    where: { id: triggerId, agentId: id },
    data,
  });
  if (trigger.count === 0) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const updated = await prisma.trigger.findUnique({ where: { id: triggerId } });
  return NextResponse.json({ trigger: updated });
}

/** DELETE /api/agents/[id]/triggers/[triggerId] */
export async function DELETE(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id, triggerId } = await params;
  const agent = await prisma.agent.findFirst({ where: { id, userId: session.user.id }, select: { id: true } });
  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  await prisma.trigger.deleteMany({ where: { id: triggerId, agentId: id } });
  return NextResponse.json({ ok: true });
}
