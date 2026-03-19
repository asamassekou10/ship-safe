import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

// GET — list policies for user's orgs
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const orgId = url.searchParams.get('orgId');
  if (!orgId) return NextResponse.json({ error: 'orgId required' }, { status: 400 });

  // Check membership
  const membership = await prisma.orgMember.findUnique({
    where: { orgId_userId: { orgId, userId: session.user.id } },
  });
  if (!membership) return NextResponse.json({ error: 'Not a member' }, { status: 403 });

  const policies = await prisma.policy.findMany({
    where: { orgId },
    orderBy: { createdAt: 'desc' },
  });

  return NextResponse.json({ policies });
}

// POST — create a policy
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { orgId, name, description, rules, enforcement = 'warn' } = await req.json();
  if (!orgId || !name || !rules) {
    return NextResponse.json({ error: 'orgId, name, and rules are required' }, { status: 400 });
  }

  // Only owner/admin can create policies
  const membership = await prisma.orgMember.findUnique({
    where: { orgId_userId: { orgId, userId: session.user.id } },
  });
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  const policy = await prisma.policy.create({
    data: { orgId, name, description, rules, enforcement },
  });

  await logAudit({ userId: session.user.id, orgId, action: 'policy.created', target: policy.id, meta: { name } });

  return NextResponse.json(policy, { status: 201 });
}

// PUT — update a policy
export async function PUT(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id, name, description, rules, enforcement, enabled } = await req.json();
  if (!id) return NextResponse.json({ error: 'id required' }, { status: 400 });

  const policy = await prisma.policy.findUnique({ where: { id }, include: { org: true } });
  if (!policy) return NextResponse.json({ error: 'Policy not found' }, { status: 404 });

  const membership = await prisma.orgMember.findUnique({
    where: { orgId_userId: { orgId: policy.orgId, userId: session.user.id } },
  });
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  const updated = await prisma.policy.update({
    where: { id },
    data: {
      ...(name !== undefined && { name }),
      ...(description !== undefined && { description }),
      ...(rules !== undefined && { rules }),
      ...(enforcement !== undefined && { enforcement }),
      ...(enabled !== undefined && { enabled }),
    },
  });

  await logAudit({ userId: session.user.id, orgId: policy.orgId, action: 'policy.updated', target: id });

  return NextResponse.json(updated);
}
