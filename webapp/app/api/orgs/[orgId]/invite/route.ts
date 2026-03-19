import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

// POST — invite a user by email
export async function POST(req: NextRequest, { params }: { params: Promise<{ orgId: string }> }) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { orgId } = await params;

  // Only owner/admin can invite
  const membership = await prisma.orgMember.findUnique({
    where: { orgId_userId: { orgId, userId: session.user.id } },
  });
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
  }

  const { email, role = 'member' } = await req.json();
  if (!email) return NextResponse.json({ error: 'email required' }, { status: 400 });
  if (!['admin', 'member', 'viewer'].includes(role)) {
    return NextResponse.json({ error: 'Invalid role' }, { status: 400 });
  }

  // Find user by email
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return NextResponse.json({ error: 'No user found with that email. They must sign up first.' }, { status: 404 });
  }

  // Check not already member
  const existing = await prisma.orgMember.findUnique({
    where: { orgId_userId: { orgId, userId: user.id } },
  });
  if (existing) {
    return NextResponse.json({ error: 'User is already a member' }, { status: 409 });
  }

  const member = await prisma.orgMember.create({
    data: { orgId, userId: user.id, role },
  });

  await logAudit({
    userId: session.user.id,
    orgId,
    action: 'member.invited',
    target: user.id,
    meta: { email, role },
  });

  return NextResponse.json({ id: member.id, role, userId: user.id }, { status: 201 });
}
