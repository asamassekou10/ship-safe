import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

async function requireOrgRole(orgId: string, userId: string, minRole: string[]) {
  const membership = await prisma.orgMember.findUnique({
    where: { orgId_userId: { orgId, userId } },
  });
  if (!membership || !minRole.includes(membership.role)) return null;
  return membership;
}

// GET — list org members
export async function GET(_req: NextRequest, { params }: { params: Promise<{ orgId: string }> }) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { orgId } = await params;
  const membership = await requireOrgRole(orgId, session.user.id, ['owner', 'admin', 'member', 'viewer']);
  if (!membership) return NextResponse.json({ error: 'Not a member' }, { status: 403 });

  const members = await prisma.orgMember.findMany({
    where: { orgId },
    include: { user: { select: { id: true, name: true, email: true, image: true } } },
  });

  return NextResponse.json({
    members: members.map(m => ({
      id: m.id,
      role: m.role,
      user: m.user,
    })),
  });
}

// DELETE — remove a member
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ orgId: string }> }) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { orgId } = await params;
  const membership = await requireOrgRole(orgId, session.user.id, ['owner', 'admin']);
  if (!membership) return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });

  const { memberId } = await req.json();
  if (!memberId) return NextResponse.json({ error: 'memberId required' }, { status: 400 });

  // Can't remove the owner
  const target = await prisma.orgMember.findUnique({ where: { id: memberId } });
  if (target?.role === 'owner') {
    return NextResponse.json({ error: 'Cannot remove the organization owner' }, { status: 400 });
  }

  await prisma.orgMember.delete({ where: { id: memberId } });
  await logAudit({ userId: session.user.id, orgId, action: 'member.removed', target: memberId });

  return NextResponse.json({ ok: true });
}
