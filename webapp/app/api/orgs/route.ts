import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

// GET — list user's orgs
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const memberships = await prisma.orgMember.findMany({
    where: { userId: session.user.id },
    include: {
      org: {
        include: {
          _count: { select: { members: true, scans: true } },
        },
      },
    },
  });

  const orgs = memberships.map(m => ({
    id: m.org.id,
    name: m.org.name,
    slug: m.org.slug,
    plan: m.org.plan,
    role: m.role,
    memberCount: m.org._count.members,
    scanCount: m.org._count.scans,
  }));

  return NextResponse.json({ orgs });
}

// POST — create an org
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string;
  if (plan !== 'team' && plan !== 'enterprise') {
    return NextResponse.json({ error: 'Team or Enterprise plan required to create an organization' }, { status: 403 });
  }

  const { name } = await req.json();
  if (!name || name.length < 2) {
    return NextResponse.json({ error: 'Organization name is required (min 2 chars)' }, { status: 400 });
  }

  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  const existing = await prisma.org.findUnique({ where: { slug } });
  if (existing) {
    return NextResponse.json({ error: 'Organization slug already taken' }, { status: 409 });
  }

  const org = await prisma.org.create({
    data: {
      name,
      slug,
      plan,
      members: {
        create: { userId: session.user.id, role: 'owner' },
      },
    },
  });

  await logAudit({ userId: session.user.id, orgId: org.id, action: 'org.created', target: org.id });

  return NextResponse.json({ id: org.id, name: org.name, slug: org.slug }, { status: 201 });
}
