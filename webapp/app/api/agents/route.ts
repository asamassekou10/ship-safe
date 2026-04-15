import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

function toSlug(name: string, suffix?: string) {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
  return suffix ? `${base}-${suffix}` : base;
}

/** GET /api/agents — list agents for current user + shared via orgs */
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const orgIds = await prisma.orgMember
    .findMany({ where: { userId: session.user.id }, select: { orgId: true } })
    .then(ms => ms.map(m => m.orgId));

  const agents = await prisma.agent.findMany({
    where: {
      OR: [
        { userId: session.user.id },
        ...(orgIds.length > 0 ? [{ orgId: { in: orgIds } }] : []),
      ],
    },
    orderBy: { createdAt: 'desc' },
    include: {
      deployments: {
        orderBy: { createdAt: 'desc' },
        take: 1,
        select: { id: true, status: true, securityScore: true, createdAt: true, subdomain: true },
      },
    },
  });

  return NextResponse.json({ agents });
}

/** POST /api/agents — create a new agent */
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  if (!plan || plan === 'free') {
    const agentCount = await prisma.agent.count({ where: { userId: session.user.id } });
    if (agentCount >= 1) {
      return NextResponse.json(
        { error: '__AGENT_LIMIT__', message: 'Free plan is limited to 1 agent. Upgrade to Pro for unlimited agents.' },
        { status: 403 },
      );
    }
  }

  const body = await req.json();
  const { name, description, tools, memoryProvider, maxDepth, skills, envVars, ciProvider } = body;

  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 });
  }

  // Generate a unique slug
  let slug = toSlug(name.trim());
  const existing = await prisma.agent.findUnique({ where: { slug } });
  if (existing) {
    slug = toSlug(name.trim(), Date.now().toString(36));
  }

  const agent = await prisma.agent.create({
    data: {
      userId: session.user.id,
      name: name.trim().slice(0, 80),
      slug,
      description: typeof description === 'string' ? description.trim().slice(0, 300) : null,
      tools: Array.isArray(tools) ? tools : [],
      memoryProvider: ['builtin', 'honcho', 'hindsight', 'mem0', 'none'].includes(memoryProvider)
        ? memoryProvider
        : 'builtin',
      maxDepth: typeof maxDepth === 'number' ? Math.min(Math.max(maxDepth, 1), 2) : 2,
      skills: Array.isArray(skills) ? skills : [],
      envVars: typeof envVars === 'object' && !Array.isArray(envVars) ? envVars : {},
      ciProvider: ['github', 'gitlab', 'none'].includes(ciProvider) ? ciProvider : 'none',
      status: 'draft',
    },
  });

  return NextResponse.json({ agent }, { status: 201 });
}
