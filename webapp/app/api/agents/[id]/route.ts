import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { encryptAgentEnvVars, maskAgentSecrets, mergeAgentEnvVarUpdate } from '@/lib/agent-secrets';

type Params = { params: Promise<{ id: string }> };

/** Returns the agent if the user owns it (for write ops). */
async function getAgentForUser(id: string, userId: string) {
  return prisma.agent.findFirst({ where: { id, userId } });
}

/** Returns the agent if the user owns it OR is a member of its org (for read ops). */
async function getAgentForUserOrOrg(id: string, userId: string) {
  const orgIds = await prisma.orgMember
    .findMany({ where: { userId }, select: { orgId: true } })
    .then(ms => ms.map(m => m.orgId));

  return prisma.agent.findFirst({
    where: {
      id,
      OR: [
        { userId },
        ...(orgIds.length > 0 ? [{ orgId: { in: orgIds } }] : []),
      ],
    },
  });
}

/** GET /api/agents/[id] */
export async function GET(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const orgIds = await prisma.orgMember
    .findMany({ where: { userId: session.user.id }, select: { orgId: true } })
    .then(ms => ms.map(m => m.orgId));

  const agent = await prisma.agent.findFirst({
    where: {
      id,
      OR: [
        { userId: session.user.id },
        ...(orgIds.length > 0 ? [{ orgId: { in: orgIds } }] : []),
      ],
    },
    include: {
      deployments: {
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true, version: true, status: true, securityScore: true,
          subdomain: true, deployLog: true, startedAt: true, stoppedAt: true, createdAt: true,
        },
      },
    },
  });

  if (!agent) return NextResponse.json({ error: 'Not found' }, { status: 404 });
  const isOwner = agent.userId === session.user.id;
  return NextResponse.json({ agent: maskAgentSecrets(agent), isOwner });
}

/** PATCH /api/agents/[id] */
export async function PATCH(req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const existing = await getAgentForUser(id, session.user.id);
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  const body = await req.json();
  const { name, description, tools, memoryProvider, maxDepth, skills, envVars, ciProvider } = body;

  const data: Record<string, unknown> = {};
  if (name && typeof name === 'string') data.name = name.trim().slice(0, 80);
  if (typeof description === 'string') data.description = description.trim().slice(0, 300);
  if (Array.isArray(tools)) data.tools = tools.slice(0, 50);
  if (['builtin', 'honcho', 'hindsight', 'mem0', 'none'].includes(memoryProvider)) data.memoryProvider = memoryProvider;
  if (typeof maxDepth === 'number') data.maxDepth = Math.min(Math.max(maxDepth, 1), 2);
  if (Array.isArray(skills)) data.skills = skills.slice(0, 50);
  if (typeof envVars === 'object' && !Array.isArray(envVars) && envVars !== null) {
    const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
    const safe: Record<string, string> = {};
    for (const [k, v] of Object.entries(envVars).slice(0, 50)) {
      if (!BLOCKED_KEYS.has(k) && typeof v === 'string') safe[k] = v.slice(0, 1024);
    }
    data.envVars = encryptAgentEnvVars(mergeAgentEnvVarUpdate(existing.envVars, safe));
  }
  if (['github', 'gitlab', 'none'].includes(ciProvider)) data.ciProvider = ciProvider;

  const agent = await prisma.agent.update({ where: { id }, data });
  return NextResponse.json({ agent: maskAgentSecrets(agent) });
}

/** DELETE /api/agents/[id] */
export async function DELETE(_req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const existing = await getAgentForUser(id, session.user.id);
  if (!existing) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  await prisma.agent.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}
