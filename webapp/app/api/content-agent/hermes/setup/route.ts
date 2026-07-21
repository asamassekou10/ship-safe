import { NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { decryptAgentEnvVars, encryptAgentEnvVars, maskAgentSecrets } from '@/lib/agent-secrets';
import { readLLMSettings } from '@/lib/llm-credentials';

const AGENT_NAME = 'Ship Safe Content Research Agent';
const AGENT_SLUG_PREFIX = 'ship-safe-content-research';
const TOOL_NAMES = ['web_search', 'browser', 'read_file'];
const LLM_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY', 'MOONSHOT_API_KEY', 'KIMI_API_KEY', 'XAI_API_KEY'];

function toSlug(name: string, suffix?: string) {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
  return suffix ? `${base}-${suffix}` : base;
}

function apiKeysFromSettings(settings: unknown) {
  const apiKeys = readLLMSettings(settings).apiKeys;

  const envVars: Record<string, string> = {};
  for (const key of LLM_KEYS) {
    const value = apiKeys[key];
    if (typeof value === 'string' && value.trim()) envVars[key] = value.trim();
  }

  return envVars;
}

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const agent = await prisma.agent.findFirst({
    where: {
      userId: session.user.id,
      slug: { startsWith: AGENT_SLUG_PREFIX },
    },
    orderBy: { createdAt: 'desc' },
    include: {
      deployments: {
        orderBy: { createdAt: 'desc' },
        take: 1,
        select: { id: true, status: true, port: true, subdomain: true, createdAt: true },
      },
    },
  });

  return NextResponse.json({ agent: agent ? maskAgentSecrets(agent) : null });
}

export async function POST() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { llmSettings: true },
  });

  const envVars = apiKeysFromSettings(user?.llmSettings);

  const existing = await prisma.agent.findFirst({
    where: {
      userId: session.user.id,
      slug: { startsWith: AGENT_SLUG_PREFIX },
    },
    orderBy: { createdAt: 'desc' },
    include: {
      deployments: {
        orderBy: { createdAt: 'desc' },
        take: 1,
        select: { id: true, status: true, port: true, subdomain: true, createdAt: true },
      },
    },
  });

  if (existing) {
    const agent = await prisma.agent.update({
      where: { id: existing.id },
      data: {
        tools: TOOL_NAMES.map((name) => ({ name })),
        memoryProvider: 'builtin',
        maxDepth: 2,
        skills: ['content-research', 'fact-checking', 'seo-briefing'],
        envVars: encryptAgentEnvVars({ ...decryptAgentEnvVars(existing.envVars), ...envVars }),
      },
      include: {
        deployments: {
          orderBy: { createdAt: 'desc' },
          take: 1,
          select: { id: true, status: true, port: true, subdomain: true, createdAt: true },
        },
      },
    });
    return NextResponse.json({ agent: maskAgentSecrets(agent), created: false });
  }

  let slug = AGENT_SLUG_PREFIX;
  const slugOwner = await prisma.agent.findUnique({ where: { slug } });
  if (slugOwner) slug = toSlug(AGENT_NAME, Date.now().toString(36));

  const agent = await prisma.agent.create({
    data: {
      userId: session.user.id,
      name: AGENT_NAME,
      slug,
      description: 'Researches recent security news and drafts cited Ship Safe blog posts for review.',
      tools: TOOL_NAMES.map((name) => ({ name })),
      memoryProvider: 'builtin',
      maxDepth: 2,
      skills: ['content-research', 'fact-checking', 'seo-briefing'],
      envVars: encryptAgentEnvVars(envVars),
      ciProvider: 'none',
      status: 'draft',
    },
    include: {
      deployments: {
        orderBy: { createdAt: 'desc' },
        take: 1,
        select: { id: true, status: true, port: true, subdomain: true, createdAt: true },
      },
    },
  });

  return NextResponse.json({ agent: maskAgentSecrets(agent), created: true }, { status: 201 });
}
