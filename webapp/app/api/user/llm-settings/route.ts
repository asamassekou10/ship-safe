import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { maskLLMSettings, secureLLMSettings } from '@/lib/llm-credentials';

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { llmSettings: true },
  });

  return NextResponse.json({ llmSettings: maskLLMSettings(user?.llmSettings) });
}

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json();
  const { provider, model, think, swarm, apiKeys } = body;

  // Only allow known provider names
  const ALLOWED_PROVIDERS = ['anthropic', 'openai', 'deepseek', 'deepseek-flash', 'kimi', 'xai', 'google', 'auto'];
  if (provider && !ALLOWED_PROVIDERS.includes(provider)) {
    return NextResponse.json({ error: 'Invalid provider' }, { status: 400 });
  }

  const existing = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { llmSettings: true },
  });
  const llmSettings = secureLLMSettings({ provider, model, think: !!think, swarm: !!swarm, apiKeys }, existing?.llmSettings);

  await prisma.user.update({
    where: { id: session.user.id },
    data: { llmSettings },
  });

  return NextResponse.json({ ok: true, llmSettings: maskLLMSettings(llmSettings) });
}
