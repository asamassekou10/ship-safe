import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { llmSettings: true },
  });

  return NextResponse.json({ llmSettings: user?.llmSettings ?? null });
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

  // Only store known API key names
  const ALLOWED_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'DEEPSEEK_API_KEY', 'MOONSHOT_API_KEY', 'XAI_API_KEY', 'GOOGLE_API_KEY'];
  const safeKeys: Record<string, string> = {};
  if (apiKeys && typeof apiKeys === 'object') {
    for (const [k, v] of Object.entries(apiKeys)) {
      if (ALLOWED_KEYS.includes(k) && typeof v === 'string') safeKeys[k] = v;
    }
  }

  const llmSettings = { provider, model, think: !!think, swarm: !!swarm, apiKeys: safeKeys };

  await prisma.user.update({
    where: { id: session.user.id },
    data: { llmSettings },
  });

  return NextResponse.json({ ok: true });
}
