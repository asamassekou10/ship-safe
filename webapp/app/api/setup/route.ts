import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { encodeConfig, type HermesConfig } from '@/lib/hermes-config-generator';

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let config: HermesConfig;
  try {
    config = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  if (!config.tools || !Array.isArray(config.tools) || config.tools.length === 0) {
    return NextResponse.json({ error: 'At least one tool is required' }, { status: 400 });
  }
  if (config.tools.length > 50) {
    return NextResponse.json({ error: 'Too many tools (max 50)' }, { status: 400 });
  }

  // Sanitize
  config.tools = config.tools.map(t => ({
    name: t.name.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64),
    sourceUrl: t.sourceUrl?.startsWith('https://') ? t.sourceUrl.slice(0, 512) : undefined,
  }));

  const token = encodeConfig(config);
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL ?? 'https://shipsafecli.com';
  const url = `${baseUrl}/s/${token}`;
  const command = `npx ship-safe init --hermes --from ${url}`;

  return NextResponse.json({ token, url, command });
}
