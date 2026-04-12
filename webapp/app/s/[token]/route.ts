import { NextRequest, NextResponse } from 'next/server';
import { decodeConfig, generateAllFiles } from '@/lib/hermes-config-generator';

/**
 * GET /s/[token]
 *
 * Public endpoint — no auth required.
 * The CLI calls this with the token from the setup URL:
 *   npx ship-safe init --hermes --from https://shipsafecli.com/s/<token>
 *
 * Returns: { files: Array<{ path: string; content: string }> }
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ token: string }> },
) {
  const { token } = await params;

  if (!token || typeof token !== 'string' || token.length > 4096) {
    return NextResponse.json({ error: 'Invalid token' }, { status: 400 });
  }

  const config = decodeConfig(token);
  if (!config) {
    return NextResponse.json({ error: 'Invalid or expired setup token' }, { status: 400 });
  }

  // Sanitize after decode (defensive — data came from user originally)
  config.tools = (config.tools ?? [])
    .slice(0, 50)
    .map(t => ({
      name: String(t.name ?? '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64),
      sourceUrl: String(t.sourceUrl ?? '').startsWith('https://')
        ? String(t.sourceUrl).slice(0, 512)
        : undefined,
    }))
    .filter(t => t.name);

  if (config.tools.length === 0) {
    return NextResponse.json({ error: 'No valid tools in config' }, { status: 400 });
  }

  const files = generateAllFiles(config);

  return NextResponse.json(
    { files, projectName: config.projectName || 'my-hermes-agent' },
    {
      headers: {
        // CLI can cache for 24 h; after that user should re-run the wizard
        'Cache-Control': 'public, max-age=86400, immutable',
      },
    },
  );
}
