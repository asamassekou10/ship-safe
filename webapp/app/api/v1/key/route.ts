import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { generateApiKey } from '@/lib/api-auth';
import { logAudit } from '@/lib/audit';

// GET — list API keys (without secrets)
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const keys = await prisma.apiKey.findMany({
    where: { userId: session.user.id },
    select: { id: true, name: true, keyPrefix: true, lastUsedAt: true, expiresAt: true, scopes: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
  });

  return NextResponse.json({ keys });
}

// POST — create a new API key
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string;
  if (plan === 'free') {
    return NextResponse.json({ error: 'API keys require a Pro or Team plan' }, { status: 403 });
  }

  const body = await req.json();
  const { name = 'Default', scopes = ['scan:create', 'scan:read', 'report:read'] } = body;

  // Limit to 5 keys
  const count = await prisma.apiKey.count({ where: { userId: session.user.id } });
  if (count >= 5) {
    return NextResponse.json({ error: 'Maximum 5 API keys allowed' }, { status: 400 });
  }

  const { key, hash, prefix } = generateApiKey();

  await prisma.apiKey.create({
    data: {
      userId: session.user.id,
      name,
      keyHash: hash,
      keyPrefix: prefix,
      scopes,
    },
  });

  await logAudit({ userId: session.user.id, action: 'apikey.created', meta: { name, prefix } });

  // Return the full key ONCE — it cannot be retrieved again
  return NextResponse.json({ key, prefix, name }, { status: 201 });
}

// DELETE — revoke an API key
export async function DELETE(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await req.json();
  if (!id) return NextResponse.json({ error: 'id is required' }, { status: 400 });

  await prisma.apiKey.deleteMany({ where: { id, userId: session.user.id } });
  await logAudit({ userId: session.user.id, action: 'apikey.revoked', target: id });

  return NextResponse.json({ ok: true });
}
