import { NextRequest } from 'next/server';
import { prisma } from './prisma';
import crypto from 'crypto';

/**
 * Authenticate API requests via Bearer token (API key) or session.
 * Returns { userId, keyId } or null.
 */
export async function authenticateApiKey(req: NextRequest): Promise<{ userId: string; keyId: string } | null> { // ship-safe-ignore — this IS the auth library; it validates tokens, not forward credentials between tools
  const authHeader = req.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer sk_')) return null;

  const key = authHeader.slice(7); // Remove "Bearer "
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');

  const apiKey = await prisma.apiKey.findUnique({
    where: { keyHash },
    select: { id: true, userId: true, expiresAt: true, scopes: true },
  });

  if (!apiKey) return null;
  if (apiKey.expiresAt && apiKey.expiresAt < new Date()) return null;

  // Update last used
  prisma.apiKey.update({ where: { id: apiKey.id }, data: { lastUsedAt: new Date() } }).catch(() => {});

  return { userId: apiKey.userId, keyId: apiKey.id };
}

export function generateApiKey(): { key: string; hash: string; prefix: string } {
  const raw = crypto.randomBytes(32).toString('base64url');
  const key = `sk_live_${raw}`;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  const prefix = key.slice(0, 16);
  return { key, hash, prefix };
}
