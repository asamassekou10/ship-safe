import { prisma } from './prisma';
import crypto from 'crypto';

// ── GitHub App JWT ──────────────────────────────────────────

const APP_ID = process.env.GITHUB_APP_ID || '';
const PRIVATE_KEY = (process.env.GITHUB_APP_PRIVATE_KEY || '').replace(/\\n/g, '\n');

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function generateJWT(): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({ iss: APP_ID, iat: now - 60, exp: now + 600 }));
  const signature = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), PRIVATE_KEY);
  return `${header}.${payload}.${base64url(signature)}`;
}

// ── Installation Token Cache ────────────────────────────────

const tokenCache = new Map<number, { token: string; expiresAt: number }>();

async function getInstallationToken(installationId: number): Promise<string> {
  const cached = tokenCache.get(installationId);
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;

  const jwt = generateJWT();
  const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github.v3+json',
    },
  });

  if (!res.ok) throw new Error(`Failed to get installation token: ${res.status}`);
  const data = await res.json();
  tokenCache.set(installationId, { token: data.token, expiresAt: new Date(data.expires_at).getTime() });
  return data.token;
}

// ── Get Authenticated Client ────────────────────────────────

export interface GitHubClient {
  token: string;
  headers: Record<string, string>;
  fetch: (path: string, init?: RequestInit) => Promise<Response>;
}

/**
 * Get an authenticated GitHub client for a repo.
 * Prefers GitHub App installation token; falls back to user OAuth token.
 */
export async function getGitHubClient(repo: string, userId?: string): Promise<GitHubClient> {
  const [owner] = repo.split('/');
  let token = '';

  // Try GitHub App installation first
  if (APP_ID && PRIVATE_KEY) {
    const installation = await prisma.gitHubInstallation.findFirst({
      where: { accountLogin: owner },
    });
    if (installation) {
      token = await getInstallationToken(installation.installationId);
    }
  }

  // Fallback to user OAuth token
  if (!token && userId) {
    const account = await prisma.account.findFirst({
      where: { userId, provider: 'github' },
      select: { access_token: true },
    });
    if (account?.access_token) token = account.access_token;
  }

  if (!token) throw new Error('No GitHub authentication available for this repo');

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
  };

  return {
    token,
    headers,
    fetch: (path: string, init?: RequestInit) =>
      fetch(`https://api.github.com${path}`, { ...init, headers: { ...headers, ...init?.headers } }),
  };
}
