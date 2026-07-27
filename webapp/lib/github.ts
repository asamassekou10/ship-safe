import { prisma } from './prisma';
import crypto from 'crypto';
import { CANONICAL_URL } from './site';

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

  if (process.env.CONTENT_AGENT_GITHUB_TOKEN) {
    token = process.env.CONTENT_AGENT_GITHUB_TOKEN;
  }

  // Try GitHub App installation first
  if (!token && APP_ID && PRIVATE_KEY) {
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

// ── PR Comment ──────────────────────────────────────────────

export async function postPRComment(
  repo: string,
  prNumber: number,
  score: number | null,
  grade: string | null,
  findings: number,
  secrets: number,
  vulns: number,
  scanId: string,
  userId: string,
) {
  let client: GitHubClient;
  try {
    client = await getGitHubClient(repo, userId);
  } catch {
    return; // No GitHub auth — skip silently
  }

  const gradeEmoji = (grade ?? 'F') <= 'B' ? '✅' : (grade ?? 'F') <= 'C' ? '⚠️' : '🚨';
  const scoreColor = (score ?? 0) >= 80 ? '🟢' : (score ?? 0) >= 60 ? '🟡' : '🔴';
  const appUrl = CANONICAL_URL;

  const body = [
    `## ${gradeEmoji} Ship Safe Security Scan`,
    '',
    `| | |`,
    `|---|---|`,
    `| **Score** | ${scoreColor} ${score ?? '?'}/100 (${grade ?? 'F'}) |`,
    `| **Findings** | ${findings} |`,
    `| **Secrets** | ${secrets > 0 ? `🔴 ${secrets}` : '✅ 0'} |`,
    `| **Vulns** | ${vulns > 0 ? `🔴 ${vulns}` : '✅ 0'} |`,
    '',
    findings > 0
      ? `> ⚠️ This PR introduced or contains security findings. [View full report](${appUrl}/app/scans/${scanId})`
      : `> ✅ No security issues found. [View full report](${appUrl}/app/scans/${scanId})`,
    '',
    `<sub>Scanned by [Ship Safe](${CANONICAL_URL}) · [Dismiss](${appUrl}/app/scans/${scanId})</sub>`,
  ].join('\n');

  const [owner, repoName] = repo.split('/');
  await client.fetch(`/repos/${owner}/${repoName}/issues/${prNumber}/comments`, {
    method: 'POST',
    body: JSON.stringify({ body }),
  }).catch(console.error);
}
