import { NextRequest, NextResponse } from 'next/server';

/* ── Rate limiting (in-memory, per-IP) ── */
const rateMap = new Map<string, { count: number; resetAt: number }>();
const MAX_PER_HOUR = 3;

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateMap.set(ip, { count: 1, resetAt: now + 3600_000 });
    return false;
  }
  if (entry.count >= MAX_PER_HOUR) return true;
  entry.count++;
  return false;
}

/* ── Validation ── */
const GITHUB_URL_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?$/;

function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const m = url.match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

/* ── Secret patterns (subset of cli/utils/patterns.js for serverless) ── */
interface Pattern {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  category: string;
}

const SECRET_PATTERNS: Pattern[] = [
  { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', category: 'secrets' },
  { name: 'AWS Secret Access Key', pattern: /(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, severity: 'critical', category: 'secrets' },
  { name: 'GitHub Personal Access Token', pattern: /ghp_[a-zA-Z0-9]{36}/g, severity: 'critical', category: 'secrets' },
  { name: 'GitHub Fine-Grained PAT', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, severity: 'critical', category: 'secrets' },
  { name: 'Stripe Live Secret Key', pattern: /sk_live_[a-zA-Z0-9]{24,}/g, severity: 'critical', category: 'secrets' },
  { name: 'Private Key Block', pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g, severity: 'critical', category: 'secrets' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20,}/g, severity: 'high', category: 'secrets' },
  { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9_-]{32,}/g, severity: 'high', category: 'secrets' },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: 'high', category: 'secrets' },
  { name: 'SendGrid API Key', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'high', category: 'secrets' },
  { name: 'Twilio API Key', pattern: /SK[a-f0-9]{32}/g, severity: 'high', category: 'secrets' },
  { name: 'Database URL with Credentials', pattern: /(mongodb|postgres|postgresql|mysql|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi, severity: 'high', category: 'secrets' },
  { name: 'NPM Token', pattern: /npm_[a-zA-Z0-9]{36}/g, severity: 'high', category: 'secrets' },
  { name: 'Vercel Token', pattern: /vercel_[a-zA-Z0-9]{24}/gi, severity: 'high', category: 'secrets' },
  { name: 'Neon Database Connection String', pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^.]+\.neon\.tech/g, severity: 'critical', category: 'secrets' },
  { name: 'Generic API Key Assignment', pattern: /["']?(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, severity: 'medium', category: 'secrets' },
  { name: 'Generic Secret Assignment', pattern: /["']?(?:secret|secret[_-]?key)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, severity: 'medium', category: 'secrets' },
  { name: 'Password Assignment', pattern: /["']?password["']?\s*[:=]\s*["']([^"']{8,})["']/gi, severity: 'medium', category: 'secrets' },
];

const VULN_PATTERNS: Pattern[] = [
  { name: 'XSS: dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g, severity: 'high', category: 'injection' },
  { name: 'Code Injection: eval()', pattern: /\beval\s*\(/g, severity: 'high', category: 'injection' }, // ship-safe-ignore
  { name: 'SQL Injection: Template Literal Query', pattern: /`(?:SELECT|INSERT|UPDATE|DELETE|DROP\s+TABLE)[^`]*\$\{/gi, severity: 'critical', category: 'injection' },
  { name: 'Command Injection: exec with Template Literal', pattern: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{/g, severity: 'critical', category: 'injection' },
  { name: 'TLS Bypass: NODE_TLS_REJECT_UNAUTHORIZED=0', pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?/g, severity: 'critical', category: 'config' }, // ship-safe-ignore
  { name: 'TLS Bypass: rejectUnauthorized false', pattern: /\brejectUnauthorized\s*:\s*false\b/g, severity: 'high', category: 'config' },
  { name: 'Security Config: CORS Wildcard', pattern: /\borigin\s*:\s*['"]?\*['"]?/g, severity: 'medium', category: 'config' },
  { name: 'Weak Crypto: MD5', pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi, severity: 'medium', category: 'config' },
];

const ALL_PATTERNS = [...SECRET_PATTERNS, ...VULN_PATTERNS];

/* ── Skip logic ── */
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.woff', '.woff2',
  '.ttf', '.eot', '.otf', '.mp3', '.mp4', '.zip', '.tar', '.gz', '.pdf',
  '.lock', '.min.js', '.min.css', '.exe', '.dll', '.so', '.map',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'vendor', 'dist', 'build', '.next', 'coverage',
  '__pycache__', 'venv', '.venv', '.cache', '.turbo', 'out',
]);

const SKIP_FILENAMES = new Set([
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'composer.lock',
  'Gemfile.lock', 'Pipfile.lock', 'poetry.lock', 'go.sum',
]);

function shouldSkip(path: string): boolean {
  const parts = path.split('/');
  const filename = parts[parts.length - 1]; // ship-safe-ignore — filename extracted from zip entry path for skip-list filtering, not a user file upload

  if (SKIP_FILENAMES.has(filename)) return true;

  for (const part of parts) {
    if (SKIP_DIRS.has(part)) return true;
  }

  for (const ext of SKIP_EXTENSIONS) {
    if (filename.endsWith(ext)) return true;
  }

  return false;
}

/* ── GitHub API helpers ── */
const GITHUB_API = 'https://api.github.com';
const MAX_FILES_TO_SCAN = 50;
const MAX_FILE_SIZE = 100_000; // 100KB per file via API

interface TreeItem {
  path: string;
  type: string;
  size?: number;
  url?: string;
}

interface Finding {
  title: string;
  severity: string;
  category: string;
  file: string;
  line?: number;
}

async function fetchRepoTree(owner: string, repo: string): Promise<TreeItem[]> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`, {
    headers: {
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'ship-safe-demo',
      ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API ${res.status}: ${text}`);
  }

  const data = await res.json();
  return data.tree || [];
}

async function fetchFileContent(owner: string, repo: string, path: string): Promise<string | null> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
    headers: {
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'ship-safe-demo',
      ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
  });

  if (!res.ok) return null;

  const data = await res.json();
  if (data.encoding === 'base64' && data.content) {
    return Buffer.from(data.content, 'base64').toString('utf-8');
  }
  return null;
}

function scanContent(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const p of ALL_PATTERNS) {
    // Reset lastIndex for global regex
    p.pattern.lastIndex = 0;
    let match;
    while ((match = p.pattern.exec(content)) !== null) {
      // Find line number
      const upToMatch = content.slice(0, match.index);
      const lineNum = upToMatch.split('\n').length;

      // Skip if it looks like a test/example/comment
      const line = lines[lineNum - 1] || '';
      if (/\/\/.*example|\/\/.*test|\/\/.*fake|\/\/.*dummy|\/\*.*test/i.test(line)) continue;

      findings.push({
        title: p.name,
        severity: p.severity,
        category: p.category,
        file: filePath,
        line: lineNum,
      });

      // Limit per-pattern to avoid flooding
      if (findings.filter(f => f.title === p.name).length >= 3) break;
    }
  }

  return findings;
}

function computeScore(findings: Finding[]): { score: number; grade: string } {
  let deduction = 0;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': deduction += 15; break;
      case 'high': deduction += 8; break;
      case 'medium': deduction += 3; break;
      default: deduction += 1;
    }
  }
  const score = Math.max(0, Math.min(100, 100 - deduction));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 50 ? 'D' : 'F';
  return { score, grade };
}

/* ── Handler ── */
export async function POST(req: NextRequest) {
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    'unknown';

  if (isRateLimited(ip)) {
    return NextResponse.json(
      { error: 'Rate limit exceeded. Try again in an hour.' },
      { status: 429 },
    );
  }

  let body: { repoUrl?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const { repoUrl } = body;
  if (!repoUrl || !GITHUB_URL_RE.test(repoUrl)) {
    return NextResponse.json(
      { error: 'Provide a valid public GitHub repo URL (https://github.com/owner/repo)' },
      { status: 400 },
    );
  }

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return NextResponse.json({ error: 'Invalid GitHub URL' }, { status: 400 });
  }

  const startTime = Date.now();

  try {
    // 1. Fetch repo file tree via GitHub API
    const tree = await fetchRepoTree(parsed.owner, parsed.repo);

    // 2. Filter to scannable files
    const scannable = tree
      .filter((f) => f.type === 'blob' && !shouldSkip(f.path) && (f.size ?? 0) < MAX_FILE_SIZE)
      .sort((a, b) => {
        // Prioritize config/env files, then by size (smaller first)
        const priority = (p: string) => {
          if (p.includes('.env')) return 0;
          if (p.endsWith('.json') || p.endsWith('.yml') || p.endsWith('.yaml')) return 1;
          if (p.endsWith('.js') || p.endsWith('.ts') || p.endsWith('.py')) return 2;
          return 3;
        };
        return priority(a.path) - priority(b.path) || (a.size ?? 0) - (b.size ?? 0);
      })
      .slice(0, MAX_FILES_TO_SCAN);

    // 3. Fetch file contents in parallel (batched)
    const allFindings: Finding[] = [];
    const batchSize = 10;

    for (let i = 0; i < scannable.length; i += batchSize) {
      const batch = scannable.slice(i, i + batchSize);
      const contents = await Promise.all(
        batch.map((f) => fetchFileContent(parsed.owner, parsed.repo, f.path)),
      );

      for (let j = 0; j < batch.length; j++) {
        const content = contents[j];
        if (content) {
          const findings = scanContent(content, batch[j].path);
          allFindings.push(...findings);
        }
      }

      // Safety cap
      if (allFindings.length > 50) break;
    }

    const duration = Math.round((Date.now() - startTime) / 1000);
    const { score, grade } = computeScore(allFindings);

    // Deduplicate and pick top highlights
    const seen = new Set<string>();
    const highlights = allFindings
      .filter((f) => {
        const key = `${f.title}:${f.file}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .sort((a, b) => {
        const sev = { critical: 0, high: 1, medium: 2, low: 3 };
        return (sev[a.severity as keyof typeof sev] ?? 3) - (sev[b.severity as keyof typeof sev] ?? 3);
      })
      .slice(0, 5)
      .map((f) => ({
        title: `${f.title} in ${f.file}${f.line ? `:${f.line}` : ''}`,
        severity: f.severity,
        category: f.category,
      }));

    // Category summary
    const categories: Record<string, number> = {};
    for (const f of allFindings) {
      categories[f.category] = (categories[f.category] || 0) + 1;
    }

    return NextResponse.json({
      repo: `${parsed.owner}/${parsed.repo}`,
      score,
      grade,
      totalFindings: allFindings.length,
      categories,
      highlights,
      duration,
      filesScanned: scannable.length,
      totalFiles: tree.filter((f) => f.type === 'blob').length,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    if (message.includes('404') || message.includes('Not Found')) {
      return NextResponse.json(
        { error: 'Repository not found. Make sure it exists and is public.' },
        { status: 400 },
      );
    }

    if (message.includes('403')) {
      return NextResponse.json(
        { error: 'GitHub API rate limit reached. Try again in a few minutes.' },
        { status: 429 },
      );
    }

    return NextResponse.json(
      { error: 'Scan failed. Please try again.' },
      { status: 500 },
    );
  }
}
