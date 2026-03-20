import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';
import { promisify } from 'util';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';

const execAsync = promisify(exec);

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

// Cleanup stale entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateMap) {
    if (now > entry.resetAt) rateMap.delete(ip);
  }
}, 600_000).unref?.();

/* ── Validation ── */
const GITHUB_URL_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?$/;

function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const m = url.match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  return m ? { owner: m[1], repo: m[2] } : null;
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

  const tmpDir = await mkdtemp(join(tmpdir(), 'shipsafe-demo-'));
  const startTime = Date.now();

  try {
    // Shallow clone
    await execAsync(`git clone --depth 1 ${repoUrl} ${join(tmpDir, 'repo')}`, {
      timeout: 30_000,
    });

    const scanDir = join(tmpDir, 'repo');

    // Run a lightweight scan with JSON output
    const { stdout } = await execAsync(
      `npx ship-safe audit ${scanDir} --json`,
      { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
    );

    const duration = Math.round((Date.now() - startTime) / 1000);
    let report: Record<string, unknown> = {};
    try {
      report = JSON.parse(stdout);
    } catch {
      report = { raw: stdout };
    }

    const score = typeof report.score === 'number' ? report.score : null;
    const grade = typeof report.grade === 'string' ? report.grade : null;
    const totalFindings = typeof report.totalFindings === 'number' ? report.totalFindings : 0;

    // Extract top findings for highlights
    const findings = Array.isArray(report.findings) ? report.findings : [];
    const highlights = findings.slice(0, 5).map((f: Record<string, unknown>) => ({
      title: f.title || f.message || 'Finding',
      severity: f.severity || 'medium',
      category: f.category || 'general',
    }));

    // Category summary
    const cats = report.categories as Record<string, { findingCount?: number }> | undefined;
    const categories: Record<string, number> = {};
    if (cats) {
      for (const [key, val] of Object.entries(cats)) {
        if (val?.findingCount) categories[key] = val.findingCount;
      }
    }

    return NextResponse.json({
      repo: `${parsed.owner}/${parsed.repo}`,
      score,
      grade,
      totalFindings,
      categories,
      highlights,
      duration,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    if (message.includes('Repository not found') || message.includes('fatal:')) {
      return NextResponse.json(
        { error: 'Could not clone repository. Make sure it exists and is public.' },
        { status: 400 },
      );
    }

    return NextResponse.json(
      { error: 'Scan failed. The repository may be too large or private.' },
      { status: 500 },
    );
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
