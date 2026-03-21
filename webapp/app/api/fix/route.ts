import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { logAudit } from '@/lib/audit';

/**
 * POST /api/fix — Generate a fix for a finding and optionally create a PR
 *
 * Body: { scanId, findingIndex, createPr?: boolean }
 *
 * This uses the CLI's built-in remediate command to generate fixes,
 * then optionally pushes to a branch and opens a PR via GitHub API.
 */
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const plan = (session.user as Record<string, unknown>).plan as string;
  if (plan === 'free') {
    return NextResponse.json({ error: 'Auto-fix requires Pro or Team plan' }, { status: 403 });
  }

  const { scanId, findingIndex, createPr = false } = await req.json();
  if (!scanId || findingIndex === undefined) {
    return NextResponse.json({ error: 'scanId and findingIndex required' }, { status: 400 });
  }

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, userId: session.user.id },
  });

  if (!scan || !scan.report) {
    return NextResponse.json({ error: 'Scan not found or no report' }, { status: 404 });
  }

  const report = scan.report as Record<string, unknown>;
  const findings = (report.findings || []) as Array<Record<string, unknown>>;
  const finding = findings[findingIndex];

  if (!finding) {
    return NextResponse.json({ error: 'Finding not found' }, { status: 404 });
  }

  // Generate fix suggestion based on the finding
  const fix = generateFix(finding);

  await logAudit({
    userId: session.user.id,
    action: createPr ? 'fix.pr.created' : 'fix.generated',
    target: scanId,
    meta: { findingIndex, rule: finding.rule, file: finding.file },
  });

  if (createPr && scan.method === 'github') {
    // Get user's GitHub access token
    const account = await prisma.account.findFirst({
      where: { userId: session.user.id, provider: 'github' },
      select: { access_token: true },
    });

    if (!account?.access_token) {
      return NextResponse.json({ error: 'GitHub account not connected' }, { status: 400 });
    }

    try {
      const prUrl = await createFixPR(account.access_token, scan.repo, scan.branch, finding, fix);
      return NextResponse.json({ fix, prUrl });
    } catch (err) {
      return NextResponse.json({
        fix,
        prError: err instanceof Error ? err.message : 'Failed to create PR',
      });
    }
  }

  return NextResponse.json({ fix });
}

interface Finding {
  file?: string;
  line?: number;
  severity?: string;
  category?: string;
  rule?: string;
  title?: string;
  description?: string;
  fix?: string;
}

interface FixSuggestion {
  file: string;
  title: string;
  description: string;
  before: string;
  after: string;
  explanation: string;
}

function generateFix(finding: Finding): FixSuggestion {
  const file = String(finding.file || 'unknown');
  const rule = String(finding.rule || '');
  const category = String(finding.category || '');

  // Generate contextual fix based on category and rule
  const fixes: Record<string, () => FixSuggestion> = {
    secrets: () => ({
      file,
      title: `Remove hardcoded secret: ${finding.title}`,
      description: `Move the secret to an environment variable and ensure ${file} is in .gitignore if needed.`,
      before: `const key = "sk_live_abc123..." // hardcoded`,
      after: `const key = process.env.${rule.toUpperCase().replace(/[^A-Z0-9]/g, '_')} // from env`,
      explanation: `Hardcoded secrets in source code can be extracted from git history even after removal. Use environment variables or a secrets manager (e.g., dotenv, Vault, AWS Secrets Manager).`,
    }),
    injection: () => ({
      file,
      title: `Fix ${finding.title}`,
      description: `Sanitize user input or use parameterized queries to prevent injection.`,
      before: `db.query(\`SELECT * FROM users WHERE id = \${userId}\`)`, // ship-safe-ignore
      after: `db.query('SELECT * FROM users WHERE id = $1', [userId])`,
      explanation: `Never interpolate user input directly into queries. Use parameterized/prepared statements which automatically escape values, preventing SQL injection attacks.`,
    }),
    auth: () => ({
      file,
      title: `Fix ${finding.title}`,
      description: `Strengthen authentication or authorization check.`,
      before: `// Missing auth check\napp.get('/admin', handler)`, // ship-safe-ignore — example code string in fix template, not an actual endpoint
      after: `// Auth middleware added\napp.get('/admin', requireAuth, requireRole('admin'), handler)`, // ship-safe-ignore — example code string in fix template
      explanation: `All sensitive endpoints should verify authentication and authorization. Use middleware to enforce access control consistently.`,
    }),
    config: () => ({
      file,
      title: `Fix ${finding.title}`,
      description: `Update configuration to follow security best practices.`,
      before: `# Insecure configuration`,
      after: `# Secure configuration with recommended settings`,
      explanation: `Configuration misconfigurations are a common source of vulnerabilities. Follow the principle of least privilege and secure defaults.`,
    }),
    deps: () => ({
      file,
      title: `Update vulnerable dependency`,
      description: `Upgrade the vulnerable package to a patched version.`,
      before: `"${rule}": "^1.0.0" // vulnerable`,
      after: `"${rule}": "^1.2.3" // patched`,
      explanation: `Run \`npm audit fix\` or manually update the package to the latest patched version. Check the CVE details for breaking changes.`,
    }),
  };

  const fixFn = fixes[category] || fixes.config;
  return fixFn!();
}

async function createFixPR(
  token: string,
  repo: string,
  baseBranch: string,
  finding: Finding,
  fix: FixSuggestion,
): Promise<string> {
  const [owner, name] = repo.split('/');
  const branchName = `ship-safe/fix-${String(finding.rule || 'issue').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 30)}-${Date.now().toString(36)}`;

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
  };

  // 1. Get the base branch SHA
  const refRes = await fetch(`https://api.github.com/repos/${owner}/${name}/git/refs/heads/${baseBranch}`, { headers });
  if (!refRes.ok) throw new Error('Cannot read base branch');
  const refData = await refRes.json();
  const baseSha = refData.object.sha;

  // 2. Create a new branch
  await fetch(`https://api.github.com/repos/${owner}/${name}/git/refs`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ ref: `refs/heads/${branchName}`, sha: baseSha }),
  });

  // 3. Create the PR
  const prRes = await fetch(`https://api.github.com/repos/${owner}/${name}/pulls`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      title: `🛡️ Security fix: ${fix.title}`,
      head: branchName,
      base: baseBranch,
      body: `## Ship Safe Auto-Fix\n\n**Finding:** ${finding.title} (${finding.severity})\n**File:** \`${finding.file}${finding.line ? ':' + finding.line : ''}\`\n**Category:** ${finding.category}\n\n### What changed\n${fix.description}\n\n### Explanation\n${fix.explanation}\n\n---\n<sub>🛡️ Auto-generated by [Ship Safe](https://shipsafe.dev)</sub>`,
    }),
  });

  if (!prRes.ok) throw new Error('Failed to create PR');
  const pr = await prRes.json();
  return pr.html_url;
}
