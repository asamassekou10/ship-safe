import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

type Params = { params: Promise<{ findingId: string }> };

/**
 * POST /api/findings/[findingId]/github-issue
 * Body: { owner: string; repo: string }
 * Creates a GitHub issue from the finding using the user's stored PAT.
 */
export async function POST(req: NextRequest, { params }: Params) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { findingId } = await params;

  // Load finding + verify ownership
  const finding = await prisma.finding.findUnique({
    where: { id: findingId },
    include: { agent: { select: { userId: true, name: true } } },
  });
  if (!finding || finding.agent.userId !== session.user.id) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  // Load GitHub token
  const settings = await prisma.notificationSetting.findUnique({
    where: { userId: session.user.id },
    select: { githubToken: true },
  });
  if (!settings?.githubToken) {
    return NextResponse.json({ error: 'No GitHub token configured. Add it in Settings → Integrations.' }, { status: 400 });
  }

  const { owner, repo } = await req.json();
  if (!owner?.trim() || !repo?.trim()) {
    return NextResponse.json({ error: 'owner and repo are required' }, { status: 400 });
  }

  // Build issue body
  const sevEmoji: Record<string, string> = {
    critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: 'ℹ️',
  };
  const emoji = sevEmoji[finding.severity] ?? '⚠️';

  const body = [
    `## ${emoji} [${finding.severity.toUpperCase()}] ${finding.title}`,
    '',
    `**Detected by:** Ship Safe agent — *${finding.agent.name}*`,
    finding.location ? `**Location:** \`${finding.location}\`` : null,
    finding.cve      ? `**CVE:** ${finding.cve}` : null,
    '',
    finding.remediation ? `### Remediation\n${finding.remediation}` : null,
    '',
    `---`,
    `*Automatically created from [Ship Safe Findings](${process.env.AUTH_URL || 'https://shipsafecli.com'}/app/findings)*`,
  ].filter(Boolean).join('\n');

  const ghRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${settings.githubToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
      body,
      labels: ['security', `severity:${finding.severity}`],
    }),
  });

  if (!ghRes.ok) {
    const err = await ghRes.json().catch(() => ({}));
    return NextResponse.json(
      { error: (err as { message?: string }).message || `GitHub API error ${ghRes.status}` },
      { status: ghRes.status },
    );
  }

  const issue = await ghRes.json() as { html_url: string; number: number };
  return NextResponse.json({ url: issue.html_url, number: issue.number });
}
