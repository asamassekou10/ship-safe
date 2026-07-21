import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { scanFindingKey, scanReportFindings } from '@/lib/scan-findings';

function repositoryParts(value: string): { owner: string; repo: string } | null {
  const normalized = value
    .trim()
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/^git@github\.com:/i, '')
    .replace(/\.git$/i, '')
    .replace(/^\/+|\/+$/g, '');
  const [owner, repo, ...rest] = normalized.split('/');
  return owner && repo && rest.length === 0 ? { owner, repo } : null;
}

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const payload = await req.json().catch(() => null) as { scanId?: string; findingKey?: string } | null;
  if (!payload?.scanId || !payload.findingKey) {
    return NextResponse.json({ error: 'scanId and findingKey are required' }, { status: 400 });
  }

  const scan = await prisma.scan.findFirst({
    where: { id: payload.scanId, userId: session.user.id },
    select: { id: true, repo: true, report: true },
  });
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 });

  const finding = scanReportFindings(scan.report).find(item => scanFindingKey(item) === payload.findingKey);
  if (!finding) return NextResponse.json({ error: 'Finding not found' }, { status: 404 });

  const repository = repositoryParts(scan.repo);
  if (!repository) {
    return NextResponse.json({ error: 'This scan is not linked to a GitHub owner/repository.' }, { status: 400 });
  }

  const settings = await prisma.notificationSetting.findUnique({
    where: { userId: session.user.id },
    select: { githubToken: true },
  });
  if (!settings?.githubToken) {
    return NextResponse.json({
      error: 'Connect GitHub in Settings before creating an issue.',
      setupUrl: '/app/settings#integrations',
    }, { status: 400 });
  }

  const severity = typeof finding.severity === 'string' ? finding.severity : 'unknown';
  const title = typeof finding.title === 'string' ? finding.title : 'Security finding';
  const location = typeof finding.file === 'string'
    ? `\`${finding.file}${finding.line ? `:${finding.line}` : ''}\``
    : null;
  const issueBody = [
    `## [${severity.toUpperCase()}] ${title}`,
    '',
    '**Detected by:** Ship Safe repository scan',
    location ? `**Location:** ${location}` : null,
    typeof finding.rule === 'string' ? `**Rule:** \`${finding.rule}\`` : null,
    typeof finding.cwe === 'string' ? `**CWE:** CWE-${finding.cwe}` : null,
    '',
    typeof finding.description === 'string' ? `### Evidence\n${finding.description}` : null,
    typeof finding.fix === 'string' ? `### Recommended fix\n${finding.fix}` : null,
    '',
    '---',
    `Created from [Ship Safe scan](${process.env.AUTH_URL || 'https://www.shipsafecli.com'}/app/scans/${scan.id}).`,
  ].filter(Boolean).join('\n');

  const response = await fetch(`https://api.github.com/repos/${repository.owner}/${repository.repo}/issues`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${settings.githubToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      title: `[${severity.toUpperCase()}] ${title}`,
      body: issueBody,
      labels: ['security'],
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({})) as { message?: string };
    return NextResponse.json({ error: error.message || `GitHub API error ${response.status}` }, { status: response.status });
  }

  const issue = await response.json() as { html_url: string; number: number };
  return NextResponse.json({ url: issue.html_url, number: issue.number });
}
