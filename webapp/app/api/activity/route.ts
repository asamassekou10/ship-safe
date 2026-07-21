import { NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { scanReportFindings } from '@/lib/scan-findings';

type ActivitySeverity = 'critical' | 'high' | 'medium' | 'info';

interface ActivityItem {
  id: string;
  severity: ActivitySeverity;
  title: string;
  detail: string;
  href: string;
  createdAt: string;
}

const severityRank: Record<ActivitySeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  info: 3,
};

function normalizeSeverity(value: unknown): ActivitySeverity {
  const severity = String(value ?? '').toLowerCase();
  if (severity === 'critical' || severity === 'high' || severity === 'medium') return severity;
  return 'info';
}

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const userId = session.user.id;
  const [user, scans, findings, failedRuns, guardianRuns] = await Promise.all([
    prisma.user.findUnique({ where: { id: userId }, select: { lastActivityReadAt: true } }),
    prisma.scan.findMany({
      where: { userId, OR: [{ status: 'failed' }, { status: 'done', findings: { gt: 0 } }] },
      orderBy: { createdAt: 'desc' },
      take: 20,
      select: { id: true, repo: true, status: true, findings: true, score: true, report: true, createdAt: true },
    }),
    prisma.finding.findMany({
      where: { agent: { userId }, status: 'open', severity: { in: ['critical', 'high'] } },
      orderBy: { createdAt: 'desc' },
      take: 20,
      select: { id: true, title: true, severity: true, location: true, createdAt: true, agent: { select: { id: true, name: true } } },
    }),
    prisma.agentRun.findMany({
      where: { status: 'error', deployment: { agent: { userId } } },
      orderBy: { startedAt: 'desc' },
      take: 10,
      select: { id: true, startedAt: true, deployment: { select: { agent: { select: { id: true, name: true } } } } },
    }),
    prisma.pRGuardianRun.findMany({
      where: { userId, status: { in: ['failed', 'blocked'] } },
      orderBy: { updatedAt: 'desc' },
      take: 10,
      select: { id: true, repo: true, prNumber: true, status: true, failureType: true, updatedAt: true },
    }),
  ]);

  const scanItems: ActivityItem[] = scans.map(scan => {
    if (scan.status === 'failed') {
      return {
        id: `scan-failed:${scan.id}`,
        severity: 'high',
        title: `Scan failed for ${scan.repo}`,
        detail: 'Open the scan to review the failure and try again.',
        href: `/app/scans/${scan.id}`,
        createdAt: scan.createdAt.toISOString(),
      };
    }

    const highest = scanReportFindings(scan.report)
      .map(finding => normalizeSeverity(finding.severity))
      .sort((a, b) => severityRank[a] - severityRank[b])[0] ?? 'medium';
    return {
      id: `scan-findings:${scan.id}`,
      severity: highest,
      title: `${scan.findings} finding${scan.findings === 1 ? '' : 's'} in ${scan.repo}`,
      detail: scan.score == null ? 'Review the latest scan results.' : `Security score ${scan.score}/100`,
      href: `/app/scans/${scan.id}`,
      createdAt: scan.createdAt.toISOString(),
    };
  });

  const items: ActivityItem[] = [
    ...scanItems,
    ...findings.map(finding => ({
      id: `agent-finding:${finding.id}`,
      severity: normalizeSeverity(finding.severity),
      title: finding.title,
      detail: `${finding.agent.name}${finding.location ? ` · ${finding.location}` : ''}`,
      href: `/app/agents/${finding.agent.id}`,
      createdAt: finding.createdAt.toISOString(),
    })),
    ...failedRuns.map(run => ({
      id: `agent-run:${run.id}`,
      severity: 'high' as const,
      title: `${run.deployment.agent.name} run failed`,
      detail: 'Open the agent activity to inspect the run.',
      href: `/app/agents/${run.deployment.agent.id}`,
      createdAt: run.startedAt.toISOString(),
    })),
    ...guardianRuns.map(run => ({
      id: `guardian:${run.id}`,
      severity: run.status === 'failed' ? 'high' as const : 'medium' as const,
      title: `PR Guardian ${run.status} on ${run.repo}#${run.prNumber}`,
      detail: run.failureType ? `Failure type: ${run.failureType}` : 'Review the Guardian timeline.',
      href: '/app/guardian',
      createdAt: run.updatedAt.toISOString(),
    })),
  ]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 20);

  const readAt = user?.lastActivityReadAt?.getTime() ?? 0;
  const unreadCount = items.filter(item => new Date(item.createdAt).getTime() > readAt).length;

  return NextResponse.json({ items, unreadCount, lastReadAt: user?.lastActivityReadAt ?? null });
}

export async function POST() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const lastActivityReadAt = new Date();
  await prisma.user.update({
    where: { id: session.user.id },
    data: { lastActivityReadAt },
  });

  return NextResponse.json({ ok: true, lastReadAt: lastActivityReadAt });
}
