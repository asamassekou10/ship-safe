import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { scanFindingKey, scanReportFindings } from '@/lib/scan-findings';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
type Severity = (typeof SEVERITIES)[number];
type Summary = Record<Severity, number>;

function emptySummary(): Summary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function normalizeSeverity(value: unknown): Severity {
  const severity = String(value ?? 'info').toLowerCase();
  return SEVERITIES.includes(severity as Severity) ? severity as Severity : 'info';
}

/**
 * GET /api/findings
 * Current security findings across agent runs and the latest completed scan per repository.
 * Query params: severity, status, source (all | scan | agent), agentId, limit.
 */
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { searchParams } = req.nextUrl;
  const severity = searchParams.get('severity');
  const status = searchParams.get('status');
  const source = searchParams.get('source') ?? 'all';
  const agentId = searchParams.get('agentId');
  const requestedLimit = Number.parseInt(searchParams.get('limit') ?? '100', 10);
  const limit = Math.min(Number.isFinite(requestedLimit) ? requestedLimit : 100, 500);
  const includeAgents = source !== 'scan';
  const includeScans = source !== 'agent';

  const [agentFindings, agentCounts, completedScans] = await Promise.all([
    includeAgents
      ? prisma.finding.findMany({
          where: {
            agent: { userId: session.user.id },
            ...(severity ? { severity } : {}),
            ...(status ? { status } : {}),
            ...(agentId ? { agentId } : {}),
          },
          orderBy: { createdAt: 'desc' },
          take: limit,
          include: {
            agent: { select: { id: true, name: true, slug: true } },
            run: { select: { id: true, startedAt: true } },
          },
        })
      : Promise.resolve([]),
    includeAgents
      ? prisma.finding.groupBy({
          by: ['severity'],
          where: { agent: { userId: session.user.id }, status: 'open' },
          _count: { _all: true },
        })
      : Promise.resolve([]),
    includeScans
      ? prisma.scan.findMany({
          where: { userId: session.user.id, status: 'done' },
          select: { id: true, repo: true, branch: true, report: true, createdAt: true },
          orderBy: { createdAt: 'desc' },
          take: 100,
        })
      : Promise.resolve([]),
  ]);

  const summary = emptySummary();
  for (const count of agentCounts) {
    const normalized = normalizeSeverity(count.severity);
    summary[normalized] += count._count._all;
  }

  const latestScans = completedScans.filter((scan, index, scans) =>
    scans.findIndex(candidate => candidate.repo === scan.repo) === index,
  );

  const scanStates = latestScans.length > 0
    ? await prisma.scanFindingState.findMany({
        where: {
          userId: session.user.id,
          scanId: { in: latestScans.map(scan => scan.id) },
        },
        select: { scanId: true, findingKey: true, status: true },
      })
    : [];
  const stateByFinding = new Map(
    scanStates.map(state => [`${state.scanId}:${state.findingKey}`, state.status]),
  );

  const currentScanFindings = latestScans.flatMap(scan =>
    scanReportFindings(scan.report).map((finding, index) => {
      const normalizedSeverity = normalizeSeverity(finding.severity);
      const findingKey = scanFindingKey(finding);
      const findingStatus = stateByFinding.get(`${scan.id}:${findingKey}`) ?? 'open';
      if (findingStatus === 'open') summary[normalizedSeverity] += 1;
      const file = typeof finding.file === 'string' ? finding.file : null;
      const line = typeof finding.line === 'number' ? finding.line : null;
      const cve = typeof finding.cve === 'string'
        ? finding.cve
        : typeof finding.cwe === 'string'
          ? finding.cwe.toUpperCase().startsWith('CWE-') ? finding.cwe : `CWE-${finding.cwe}`
          : null;

      return {
        id: `scan:${scan.id}:${index}`,
        source: 'scan' as const,
        severity: normalizedSeverity,
        title: typeof finding.title === 'string' ? finding.title : 'Untitled scan finding',
        location: file ? `${file}${line ? `:${line}` : ''}` : null,
        cve,
        remediation: typeof finding.fix === 'string'
          ? finding.fix
          : typeof finding.description === 'string' ? finding.description : null,
        status: findingStatus,
        createdAt: scan.createdAt.toISOString(),
        repo: scan.repo,
        branch: scan.branch,
        scan: { id: scan.id, findingKey },
        rule: typeof finding.rule === 'string' ? finding.rule : null,
        category: typeof finding.category === 'string' ? finding.category : null,
      };
    }),
  );

  const scanFindings = currentScanFindings
    .filter(finding => !severity || finding.severity === severity)
    .filter(finding => !status || finding.status === status);

  const normalizedAgentFindings = agentFindings.map(finding => ({
    ...finding,
    source: 'agent' as const,
    repo: null,
    branch: null,
    scan: null,
    rule: null,
    category: null,
  }));

  const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const findings = [...normalizedAgentFindings, ...scanFindings]
    .sort((a, b) => {
      const severityDelta = severityRank[a.severity as Severity] - severityRank[b.severity as Severity];
      return severityDelta || new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    })
    .slice(0, limit);

  return NextResponse.json({ findings, summary, sources: { scans: scanFindings.length, agents: agentFindings.length } });
}
