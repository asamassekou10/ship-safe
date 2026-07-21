import Link from 'next/link';
import { Suspense, type CSSProperties } from 'react';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from './dashboard.module.css';
import UpgradeToast from './UpgradeToast';
import OnboardingChecklist from './OnboardingChecklist';
import DashboardTrend from './DashboardTrend';
import { RiskSignalChart, SeverityOverview } from './DashboardRiskCharts';
import RepositoryPosture, { type RepositoryPostureItem } from './RepositoryPosture';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Dashboard — Ship Safe',
};

const scoreColor = (score: number) => score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';
const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#38bdf8',
};

function timeAgo(date: Date) {
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export default async function Dashboard() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const userId = session.user.id;
  const plan = ((session.user as Record<string, unknown>).plan as string) ?? 'free';
  const isPaid = plan === 'pro' || plan === 'team' || plan === 'enterprise';
  const freeLimit = parseInt(process.env.FREE_SCAN_LIMIT ?? '3', 10);
  const now = new Date();
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  const healthStart = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const onboardingState = await prisma.user.findUnique({
    where: { id: userId },
    select: { onboardingCompleted: true, llmSettings: true },
  });
  const everScanned = await prisma.scan.count({ where: { userId }, take: 1 });
  if (everScanned === 0 && !onboardingState?.onboardingCompleted) redirect('/app/onboarding');

  const [
    recentScans,
    totalScans,
    scansThisMonth,
    scoreAggregate,
    monitoredRepos,
    scannedRepoGroups,
    notification,
    orgMembership,
    activeAgents,
    openFindingCounts,
    recentAgentFindings,
    trendScans,
    guardianConfigCount,
    scanStatusCounts,
    scanRiskAggregate,
    repositoryScans,
  ] = await Promise.all([
    prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 8,
      select: {
        id: true, repo: true, branch: true, score: true, grade: true,
        findings: true, status: true, createdAt: true,
      },
    }),
    prisma.scan.count({ where: { userId } }),
    prisma.scan.count({ where: { userId, createdAt: { gte: startOfMonth } } }),
    prisma.scan.aggregate({ where: { userId, status: 'done' }, _avg: { score: true } }),
    prisma.monitoredRepo.findMany({ where: { userId, enabled: true }, select: { repo: true } }),
    prisma.scan.groupBy({ by: ['repo'], where: { userId } }),
    prisma.notificationSetting.findUnique({ where: { userId }, select: { slackWebhookUrl: true } }),
    prisma.orgMember.count({ where: { userId } }),
    prisma.agent.count({ where: { userId, status: { in: ['running', 'deployed'] } } }),
    prisma.finding.groupBy({
      by: ['severity'],
      where: { agent: { userId }, status: 'open' },
      _count: { _all: true },
    }),
    prisma.finding.findMany({
      where: { agent: { userId }, status: 'open' },
      orderBy: { createdAt: 'desc' },
      take: 8,
      include: { agent: { select: { id: true, name: true } } },
    }),
    prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
      select: { createdAt: true, status: true, score: true, findings: true },
    }),
    prisma.guardianConfig.count({ where: { userId, enabled: true } }),
    prisma.scan.groupBy({ by: ['status'], where: { userId }, _count: { _all: true } }),
    prisma.scan.aggregate({
      where: { userId, status: 'done' },
      _sum: { findings: true, secrets: true, vulns: true, cves: true },
    }),
    prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 250,
      select: { id: true, repo: true, score: true, grade: true, findings: true, status: true, createdAt: true },
    }),
  ]);

  const monitoredRepoCount = monitoredRepos.length;
  const monitoredRepoNames = new Set(monitoredRepos.map(repository => repository.repo));
  const avgScore = Math.round(scoreAggregate._avg.score ?? 0);
  const freeExhausted = !isPaid && scansThisMonth >= freeLimit;
  const findingSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
  for (const count of openFindingCounts) findingSummary[count.severity] = count._count._all;
  const totalOpenFindings = Object.values(findingSummary).reduce((sum, count) => sum + count, 0);
  const urgentFindings = findingSummary.critical + findingSummary.high;
  const latestScan = recentScans[0];
  const scanOutcomes = ['done', 'failed', 'running', 'pending'].map(status => ({
    status,
    count: scanStatusCounts.find(item => item.status === status)?._count._all ?? 0,
  }));
  const riskSignals = [
    { label: 'Agent findings', value: totalOpenFindings, color: '#22d3ee', href: '/app/findings?source=agent&status=open' },
    { label: 'Scan findings', value: scanRiskAggregate._sum.findings ?? 0, color: '#8b5cf6', href: '/app/findings?source=scan&status=open' },
    { label: 'Secrets', value: scanRiskAggregate._sum.secrets ?? 0, color: '#ef4444', href: '/app/findings?source=scan&status=open' },
    { label: 'Vulnerabilities', value: scanRiskAggregate._sum.vulns ?? 0, color: '#f97316', href: '/app/findings?source=scan&status=open' },
    { label: 'Known CVEs', value: scanRiskAggregate._sum.cves ?? 0, color: '#eab308', href: '/app/findings?source=scan&status=open' },
  ];
  const scansByRepository = new Map<string, typeof repositoryScans>();
  for (const scan of repositoryScans) {
    const scans = scansByRepository.get(scan.repo) ?? [];
    scans.push(scan);
    scansByRepository.set(scan.repo, scans);
  }
  const repositoryPosture: RepositoryPostureItem[] = [...scansByRepository.entries()].map(([repo, scans]) => {
    const latest = scans[0];
    const scored = scans.filter(scan => scan.score !== null);
    const current = scored[0] ?? latest;
    const previous = scored[1];
    return {
      repo,
      latestScanId: latest.id,
      score: current.score,
      grade: current.grade,
      findings: current.findings,
      status: latest.status,
      protected: monitoredRepoNames.has(repo),
      previousScore: previous?.score ?? null,
      scannedAt: latest.createdAt.toISOString(),
    };
  }).sort((a, b) => {
    if (a.status === 'failed' && b.status !== 'failed') return -1;
    if (b.status === 'failed' && a.status !== 'failed') return 1;
    return (a.score ?? -1) - (b.score ?? -1);
  }).slice(0, 6);

  const healthScans = trendScans.filter(scan => scan.createdAt >= healthStart && ['done', 'failed'].includes(scan.status));
  const successfulScans = healthScans.filter(scan => scan.status === 'done').length;
  const scanSuccessRate = healthScans.length ? Math.round((successfulScans / healthScans.length) * 100) : null;

  const rawLlmSettings = onboardingState?.llmSettings;
  const llmSettings = rawLlmSettings && typeof rawLlmSettings === 'object' && !Array.isArray(rawLlmSettings)
    ? rawLlmSettings as Record<string, unknown>
    : null;
  const llmProvider = typeof llmSettings?.provider === 'string' ? llmSettings.provider : '';
  const llmConfigured = Boolean(llmProvider && llmProvider !== 'auto');

  const nextAction = latestScan && ['pending', 'running'].includes(latestScan.status)
    ? { eyebrow: 'Scan in progress', title: `Analyzing ${latestScan.repo}`, description: 'Ship Safe is running the security agent suite now. Open the live scan to follow each stage.', href: `/app/scans/${latestScan.id}`, cta: 'View live scan' }
    : latestScan?.status === 'failed'
      ? { eyebrow: 'Scan needs attention', title: 'Recover your latest scan', description: 'Review the failure reason, confirm repository access, and retry with the same settings.', href: `/app/scans/${latestScan.id}`, cta: 'Review failed scan' }
    : urgentFindings > 0
      ? { eyebrow: 'Priority findings', title: `${urgentFindings} urgent finding${urgentFindings === 1 ? '' : 's'} need review`, description: 'Start with critical and high-severity agent findings, then verify each fix with a fresh scan.', href: '/app/findings', cta: 'Open security inbox' }
      : latestScan?.findings
        ? { eyebrow: 'Latest scan', title: `Review ${latestScan.findings} finding${latestScan.findings === 1 ? '' : 's'} in ${latestScan.repo}`, description: 'Work from highest severity to lowest, then rescan to confirm the remediation.', href: `/app/scans/${latestScan.id}`, cta: 'Review scan' }
        : monitoredRepoCount === 0
          ? { eyebrow: 'Continuous protection', title: 'Monitor your first repository', description: 'Schedule scans so regressions and new dependency risks return to one place.', href: '/app/repos', cta: 'Add repository' }
          : { eyebrow: 'Security check', title: 'Your workspace is ready for a fresh scan', description: 'Check the latest code and compare its security posture with the previous result.', href: '/app/scan', cta: 'Start scan' };

  const postureLabel = totalScans === 0 ? 'No baseline' : avgScore >= 80 ? 'Strong posture' : avgScore >= 60 ? 'Needs attention' : 'At risk';
  const postureStyle = { '--posture-angle': `${Math.max(0, Math.min(avgScore, 100)) * 3.6}deg`, '--posture-color': scoreColor(avgScore) } as CSSProperties;

  const activity = [
    ...recentScans.map(scan => ({
      id: `scan-${scan.id}`,
      href: `/app/scans/${scan.id}`,
      kind: 'Scan',
      title: scan.repo,
      detail: scan.status === 'done'
        ? `${scan.findings} finding${scan.findings === 1 ? '' : 's'}${scan.score !== null ? ` · score ${scan.score}` : ''}`
        : scan.status === 'failed' ? 'Scan failed · review recovery steps' : 'Scan in progress',
      status: scan.status,
      color: scan.status === 'failed' ? 'var(--red)' : scan.status === 'done' ? 'var(--cyan)' : 'var(--yellow)',
      createdAt: scan.createdAt,
    })),
    ...recentAgentFindings.map(finding => ({
      id: `finding-${finding.id}`,
      href: `/app/agents/${finding.agent.id}?tab=findings`,
      kind: finding.severity,
      title: finding.title,
      detail: finding.agent.name,
      status: 'finding',
      color: severityColors[finding.severity] ?? 'var(--text-dim)',
      createdAt: finding.createdAt,
    })),
  ].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, 6);

  const systemHealth = [
    { label: 'Repository monitoring', value: monitoredRepoCount ? `${monitoredRepoCount} protected` : 'Not configured', ready: monitoredRepoCount > 0, href: '/app/repos' },
    { label: 'Security agents', value: activeAgents ? `${activeAgents} active` : 'No active agents', ready: activeAgents > 0, href: '/app/agents' },
    { label: 'PR Guardian', value: guardianConfigCount ? `${guardianConfigCount} enabled` : 'Not configured', ready: guardianConfigCount > 0, href: '/app/guardian' },
    { label: 'AI analysis', value: llmConfigured ? llmProvider : 'Provider needed', ready: llmConfigured, href: '/app/settings' },
    { label: 'Notifications', value: notification?.slackWebhookUrl ? 'Slack connected' : 'Not connected', ready: Boolean(notification?.slackWebhookUrl), href: '/app/settings' },
  ];

  return (
    <div className={styles.page}>
      <Suspense fallback={null}><UpgradeToast /></Suspense>

      <header className={styles.header}>
        <div>
          <span className={styles.workspaceLabel}>Ship Safe workspace</span>
          <h1>Security overview</h1>
          <p className={styles.subtitle}>Your code, repositories, and AI agents in one operational view.</p>
        </div>
        <div className={styles.headerActions}>
          <span className={styles.planPill}>{plan} plan</span>
          <Link href="/app/scan" className={styles.primaryCta}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg>
            New scan
          </Link>
        </div>
      </header>

      <OnboardingChecklist
        hasScanned={totalScans > 0}
        hasMonitoredRepo={monitoredRepoCount > 0}
        hasSlack={Boolean(notification?.slackWebhookUrl)}
        hasTeam={orgMembership > 0}
      />

      <div className={styles.commandGrid}>
        <section className={styles.nextAction}>
          <div className={styles.nextActionSignal}><span /></div>
          <div className={styles.nextActionCopy}>
            <span className={styles.nextActionEyebrow}>{nextAction.eyebrow}</span>
            <h2>{nextAction.title}</h2>
            <p>{nextAction.description}</p>
          </div>
          <Link href={nextAction.href} className={styles.primaryCta}>{nextAction.cta} →</Link>
        </section>

        <section className={styles.posturePanel}>
          <div className={styles.postureCopy}>
            <span className={styles.panelEyebrow}>Security posture</span>
            <h2>{postureLabel}</h2>
            <p>{urgentFindings ? `${urgentFindings} urgent finding${urgentFindings === 1 ? '' : 's'} open` : 'No urgent agent findings'}</p>
          </div>
          <div className={styles.postureRing} style={postureStyle} aria-label={`Average security score ${avgScore} out of 100`}>
            <div>
              <strong>{totalScans ? avgScore : '—'}</strong>
              <span>{totalScans ? '/100' : 'score'}</span>
            </div>
          </div>
        </section>
      </div>

      {freeExhausted && (
        <div className={styles.upgradeCard}>
          <div className={styles.upgradeLeft}>
            <h3>You&apos;ve used all {freeLimit} free scans this month</h3>
            <p>Your allowance resets on the first. Pro includes unlimited cloud scans.</p>
          </div>
          <Link href="/app/checkout?plan=pro" className={styles.secondaryCta}>View Pro plan</Link>
        </div>
      )}

      <section className={styles.metricsStrip} aria-label="Workspace metrics">
        <div className={styles.metric}>
          <span className={styles.metricIcon}>S</span>
          <div><strong>{totalOpenFindings}</strong><span>Open risks</span></div>
          <small>{urgentFindings} urgent</small>
        </div>
        <div className={styles.metric}>
          <span className={styles.metricIcon}>R</span>
          <div><strong>{monitoredRepoCount}</strong><span>Protected repos</span></div>
          <small>{scannedRepoGroups.length} scanned</small>
        </div>
        <div className={styles.metric}>
          <span className={styles.metricIcon}>A</span>
          <div><strong>{activeAgents}</strong><span>Active agents</span></div>
          <small>{activeAgents ? 'Operational' : 'Setup needed'}</small>
        </div>
        <div className={styles.metric}>
          <span className={styles.metricIcon}>✓</span>
          <div><strong>{scanSuccessRate === null ? '—' : `${scanSuccessRate}%`}</strong><span>Scan health</span></div>
          <small>Last 30 days</small>
        </div>
      </section>

      <div className={styles.analyticsGrid}>
        <DashboardTrend scans={trendScans.map(scan => ({ ...scan, createdAt: scan.createdAt.toISOString() }))} />

        <SeverityOverview severity={findingSummary as { critical: number; high: number; medium: number; low: number; info: number }} outcomes={scanOutcomes} />
      </div>

      <div className={styles.analyticsGrid}>
        <RiskSignalChart signals={riskSignals} />

        <section className={styles.healthPanel} aria-labelledby="system-health-title">
          <div className={styles.panelHeader}>
            <div>
              <span className={styles.panelEyebrow}>Coverage</span>
              <h2 id="system-health-title">System health</h2>
            </div>
            <span className={styles.healthScore}>{systemHealth.filter(item => item.ready).length}/{systemHealth.length}</span>
          </div>
          <div className={styles.healthList}>
            {systemHealth.map(item => (
              <Link key={item.label} href={item.href} className={styles.healthRow}>
                <span className={`${styles.healthDot} ${item.ready ? styles.healthReady : styles.healthNeedsSetup}`} />
                <span className={styles.healthLabel}>{item.label}</span>
                <span className={styles.healthValue}>{item.value}</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m9 18 6-6-6-6" /></svg>
              </Link>
            ))}
          </div>
          <Link href="/app/deploy" className={styles.healthFooter}>Harden a Hermes agent <span>→</span></Link>
        </section>
      </div>

      <RepositoryPosture repositories={repositoryPosture} />

      <section className={styles.activityPanel} aria-labelledby="activity-title">
        <div className={styles.panelHeader}>
          <div>
            <span className={styles.panelEyebrow}>Latest signal</span>
            <h2 id="activity-title">Security activity</h2>
          </div>
          <div className={styles.activityLinks}>
            <Link href="/app/findings">Findings</Link>
            <Link href="/app/history">Scan history</Link>
          </div>
        </div>

        {activity.length === 0 ? (
          <div className={styles.activityEmpty}>
            <strong>No security activity yet</strong>
            <span>Run your first scan to establish a baseline.</span>
            <Link href="/app/scan" className={styles.primaryCta}>Start first scan</Link>
          </div>
        ) : (
          <div className={styles.activityList}>
            {activity.map(item => (
              <Link href={item.href} key={item.id} className={styles.activityRow}>
                <span className={styles.activitySignal} style={{ background: item.color, boxShadow: `0 0 0 4px color-mix(in srgb, ${item.color} 12%, transparent)` }} />
                <span className={styles.activityKind}>{item.kind}</span>
                <span className={styles.activityMain}>
                  <strong>{item.title}</strong>
                  <small>{item.detail}</small>
                </span>
                <span className={styles.activityTime}>{timeAgo(item.createdAt)}</span>
                <svg className={styles.activityArrow} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m9 18 6-6-6-6" /></svg>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
