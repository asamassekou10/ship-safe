import Link from 'next/link';
import { Suspense } from 'react';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from './dashboard.module.css';
import UpgradeToast from './UpgradeToast';
import OnboardingChecklist from './OnboardingChecklist';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Dashboard — Ship Safe',
};

const scoreColor = (score: number) => score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';

export default async function Dashboard() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const userId = session.user.id;

  const plan = (session.user as Record<string, unknown>).plan as string ?? 'free';
  const isPaid = plan === 'pro' || plan === 'team' || plan === 'enterprise';
  const freeLimit = parseInt(process.env.FREE_SCAN_LIMIT ?? '3', 10);
  const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);

  const [
    recentScans, totalScans, scansThisMonth, aggFindings, monitoredRepoCount, notification, orgMembership,
    liveAgents, openFindingCounts, recentAgentFindings,
  ] = await Promise.all([
    prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 10,
      select: {
        id: true, repo: true, branch: true, score: true, grade: true,
        findings: true, status: true, createdAt: true,
      },
    }),
    prisma.scan.count({ where: { userId } }),
    prisma.scan.count({ where: { userId, createdAt: { gte: startOfMonth } } }),
    prisma.scan.aggregate({
      where: { userId, status: 'done' },
      _avg: { score: true },
      _sum: { findings: true },
    }),
    prisma.monitoredRepo.count({ where: { userId } }),
    prisma.notificationSetting.findUnique({ where: { userId }, select: { slackWebhookUrl: true } }),
    prisma.orgMember.count({ where: { userId } }),
    // Agent-specific queries
    prisma.agent.count({ where: { userId, status: 'running' } }),
    prisma.finding.groupBy({
      by: ['severity'],
      where: { agent: { userId }, status: 'open' },
      _count: { _all: true },
    }),
    prisma.finding.findMany({
      where: { agent: { userId }, status: 'open' },
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: {
        agent: { select: { id: true, name: true } },
      },
    }),
  ]);

  const avgScore = Math.round(aggFindings._avg.score ?? 0);
  const totalFindings = aggFindings._sum.findings ?? 0;
  const uniqueRepos = new Set(recentScans.map(s => s.repo)).size;
  const freeExhausted = !isPaid && scansThisMonth >= freeLimit;
  const freeScansLeft = Math.max(0, freeLimit - scansThisMonth);

  const findingSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
  for (const c of openFindingCounts) findingSummary[c.severity] = (findingSummary[c.severity] ?? 0) + c._count._all;
  const totalOpenFindings = Object.values(findingSummary).reduce((a, b) => a + b, 0);

  function timeAgo(date: Date) {
    const diff = Date.now() - new Date(date).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  return (
    <div className={styles.page}>
      <Suspense fallback={null}><UpgradeToast /></Suspense>

      <OnboardingChecklist
        hasScanned={totalScans > 0}
        hasMonitoredRepo={monitoredRepoCount > 0}
        hasSlack={!!notification?.slackWebhookUrl}
        hasTeam={orgMembership > 0}
      />

      {!isPaid && (
        <div className={styles.upgradeCard}>
          <div className={styles.upgradeLeft}>
            {freeExhausted ? (
              <>
                <h3>You&apos;ve used all {freeLimit} free scans this month</h3>
                <p>Resets on the 1st. Upgrade to Pro for unlimited scans, all agents, teams, and API access — $9/month, cancel anytime.</p>
              </>
            ) : (
              <>
                <h3>{freeScansLeft} free scan{freeScansLeft !== 1 ? 's' : ''} left this month</h3>
                <p>Free plan includes {freeLimit} cloud scans/month and 1 agent. Upgrade to Pro for unlimited everything.</p>
              </>
            )}
          </div>
          <Link href="/pricing" className="btn btn-primary">Upgrade to Pro →</Link>
        </div>
      )}

      <div className={styles.header}>
        <div>
          <h1>Dashboard</h1>
          <p className={styles.subtitle}>Your security overview</p>
        </div>
        <Link href="/app/scan" className="btn btn-primary">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg>
          New Scan
        </Link>
      </div>

      {/* Stats row */}
      <div className={styles.statsRow}>
        {[
          { label: 'Avg Score', value: totalScans > 0 ? String(avgScore) : '—', unit: totalScans > 0 ? '/100' : '', color: totalScans > 0 ? scoreColor(avgScore) : 'var(--text-dim)' },
          { label: 'Total Scans', value: String(totalScans), unit: '', color: 'var(--cyan)' },
          { label: 'Open Findings', value: String(totalFindings), unit: '', color: totalFindings > 0 ? 'var(--red)' : 'var(--green)' },
          { label: 'Repos Scanned', value: String(uniqueRepos), unit: '', color: 'var(--green)' },
        ].map(s => (
          <div key={s.label} className={styles.statCard}>
            <span className={styles.statValue} style={{ color: s.color }}>{s.value}<span className={styles.statUnit}>{s.unit}</span></span>
            <span className={styles.statLabel}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* ── Agent Security Overview ── */}
      {(liveAgents > 0 || totalOpenFindings > 0) && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2>Agent Security</h2>
            <Link href="/app/findings" className={styles.seeAll}>
              {totalOpenFindings > 0 ? `${totalOpenFindings} open findings →` : 'View all →'}
            </Link>
          </div>

          <div className={styles.agentStatsRow}>
            <div className={styles.agentStat}>
              <span className={styles.agentStatValue} style={{ color: liveAgents > 0 ? 'var(--green)' : 'var(--text-dim)' }}>
                {liveAgents}
              </span>
              <span className={styles.agentStatLabel}>Live agents</span>
            </div>
            {(['critical','high','medium','low'] as const).map(sev => {
              const n = findingSummary[sev] ?? 0;
              if (n === 0) return null;
              const colors: Record<string,string> = { critical:'var(--red)', high:'#f97316', medium:'var(--yellow)', low:'var(--green)' };
              return (
                <div key={sev} className={styles.agentStat}>
                  <span className={styles.agentStatValue} style={{ color: colors[sev] }}>{n}</span>
                  <span className={styles.agentStatLabel}>{sev}</span>
                </div>
              );
            })}
          </div>

          {recentAgentFindings.length > 0 && (
            <div className={styles.findingsList}>
              {recentAgentFindings.map(f => {
                const sevColors: Record<string,string> = { critical:'#ef4444', high:'#f97316', medium:'#ca8a04', low:'#16a34a', info:'#818cf8' };
                return (
                  <Link key={f.id} href={`/app/agents/${f.agent.id}?tab=findings`} className={styles.findingRow}>
                    <span
                      className={styles.findingSevDot}
                      style={{ background: sevColors[f.severity] ?? 'var(--text-dim)' }}
                    />
                    <span className={styles.findingTitle}>{f.title}</span>
                    <span className={styles.findingAgent}>{f.agent.name}</span>
                    <span className={styles.findingTime}>{timeAgo(f.createdAt)}</span>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Deploy Hermes Agents promo */}
      <div className={styles.hermesCard}>
        <div className={styles.hermesCardLeft}>
          <div className={styles.hermesCardBadge}>
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
            New
          </div>
          <h3>Harden your Hermes agent in one command</h3>
          <p>Answer 4 questions about your tool registry, memory provider, and delegation setup. Get a security config — allowlists, integrity hashes, and CI — dropped into your project.</p>
        </div>
        <Link href="/app/deploy" className="btn btn-primary">
          Deploy agents →
        </Link>
      </div>

      {/* Recent scans */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>Recent scans</h2>
          <Link href="/app/history" className={styles.seeAll}>See all →</Link>
        </div>

        {recentScans.length === 0 ? (
          <div className={styles.emptyState}>
            <p>No scans yet. Run your first scan to see results here.</p>
            <Link href="/app/scan" className="btn btn-primary">Start first scan</Link>
          </div>
        ) : (
          <div className={styles.scanList}>
            {recentScans.map(scan => (
              <Link key={scan.id} href={`/app/scans/${scan.id}`} className={styles.scanRow}>
                <div className={styles.scanLeft}>
                  <div className={styles.repoIcon}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" /></svg>
                  </div>
                  <div>
                    <div className={styles.repoName}>{scan.repo}</div>
                    <div className={styles.repoBranch}>{scan.branch} · {timeAgo(scan.createdAt)}</div>
                  </div>
                </div>
                <div className={styles.scanRight}>
                  {scan.status === 'running' ? (
                    <span className={styles.runningBadge}>Running...</span>
                  ) : scan.status === 'failed' ? (
                    <span className={styles.failedBadge}>Failed</span>
                  ) : (
                    <>
                      <span className={styles.findingCount}>{scan.findings} findings</span>
                      {scan.score !== null && (
                        <div className={styles.scoreChip} style={{ color: scoreColor(scan.score), borderColor: scoreColor(scan.score) + '40', background: scoreColor(scan.score) + '10' }}>
                          <span className={styles.scoreGrade}>{scan.grade}</span>
                          <span className={styles.scoreNum}>{scan.score}</span>
                        </div>
                      )}
                    </>
                  )}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={styles.chevron}><path d="M9 18l6-6-6-6" /></svg>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
