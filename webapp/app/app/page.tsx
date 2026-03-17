import Link from 'next/link';
import styles from './dashboard.module.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Dashboard — Ship Safe',
};

const recentScans = [
  { id: '1', repo: 'my-saas-app', branch: 'main', score: 82, grade: 'B', findings: 7, date: '2 hours ago', status: 'pass' },
  { id: '2', repo: 'api-service', branch: 'feat/auth', score: 61, grade: 'D', findings: 23, date: '1 day ago', status: 'fail' },
  { id: '3', repo: 'frontend', branch: 'main', score: 94, grade: 'A', findings: 2, date: '3 days ago', status: 'pass' },
];

const scoreColor = (score: number) => score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';

export default function Dashboard() {
  return (
    <div className={styles.page}>
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
          { label: 'Avg Score', value: '79', unit: '/100', color: 'var(--yellow)' },
          { label: 'Total Scans', value: '3', unit: '', color: 'var(--cyan)' },
          { label: 'Open Findings', value: '32', unit: '', color: 'var(--red)' },
          { label: 'Repos Scanned', value: '3', unit: '', color: 'var(--green)' },
        ].map(s => (
          <div key={s.label} className={styles.statCard}>
            <span className={styles.statValue} style={{ color: s.color }}>{s.value}<span className={styles.statUnit}>{s.unit}</span></span>
            <span className={styles.statLabel}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* Recent scans */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>Recent scans</h2>
          <Link href="/app/history" className={styles.seeAll}>See all →</Link>
        </div>

        <div className={styles.scanList}>
          {recentScans.map(scan => (
            <Link key={scan.id} href={`/app/scans/${scan.id}`} className={styles.scanRow}>
              <div className={styles.scanLeft}>
                <div className={styles.repoIcon}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" /></svg>
                </div>
                <div>
                  <div className={styles.repoName}>{scan.repo}</div>
                  <div className={styles.repoBranch}>{scan.branch} · {scan.date}</div>
                </div>
              </div>
              <div className={styles.scanRight}>
                <span className={styles.findingCount}>{scan.findings} findings</span>
                <div className={styles.scoreChip} style={{ color: scoreColor(scan.score), borderColor: scoreColor(scan.score) + '40', background: scoreColor(scan.score) + '10' }}>
                  <span className={styles.scoreGrade}>{scan.grade}</span>
                  <span className={styles.scoreNum}>{scan.score}</span>
                </div>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={styles.chevron}><path d="M9 18l6-6-6-6" /></svg>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Empty state / upgrade prompt for free users */}
      <div className={styles.section}>
        <div className={styles.upgradeCard}>
          <div className={styles.upgradeLeft}>
            <h3>Unlock unlimited scans</h3>
            <p>You've used 3 of 5 free scans. Upgrade to Pro for unlimited scans, private repos, AI deep analysis, and scan history.</p>
          </div>
          <Link href="/pricing" className="btn btn-primary">Upgrade to Pro</Link>
        </div>
      </div>
    </div>
  );
}
