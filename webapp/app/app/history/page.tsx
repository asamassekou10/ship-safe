import Link from 'next/link';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from '../dashboard.module.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Scan History — Ship Safe',
};

const PAGE_SIZE = 20;

const scoreColor = (score: number) => score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)';

function timeAgo(date: Date) {
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export default async function History({
  searchParams,
}: {
  searchParams: Promise<{ cursor?: string; page?: string }>;
}) {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const params = await searchParams;
  const cursor = params.cursor;

  // Fetch one extra to detect if there are more pages
  const scans = await prisma.scan.findMany({
    where: { userId: session.user.id },
    orderBy: { createdAt: 'desc' },
    take: PAGE_SIZE + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    select: {
      id: true, repo: true, branch: true, status: true,
      score: true, grade: true, findings: true, createdAt: true,
    },
  });

  const hasMore = scans.length > PAGE_SIZE;
  const displayScans = hasMore ? scans.slice(0, PAGE_SIZE) : scans;
  const nextCursor = hasMore ? displayScans[displayScans.length - 1].id : null;

  // Count total scans for display
  const totalScans = await prisma.scan.count({ where: { userId: session.user.id } });

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Scan History</h1>
          <p className={styles.subtitle}>
            {totalScans} scan{totalScans !== 1 ? 's' : ''} total
          </p>
        </div>
        <Link href="/app/scan" className="btn btn-primary">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg>
          New Scan
        </Link>
      </div>

      {displayScans.length === 0 && !cursor ? (
        <div className={styles.emptyState}>
          <p>No scans yet. Run your first scan to see results here.</p>
          <Link href="/app/scan" className="btn btn-primary">Start first scan</Link>
        </div>
      ) : (
        <>
          <div className={styles.scanList}>
            {displayScans.map(scan => (
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
                    <span style={{ color: 'var(--cyan)', fontSize: '0.82rem', fontWeight: 600 }}>Running...</span>
                  ) : scan.status === 'failed' ? (
                    <span style={{ color: 'var(--red)', fontSize: '0.82rem', fontWeight: 600 }}>Failed</span>
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

          {/* Pagination */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            {cursor ? (
              <Link href="/app/history" className="btn btn-ghost" style={{ fontSize: '0.82rem' }}>
                ← First page
              </Link>
            ) : <span />}
            {nextCursor && (
              <Link href={`/app/history?cursor=${nextCursor}`} className="btn btn-ghost" style={{ fontSize: '0.82rem' }}>
                Next page →
              </Link>
            )}
          </div>
        </>
      )}
    </div>
  );
}
