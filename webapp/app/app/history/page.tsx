import Link from 'next/link';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import dashStyles from '../dashboard.module.css';
import styles from './history.module.css';
import type { Metadata } from 'next';
import ProviderBadge from '@/components/ProviderBadge';

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

type Filter = 'all' | 'running' | 'done' | 'failed';
type Sort = 'newest' | 'oldest' | 'score_desc' | 'score_asc';

const FILTER_LABELS: Record<Filter, string> = {
  all: 'All',
  running: 'Running',
  done: 'Passed',
  failed: 'Failed',
};

export default async function History({
  searchParams,
}: {
  searchParams: Promise<{ cursor?: string; filter?: string; sort?: string }>;
}) {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const params = await searchParams;
  const cursor = params.cursor;
  const filter = (['all', 'running', 'done', 'failed'].includes(params.filter ?? '') ? params.filter : 'all') as Filter;
  const sort = (['newest', 'oldest', 'score_desc', 'score_asc'].includes(params.sort ?? '') ? params.sort : 'newest') as Sort;

  const where = {
    userId: session.user.id,
    ...(filter !== 'all' ? { status: filter } : {}),
  };

  const orderBy = sort === 'oldest'     ? { createdAt: 'asc' as const }
                : sort === 'score_desc' ? [{ score: 'desc' as const }, { createdAt: 'desc' as const }]
                : sort === 'score_asc'  ? [{ score: 'asc' as const },  { createdAt: 'desc' as const }]
                :                        { createdAt: 'desc' as const };

  const [scans, totalScans] = await Promise.all([
    prisma.scan.findMany({
      where,
      orderBy,
      take: PAGE_SIZE + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      select: { id: true, repo: true, branch: true, status: true, score: true, grade: true, findings: true, createdAt: true, aiProvider: true },
    }),
    prisma.scan.count({ where: { userId: session.user.id } }),
  ]);

  const hasMore = scans.length > PAGE_SIZE;
  const displayScans = hasMore ? scans.slice(0, PAGE_SIZE) : scans;
  const nextCursor = hasMore ? displayScans[displayScans.length - 1].id : null;

  function filterHref(f: Filter) {
    const p = new URLSearchParams();
    if (f !== 'all') p.set('filter', f);
    if (sort !== 'newest') p.set('sort', sort);
    const s = p.toString();
    return `/app/history${s ? `?${s}` : ''}`;
  }

  function sortHref(s: Sort) {
    const p = new URLSearchParams();
    if (filter !== 'all') p.set('filter', filter);
    if (s !== 'newest') p.set('sort', s);
    const str = p.toString();
    return `/app/history${str ? `?${str}` : ''}`;
  }

  return (
    <div className={dashStyles.page}>
      <div className={dashStyles.header}>
        <div>
          <h1>Scan History</h1>
          <p className={dashStyles.subtitle}>{totalScans} scan{totalScans !== 1 ? 's' : ''} total</p>
        </div>
        <Link href="/app/scan" className="btn btn-primary">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          New Scan
        </Link>
      </div>

      {/* Filters + sort */}
      <div className={styles.toolbar}>
        <div className={styles.filterTabs}>
          {(['all', 'running', 'done', 'failed'] as Filter[]).map(f => (
            <Link
              key={f}
              href={filterHref(f)}
              className={`${styles.filterTab} ${filter === f ? styles.filterTabActive : ''}`}
            >
              {f === 'running' && (
                <span className={styles.runningDot} />
              )}
              {f === 'failed' && (
                <span className={styles.failedDot} />
              )}
              {f === 'done' && (
                <span className={styles.passedDot} />
              )}
              {FILTER_LABELS[f]}
            </Link>
          ))}
        </div>

        <div className={styles.sortRow}>
          <span className={styles.sortLabel}>Sort:</span>
          {([
            ['newest', 'Newest'],
            ['oldest', 'Oldest'],
            ['score_desc', 'Score ↓'],
            ['score_asc', 'Score ↑'],
          ] as [Sort, string][]).map(([s, label]) => (
            <Link
              key={s}
              href={sortHref(s)}
              className={`${styles.sortBtn} ${sort === s ? styles.sortBtnActive : ''}`}
            >
              {label}
            </Link>
          ))}
        </div>
      </div>

      {displayScans.length === 0 && !cursor ? (
        <div className={dashStyles.emptyState}>
          {filter === 'all'
            ? <><p>No scans yet.</p><Link href="/app/scan" className="btn btn-primary">Start first scan</Link></>
            : <p>No {FILTER_LABELS[filter].toLowerCase()} scans found.</p>
          }
        </div>
      ) : (
        <>
          <div className={dashStyles.scanList}>
            {displayScans.map(scan => (
              <Link key={scan.id} href={`/app/scans/${scan.id}`} className={dashStyles.scanRow}>
                <div className={dashStyles.scanLeft}>
                  <div className={dashStyles.repoIcon}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
                  </div>
                  <div>
                    <div className={dashStyles.repoName}>{scan.repo}</div>
                    <div className={dashStyles.repoBranch}>{scan.branch} · {timeAgo(scan.createdAt)}</div>
                  </div>
                </div>
                <div className={dashStyles.scanRight}>
                  {scan.status === 'running' ? (
                    <span className={dashStyles.runningBadge}>Running...</span>
                  ) : scan.status === 'failed' ? (
                    <span className={dashStyles.failedBadge}>Failed</span>
                  ) : (
                    <>
                      <span className={dashStyles.findingCount}>{scan.findings} findings</span>
                      <ProviderBadge provider={scan.aiProvider} />
                      {scan.score !== null && (
                        <div className={dashStyles.scoreChip} style={{ color: scoreColor(scan.score), borderColor: scoreColor(scan.score) + '40', background: scoreColor(scan.score) + '10' }}>
                          <span className={dashStyles.scoreGrade}>{scan.grade}</span>
                          <span className={dashStyles.scoreNum}>{scan.score}</span>
                        </div>
                      )}
                    </>
                  )}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={dashStyles.chevron}><path d="M9 18l6-6-6-6"/></svg>
                </div>
              </Link>
            ))}
          </div>

          <div className={styles.pagination}>
            {cursor ? (
              <Link href={`/app/history${filter !== 'all' ? `?filter=${filter}` : ''}`} className="btn btn-ghost" style={{ fontSize: '0.82rem' }}>
                ← First page
              </Link>
            ) : <span />}
            {nextCursor && (
              <Link
                href={`/app/history?cursor=${nextCursor}${filter !== 'all' ? `&filter=${filter}` : ''}${sort !== 'newest' ? `&sort=${sort}` : ''}`}
                className="btn btn-ghost"
                style={{ fontSize: '0.82rem' }}
              >
                Next page →
              </Link>
            )}
          </div>
        </>
      )}
    </div>
  );
}
