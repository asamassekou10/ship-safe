import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from './admin.module.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Admin — Ship Safe',
};

function isAdmin(email: string | null | undefined): boolean {
  if (!email) return false;
  const admins = (process.env.ADMIN_EMAILS ?? '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
  return admins.includes(email.toLowerCase());
}

function timeAgo(date: Date) {
  const diff = Date.now() - new Date(date).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function usd(cents: number) {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(cents / 100);
}

export default async function AdminPage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');
  if (!isAdmin(session.user.email)) redirect('/app');

  const now = new Date();
  const days7ago = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const days30ago = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const days14ago = new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000);

  const [
    totalUsers,
    newUsers7d,
    newUsers30d,
    usersByPlan,
    totalScans,
    scans7d,
    scans30d,
    totalRevenue,
    revenue30d,
    recentUsers,
    scansPerDay,
    signupsPerDay,
    signinsPerDay,
    authProviders,
    activeUsers30d,
    signins7d,
    signins30d,
    recentSignins,
  ] = await Promise.all([
    prisma.user.count(),
    prisma.user.count({ where: { createdAt: { gte: days7ago } } }),
    prisma.user.count({ where: { createdAt: { gte: days30ago } } }),
    prisma.user.groupBy({ by: ['plan'], _count: { id: true } }),
    prisma.scan.count(),
    prisma.scan.count({ where: { createdAt: { gte: days7ago } } }),
    prisma.scan.count({ where: { createdAt: { gte: days30ago } } }),
    prisma.payment.aggregate({ where: { status: 'paid' }, _sum: { amount: true } }),
    prisma.payment.aggregate({ where: { status: 'paid', createdAt: { gte: days30ago } }, _sum: { amount: true } }),
    prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
      take: 10,
      select: { id: true, name: true, email: true, image: true, plan: true, createdAt: true },
    }),
    // Scans per day — last 14 days
    prisma.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT DATE_TRUNC('day', "createdAt") AS day, COUNT(*) AS count
      FROM "Scan"
      WHERE "createdAt" >= ${days14ago}
      GROUP BY day ORDER BY day
    `,
    // Signups per day — last 14 days
    prisma.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT DATE_TRUNC('day', "createdAt") AS day, COUNT(*) AS count
      FROM "User"
      WHERE "createdAt" >= ${days14ago}
      GROUP BY day ORDER BY day
    `,
    // Sign-ins per day from AuditLog — last 14 days
    prisma.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT DATE_TRUNC('day', "createdAt") AS day, COUNT(*) AS count
      FROM "AuditLog"
      WHERE action = 'auth.signin' AND "createdAt" >= ${days14ago}
      GROUP BY day ORDER BY day
    `,
    // Auth providers breakdown
    prisma.account.groupBy({ by: ['provider'], _count: { id: true } }),
    // Active users: ran at least one scan in last 30d
    prisma.scan.findMany({
      where: { createdAt: { gte: days30ago } },
      distinct: ['userId'],
      select: { userId: true },
    }),
    // Sign-in counts from AuditLog
    prisma.auditLog.count({ where: { action: 'auth.signin', createdAt: { gte: days7ago } } }),
    prisma.auditLog.count({ where: { action: 'auth.signin', createdAt: { gte: days30ago } } }),
    // Recent sign-ins with user info
    prisma.auditLog.findMany({
      where: { action: 'auth.signin' },
      orderBy: { createdAt: 'desc' },
      take: 10,
      select: {
        id: true,
        createdAt: true,
        meta: true,
        user: { select: { name: true, email: true, image: true, plan: true } },
      },
    }),
  ]);

  const paidRevenue = totalRevenue._sum.amount ?? 0;
  const paidRevenue30d = revenue30d._sum.amount ?? 0;
  const activeUserCount = activeUsers30d.length;

  // Build day-by-day maps for charts (last 14 days)
  const last14Days: string[] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    last14Days.push(d.toISOString().slice(0, 10));
  }

  const scansByDay: Record<string, number> = {};
  const signupsByDay: Record<string, number> = {};
  const signinsByDay: Record<string, number> = {};
  last14Days.forEach(d => { scansByDay[d] = 0; signupsByDay[d] = 0; signinsByDay[d] = 0; });

  scansPerDay.forEach(row => {
    const key = new Date(row.day).toISOString().slice(0, 10);
    if (key in scansByDay) scansByDay[key] = Number(row.count);
  });
  signupsPerDay.forEach(row => {
    const key = new Date(row.day).toISOString().slice(0, 10);
    if (key in signupsByDay) signupsByDay[key] = Number(row.count);
  });
  signinsPerDay.forEach(row => {
    const key = new Date(row.day).toISOString().slice(0, 10);
    if (key in signinsByDay) signinsByDay[key] = Number(row.count);
  });

  const maxScans = Math.max(...Object.values(scansByDay), 1);
  const maxSignups = Math.max(...Object.values(signupsByDay), 1);
  const maxSignins = Math.max(...Object.values(signinsByDay), 1);

  const planOrder = ['free', 'pro', 'team', 'enterprise'];
  const planColors: Record<string, string> = {
    free: 'var(--text-dim)',
    pro: 'var(--cyan)',
    team: 'var(--green)',
    enterprise: 'var(--yellow)',
  };
  const planMap: Record<string, number> = {};
  usersByPlan.forEach(row => { planMap[row.plan] = row._count.id; });

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Admin</h1>
          <p className={styles.subtitle}>Platform overview — internal use only</p>
        </div>
      </div>

      {/* Top stats */}
      <div className={styles.statsRow}>
        {[
          { label: 'Total Users', value: String(totalUsers), color: 'var(--cyan)' },
          { label: 'New (7d)', value: `+${newUsers7d}`, color: 'var(--green)' },
          { label: 'Sign-ins (7d)', value: String(signins7d), color: 'var(--yellow)' },
          { label: 'Active (30d)', value: String(activeUserCount), color: 'var(--cyan)' },
          { label: 'Scans (7d)', value: String(scans7d), color: 'var(--green)' },
          { label: 'Revenue', value: usd(paidRevenue), color: 'var(--green)' },
        ].map(s => (
          <div key={s.label} className={styles.statCard}>
            <span className={styles.statValue} style={{ color: s.color }}>{s.value}</span>
            <span className={styles.statLabel}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className={styles.threeCol}>
        {/* Sign-ins per day */}
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2>Sign-ins — 14d</h2>
            <span className={styles.dimBadge}>{signins30d} this month</span>
          </div>
          <div className={styles.chartCard}>
            <div className={styles.barChart}>
              {last14Days.map(day => {
                const count = signinsByDay[day] ?? 0;
                const pct = Math.max((count / maxSignins) * 100, count > 0 ? 4 : 0);
                return (
                  <div key={day} className={styles.barCol}>
                    <span className={styles.barLabel}>{count > 0 ? count : ''}</span>
                    <div className={styles.barTrack}>
                      <div className={styles.barFill} style={{ height: `${pct}%`, background: 'var(--yellow)' }} />
                    </div>
                    <span className={styles.barDate}>{new Date(day + 'T12:00:00Z').toLocaleDateString('en-US', { month: 'numeric', day: 'numeric' })}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Signups per day */}
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2>Signups — 14d</h2>
            <span className={styles.dimBadge}>+{newUsers30d} this month</span>
          </div>
          <div className={styles.chartCard}>
            <div className={styles.barChart}>
              {last14Days.map(day => {
                const count = signupsByDay[day] ?? 0;
                const pct = Math.max((count / maxSignups) * 100, count > 0 ? 4 : 0);
                return (
                  <div key={day} className={styles.barCol}>
                    <span className={styles.barLabel}>{count > 0 ? count : ''}</span>
                    <div className={styles.barTrack}>
                      <div className={styles.barFill} style={{ height: `${pct}%`, background: 'var(--cyan)' }} />
                    </div>
                    <span className={styles.barDate}>{new Date(day + 'T12:00:00Z').toLocaleDateString('en-US', { month: 'numeric', day: 'numeric' })}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Scans per day */}
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2>Scans — 14d</h2>
            <span className={styles.dimBadge}>{scans30d} this month</span>
          </div>
          <div className={styles.chartCard}>
            <div className={styles.barChart}>
              {last14Days.map(day => {
                const count = scansByDay[day] ?? 0;
                const pct = Math.max((count / maxScans) * 100, count > 0 ? 4 : 0);
                return (
                  <div key={day} className={styles.barCol}>
                    <span className={styles.barLabel}>{count > 0 ? count : ''}</span>
                    <div className={styles.barTrack}>
                      <div className={styles.barFill} style={{ height: `${pct}%`, background: 'var(--green)' }} />
                    </div>
                    <span className={styles.barDate}>{new Date(day + 'T12:00:00Z').toLocaleDateString('en-US', { month: 'numeric', day: 'numeric' })}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      <div className={styles.twoCol}>
        {/* Users by plan */}
        <div className={styles.section}>
          <div className={styles.sectionHeader}><h2>Users by plan</h2></div>
          <div className={styles.card}>
            {planOrder.map(plan => {
              const count = planMap[plan] ?? 0;
              const pct = totalUsers > 0 ? Math.round((count / totalUsers) * 100) : 0;
              return (
                <div key={plan} className={styles.planRow}>
                  <div className={styles.planLeft}>
                    <span className={styles.planDot} style={{ background: planColors[plan] }} />
                    <span className={styles.planName}>{plan.charAt(0).toUpperCase() + plan.slice(1)}</span>
                  </div>
                  <div className={styles.planBar}>
                    <div className={styles.planBarFill} style={{ width: `${pct}%`, background: planColors[plan] + '60' }} />
                  </div>
                  <span className={styles.planCount}>{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Auth providers + Revenue */}
        <div className={styles.section}>
          <div className={styles.sectionHeader}><h2>Auth providers</h2></div>
          <div className={styles.card}>
            {authProviders.map(row => (
              <div key={row.provider} className={styles.planRow}>
                <div className={styles.planLeft}>
                  <span className={styles.planName} style={{ textTransform: 'capitalize' }}>{row.provider}</span>
                </div>
                <span className={styles.planCount}>{row._count.id}</span>
              </div>
            ))}
          </div>

          <div className={styles.sectionHeader} style={{ marginTop: '1rem' }}><h2>Revenue</h2></div>
          <div className={styles.card}>
            {[
              { label: 'All time', value: usd(paidRevenue) },
              { label: 'Last 30 days', value: usd(paidRevenue30d) },
            ].map(row => (
              <div key={row.label} className={styles.planRow}>
                <span className={styles.planName}>{row.label}</span>
                <span className={styles.planCount} style={{ color: 'var(--green)' }}>{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent sign-ins */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}><h2>Recent sign-ins</h2></div>
        {recentSignins.length === 0 ? (
          <div className={styles.emptyNote}>No sign-ins recorded yet — they will appear here after the next login.</div>
        ) : (
          <div className={styles.tableCard}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Email</th>
                  <th>Provider</th>
                  <th>Plan</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {recentSignins.map(log => {
                  const provider = (log.meta as Record<string, string> | null)?.provider ?? '—';
                  const u = log.user;
                  const plan = u?.plan ?? 'free';
                  return (
                    <tr key={log.id}>
                      <td>
                        <div className={styles.userCell}>
                          {u?.image && <img src={u.image} alt="" width={24} height={24} className={styles.avatar} />}
                          <span>{u?.name ?? '—'}</span>
                        </div>
                      </td>
                      <td className={styles.emailCell}>{u?.email ?? '—'}</td>
                      <td className={styles.emailCell} style={{ textTransform: 'capitalize' }}>{provider}</td>
                      <td>
                        <span className={styles.planChip} style={{ color: planColors[plan] ?? 'var(--text-dim)', borderColor: (planColors[plan] ?? 'var(--text-dim)') + '50' }}>
                          {plan}
                        </span>
                      </td>
                      <td className={styles.timeCell}>{timeAgo(log.createdAt)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Recent signups */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}><h2>Recent signups</h2></div>
        <div className={styles.tableCard}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>User</th>
                <th>Email</th>
                <th>Plan</th>
                <th>Joined</th>
              </tr>
            </thead>
            <tbody>
              {recentUsers.map(u => (
                <tr key={u.id}>
                  <td>
                    <div className={styles.userCell}>
                      {u.image && <img src={u.image} alt="" width={24} height={24} className={styles.avatar} />}
                      <span>{u.name ?? '—'}</span>
                    </div>
                  </td>
                  <td className={styles.emailCell}>{u.email}</td>
                  <td>
                    <span className={styles.planChip} style={{ color: planColors[u.plan], borderColor: planColors[u.plan] + '50' }}>
                      {u.plan}
                    </span>
                  </td>
                  <td className={styles.timeCell}>{timeAgo(u.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
