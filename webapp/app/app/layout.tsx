import Link from 'next/link';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from './app.layout.module.css';
import type { Metadata } from 'next';
import SignOutButton from './SignOutButton';

export const metadata: Metadata = {
  title: 'Dashboard — Ship Safe',
};

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  if (!session?.user) redirect('/login');

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { plan: true },
  });

  const plan = user?.plan ?? 'free';

  // Count scans this month for free users
  let scanCount = 0;
  if (plan === 'free') {
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    scanCount = await prisma.scan.count({
      where: { userId: session.user.id!, createdAt: { gte: monthStart } },
    });
  }

  return (
    <div className={styles.shell}>
      <aside className={styles.sidebar}>
        <div className={styles.sidebarTop}>
          <Link href="/" className={styles.logo}>
            <img src="/logo.png" alt="ship-safe" width={24} height={24} className={styles.logoImg} />
            <span>ship-safe</span>
          </Link>
        </div>

        <nav className={styles.nav}>
          <Link href="/app" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>
            Dashboard
          </Link>
          <Link href="/app/scan" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg>
            New Scan
          </Link>
          <Link href="/app/repos" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" /></svg>
            Repos
          </Link>
          <Link href="/app/guardian" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" /></svg>
            PR Guardian
          </Link>
          <Link href="/app/history" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
            History
          </Link>
          <Link href="/app/team" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>
            Team
          </Link>
          <Link href="/app/policies" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            Policies
          </Link>
          <Link href="/app/settings" className={styles.navItem}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>
            Settings
          </Link>
        </nav>

        <div className={styles.sidebarBottom}>
          {plan === 'free' ? (
            <div className={styles.planBadge}>
              <span className={styles.planName}>Free Plan</span>
              <span className={styles.planScans}>{scanCount} / 5 scans used</span>
              <div className={styles.planBar}>
                <div className={styles.planBarFill} style={{ width: `${Math.min((scanCount / 5) * 100, 100)}%` }} />
              </div>
              <Link href="/pricing" className={styles.upgradeCta}>Upgrade to Pro →</Link>
            </div>
          ) : (
            <div className={styles.planBadge}>
              <span className={styles.planName}>{plan.charAt(0).toUpperCase() + plan.slice(1)} Plan</span>
              <span className={styles.planScans}>Unlimited scans</span>
            </div>
          )}
          <div className={styles.userRow}>
            {session.user.image && (
              <img src={session.user.image} alt="" width={24} height={24} className={styles.avatar} />
            )}
            <span className={styles.userName}>{session.user.name || session.user.email}</span>
            <SignOutButton />
          </div>
        </div>
      </aside>

      <main className={styles.main}>
        {children}
      </main>
    </div>
  );
}
