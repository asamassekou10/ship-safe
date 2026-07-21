import Link from 'next/link';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import { headers } from 'next/headers';
import styles from './app.layout.module.css';
import type { Metadata } from 'next';
import SignOutButton from './SignOutButton';
import MobileNav from './MobileNav';
import NavLinks from './NavLinks';
import { ToastProvider } from './Toast';
import KeyboardShortcuts from './KeyboardShortcuts';
import ActivityInbox from './ActivityInbox';

export const metadata: Metadata = {
  title: 'Dashboard — Ship Safe',
};

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const requestHeaders = await headers();
  const pathname = requestHeaders.get('x-ship-safe-pathname');
  const session = await auth();
  if (!session?.user && pathname === '/app/guide') {
    return (
      <main className={styles.publicMain}>
        {children}
      </main>
    );
  }

  if (!session?.user) redirect('/login');

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { plan: true },
  });

  const plan = user?.plan ?? 'free';
  const adminEmails = (process.env.ADMIN_EMAILS ?? '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
  const isAdmin = adminEmails.includes((session.user.email ?? '').toLowerCase());

  return (
    <div className={styles.shell}>
      <MobileNav
        userName={session.user.name || session.user.email || ''}
        userImage={session.user.image}
        plan={plan}
        isAdmin={isAdmin}
      />
      <aside className={styles.sidebar}>
        <div className={styles.sidebarTop}>
          <Link href="/" className={styles.logo}>
            <img src="/logo.png" alt="ship-safe" width={24} height={24} className={styles.logoImg} />
            <span>ship-safe</span>
          </Link>
          <ActivityInbox />
        </div>

        <NavLinks isAdmin={isAdmin} />

        <div className={styles.sidebarBottom}>
          {plan === 'free' ? (
            <div className={styles.planBadge}>
              <span className={styles.planName}>Free plan</span>
              <Link href="/app/checkout?plan=pro" className={styles.upgradeCta}>View Pro plan</Link>
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
        <ToastProvider>
          {children}
        </ToastProvider>
      </main>
      <KeyboardShortcuts />
    </div>
  );
}
