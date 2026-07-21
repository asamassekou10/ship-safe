import { redirect } from 'next/navigation';
import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import type { Metadata } from 'next';
import GoalPicker from './GoalPicker';
import styles from './page.module.css';

export const metadata: Metadata = { title: 'Get Started — Ship Safe' };

export default async function OnboardingPage() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const [user, scanCount] = await Promise.all([
    prisma.user.findUnique({
      where: { id: session.user.id },
      select: { onboardingCompleted: true },
    }),
    prisma.scan.count({ where: { userId: session.user.id }, take: 1 }),
  ]);
  if (user?.onboardingCompleted || scanCount > 0) redirect('/app');

  const firstName = session.user.name?.split(' ')[0] ?? null;

  return (
    <main className={styles.page}>
      <div className={styles.frame}>
        <div className={styles.brand}>
          <img src="/logo.png" alt="" width={34} height={34} />
          <span>ship-safe</span>
        </div>

        <header className={styles.header}>
          <span className={styles.eyebrow}>Set up your workspace</span>
          <h1>{firstName ? `${firstName}, what do you want to secure first?` : 'What do you want to secure first?'}</h1>
          <p>Choose a starting point. You can use every workflow later.</p>
        </header>

        <GoalPicker />

        <p className={styles.privacy}>Your first scan uses recommended settings. Advanced controls remain available when you need them.</p>
      </div>
    </main>
  );
}
