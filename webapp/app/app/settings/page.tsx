import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from '../dashboard.module.css';
import s from './settings.module.css';
import type { Metadata } from 'next';
import UpgradeButton from './UpgradeButton';
import NotificationSettings from './NotificationSettings';
import ApiKeys from './ApiKeys';

export const metadata: Metadata = {
  title: 'Settings — Ship Safe',
};

export default async function Settings() {
  const session = await auth();
  if (!session?.user?.id) redirect('/login');

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { name: true, email: true, plan: true, image: true, createdAt: true },
  });

  if (!user) redirect('/login');

  const payments = await prisma.payment.findMany({
    where: { userId: session.user.id, status: 'paid' },
    orderBy: { createdAt: 'desc' },
    take: 5,
    select: { plan: true, amount: true, createdAt: true },
  });

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Settings</h1>
          <p className={styles.subtitle}>Manage your account and plan</p>
        </div>
      </div>

      {/* Profile */}
      <div className={styles.section}>
        <h2>Profile</h2>
        <div className={s.profileCard}>
          {user.image && (
            <img src={user.image} alt="" width={48} height={48} className={s.profileAvatar} />
          )}
          <div>
            <div className={s.profileName}>{user.name || 'User'}</div>
            <div className={s.profileEmail}>{user.email}</div>
            <div className={s.profileSince}>
              Member since {new Date(user.createdAt).toLocaleDateString()}
            </div>
          </div>
        </div>
      </div>

      {/* Plan */}
      <div className={styles.section}>
        <h2>Plan</h2>
        <div className={s.planCard}>
          <div>
            <div className={s.planName}>
              {user.plan.charAt(0).toUpperCase() + user.plan.slice(1)} Plan
            </div>
            <div className={s.planDesc}>
              {user.plan === 'free'
                ? '5 cloud scans per month · Public repos only'
                : user.plan === 'team'
                ? 'Unlimited scans · Private repos · Shared workspace · Webhooks'
                : 'Unlimited scans · Private repos · AI analysis · API access'}
            </div>
          </div>
        </div>
        {user.plan === 'free' && <UpgradeButton />}
      </div>

      {/* Payment history */}
      {payments.length > 0 && (
        <div className={styles.section}>
          <h2>Payment History</h2>
          <div className={s.paymentList}>
            {payments.map((p, i) => (
              <div key={i} className={s.paymentRow}>
                <span className={s.paymentPlan}>
                  {p.plan.charAt(0).toUpperCase() + p.plan.slice(1)} Plan
                </span>
                <span className={s.paymentAmount}>
                  ${(p.amount / 100).toFixed(2)}
                </span>
                <span className={s.paymentDate}>
                  {new Date(p.createdAt).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* Notifications */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>Notifications</h2>
        </div>
        <NotificationSettings />
      </div>

      {/* API Keys */}
      {user.plan !== 'free' && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <h2>API Keys</h2>
          </div>
          <ApiKeys />
        </div>
      )}
    </div>
  );
}
