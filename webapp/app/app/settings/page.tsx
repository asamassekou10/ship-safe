import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { redirect } from 'next/navigation';
import styles from '../dashboard.module.css';
import type { Metadata } from 'next';
import UpgradeButton from './UpgradeButton';

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
        <div style={{
          display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '1rem',
          padding: '1.25rem', borderRadius: '12px',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
        }}>
          {user.image && (
            <img src={user.image} alt="" width={48} height={48} style={{ borderRadius: '50%' }} />
          )}
          <div>
            <div style={{ fontWeight: 600, fontSize: '1rem' }}>{user.name || 'User'}</div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{user.email}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.25rem' }}>
              Member since {new Date(user.createdAt).toLocaleDateString()}
            </div>
          </div>
        </div>
      </div>

      {/* Plan */}
      <div className={styles.section}>
        <h2>Plan</h2>
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem',
          marginTop: '1rem', padding: '1.25rem', borderRadius: '12px',
          background: 'var(--bg-card)', border: '1px solid var(--border)', flexWrap: 'wrap',
        }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>
              {user.plan.charAt(0).toUpperCase() + user.plan.slice(1)} Plan
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              {user.plan === 'free'
                ? '5 cloud scans per month · Public repos'
                : 'Unlimited cloud scans · Private repos · AI analysis'}
            </div>
          </div>
          {user.plan === 'free' && <UpgradeButton />}
        </div>
      </div>

      {/* Payment history */}
      {payments.length > 0 && (
        <div className={styles.section}>
          <h2>Payment History</h2>
          <div style={{
            marginTop: '1rem', borderRadius: '12px', overflow: 'hidden',
            border: '1px solid var(--border)',
          }}>
            {payments.map((p, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between', padding: '0.85rem 1.25rem',
                borderBottom: i < payments.length - 1 ? '1px solid var(--border)' : 'none',
                background: 'var(--bg-card)',
              }}>
                <span style={{ fontSize: '0.88rem' }}>
                  {p.plan.charAt(0).toUpperCase() + p.plan.slice(1)} Plan
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--green)' }}>
                  ${(p.amount / 100).toFixed(2)}
                </span>
                <span style={{ fontSize: '0.82rem', color: 'var(--text-dim)' }}>
                  {new Date(p.createdAt).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
