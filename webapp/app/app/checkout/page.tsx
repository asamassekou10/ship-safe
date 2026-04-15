import { auth } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { PLANS } from '@/lib/stripe';
import { plans } from '@/data/plans';
import { redirect } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import CheckoutButton from './CheckoutButton';
import styles from './checkout.module.css';

export default async function CheckoutPage({
  searchParams,
}: {
  searchParams: Promise<{ plan?: string }>;
}) {
  const session = await auth();
  if (!session?.user?.id || !session.user.email) {
    redirect('/login');
  }

  const { plan } = await searchParams;

  if (plan !== 'pro' && plan !== 'team') {
    redirect('/pricing');
  }

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { plan: true },
  });
  if (user?.plan === plan || user?.plan === 'team' || user?.plan === 'enterprise') {
    redirect('/app');
  }

  const planConfig = PLANS[plan];
  const planData = plans.find(p => p.name.toLowerCase() === plan)!;

  return (
    <div className={styles.page}>

      {/* ── Left — branding + features ── */}
      <div className={styles.left}>
        <Link href="/" className={styles.logo}>
          <Image src="/logo.png" alt="Ship Safe" width={32} height={32} className={styles.logoImg} />
          <span className={styles.logoName}>Ship Safe</span>
        </Link>

        <div className={styles.planBadge}>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
          </svg>
          {planData.name} Plan
        </div>

        <h1 className={styles.planName}>{planData.name}</h1>
        <p className={styles.planPrice}>{planData.price}{planData.period}</p>
        <p className={styles.planDesc}>{planData.desc}</p>

        <ul className={styles.featureList}>
          {planData.features.map(f => (
            <li key={f} className={styles.featureItem}>
              <svg className={styles.checkIcon} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="20 6 9 17 4 12" />
              </svg>
              {f}
            </li>
          ))}
        </ul>

        <p className={styles.guarantee}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          30-day money-back guarantee · Cancel anytime
        </p>
      </div>

      {/* ── Right — order summary ── */}
      <div className={styles.right}>
        <div className={styles.orderCard}>
          <h2 className={styles.orderTitle}>Order summary</h2>

          <div>
            <div className={styles.orderRow}>
              <span className={styles.orderLabel}>Ship Safe {planData.name}</span>
              <span className={styles.orderValue}>{planData.price}{planData.period}</span>
            </div>
          </div>

          <hr className={styles.divider} />

          <div className={styles.totalRow}>
            <span className={styles.totalLabel}>Due today</span>
            <span className={styles.totalValue}>{planData.price}</span>
          </div>

          <CheckoutButton plan={plan} />

          <p className={styles.secureBadge}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            Secured by Stripe · Cancel anytime
          </p>

          <Link href="/pricing" className={styles.backLink}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M19 12H5M12 5l-7 7 7 7" />
            </svg>
            Back to pricing
          </Link>
        </div>
      </div>

    </div>
  );
}
