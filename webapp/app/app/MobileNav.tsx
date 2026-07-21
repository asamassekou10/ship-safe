'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { signOut } from 'next-auth/react';
import styles from './app.layout.module.css';
import NavLinks from './NavLinks';
import ActivityInbox from './ActivityInbox';

interface Props {
  userName: string;
  userImage?: string | null;
  plan: string;
  isAdmin: boolean;
}

export default function MobileNav({ userName, userImage, plan, isAdmin }: Props) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();
  const close = () => setOpen(false);

  useEffect(() => {
    document.body.style.overflow = open ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [open]);

  useEffect(() => { close(); }, [pathname]);

  return (
    <>
      <header className={styles.mobileHeader}>
        <Link href="/" className={styles.logo}>
          <img src="/logo.png" alt="ship-safe" width={22} height={22} className={styles.logoImg} />
          <span>ship-safe</span>
        </Link>
        <div className={styles.mobileHeaderActions}>
          <ActivityInbox mobile />
          <button className={styles.hamburger} onClick={() => setOpen(value => !value)} aria-label={open ? 'Close menu' : 'Open menu'} aria-expanded={open}>
            {open
              ? <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 6 6 18M6 6l12 12"/></svg>
              : <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M3 6h18M3 12h18M3 18h18"/></svg>}
          </button>
        </div>
      </header>

      {open && <div className={styles.drawerOverlay} onClick={close} aria-hidden="true" />}

      <div className={`${styles.drawer} ${open ? styles.drawerOpen : ''}`}>
        <div className={styles.drawerNav}><NavLinks isAdmin={isAdmin} onNavigate={close} /></div>
        <div className={styles.sidebarBottom}>
          <div className={styles.planBadge}>
            {plan === 'free' ? (
              <><span className={styles.planName}>Free plan</span><Link href="/app/checkout?plan=pro" className={styles.upgradeCta} onClick={close}>View Pro plan</Link></>
            ) : (
              <><span className={styles.planName}>{plan.charAt(0).toUpperCase() + plan.slice(1)} plan</span><span className={styles.planScans}>Unlimited scans</span></>
            )}
          </div>
          <div className={styles.userRow}>
            {userImage && <img src={userImage} alt="" width={24} height={24} className={styles.avatar} />}
            <span className={styles.userName}>{userName}</span>
            <button onClick={() => signOut({ callbackUrl: '/' })} className={styles.mobileSignOut} title="Sign out" aria-label="Sign out">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
