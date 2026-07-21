'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState } from 'react';
import styles from './app.layout.module.css';

interface ActivityItem {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  title: string;
  detail: string;
  href: string;
  createdAt: string;
}

function relativeTime(value: string) {
  const seconds = Math.max(1, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return 'now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export default function ActivityInbox({ mobile = false }: { mobile?: boolean }) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/activity');
      if (!response.ok) return;
      const data = await response.json();
      setItems(data.items ?? []);
      setUnreadCount(data.unreadCount ?? 0);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  async function markRead() {
    setUnreadCount(0);
    await fetch('/api/activity', { method: 'POST' });
  }

  return (
    <div className={`${styles.activityRoot} ${mobile ? styles.activityRootMobile : ''}`} ref={rootRef}>
      <button
        type="button"
        className={styles.activityButton}
        aria-label={`Activity${unreadCount ? `, ${unreadCount} unread` : ''}`}
        aria-expanded={open}
        onClick={() => setOpen(value => !value)}
      >
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
          <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" />
          <path d="M10 21h4" />
        </svg>
        {unreadCount > 0 && <span className={styles.activityBadge}>{Math.min(unreadCount, 9)}{unreadCount > 9 ? '+' : ''}</span>}
      </button>

      {open && (
        <div className={styles.activityPanel} role="dialog" aria-label="Recent activity">
          <div className={styles.activityHeader}>
            <div>
              <strong>Activity</strong>
              <span>{unreadCount ? `${unreadCount} need attention` : 'You are up to date'}</span>
            </div>
            {unreadCount > 0 && <button type="button" onClick={markRead}>Mark read</button>}
          </div>
          <div className={styles.activityList}>
            {loading && items.length === 0 ? (
              <div className={styles.activityEmpty}>Loading activity…</div>
            ) : items.length === 0 ? (
              <div className={styles.activityEmpty}>No security activity yet.</div>
            ) : items.map(item => (
              <Link key={item.id} href={item.href} className={styles.activityItem} onClick={() => setOpen(false)}>
                <span className={`${styles.activityDot} ${styles[`activityDot_${item.severity}`]}`} />
                <span className={styles.activityCopy}>
                  <strong>{item.title}</strong>
                  <span>{item.detail}</span>
                </span>
                <time>{relativeTime(item.createdAt)}</time>
              </Link>
            ))}
          </div>
          <Link href="/app/findings" className={styles.activityFooter} onClick={() => setOpen(false)}>
            Open findings inbox
            <span aria-hidden="true">→</span>
          </Link>
        </div>
      )}
    </div>
  );
}
