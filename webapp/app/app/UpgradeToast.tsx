'use client';
import { useEffect, useState } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

export default function UpgradeToast() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const [plan, setPlan] = useState<string | null>(null);

  useEffect(() => {
    const upgraded = searchParams.get('upgraded');
    if (upgraded) {
      setPlan(upgraded);
      // Remove the query param without a full reload
      const params = new URLSearchParams(searchParams.toString());
      params.delete('upgraded');
      const newUrl = pathname + (params.size > 0 ? `?${params}` : '');
      router.replace(newUrl);
      // Auto-dismiss after 6s
      const t = setTimeout(() => setPlan(null), 6000);
      return () => clearTimeout(t);
    }
  }, [searchParams, router, pathname]);

  if (!plan) return null;

  const label = plan === 'team' ? 'Team' : 'Pro';

  return (
    <div style={{
      position: 'fixed',
      bottom: '1.5rem',
      right: '1.5rem',
      zIndex: 1000,
      background: 'var(--cyan)',
      color: '#fff',
      padding: '0.85rem 1.25rem',
      borderRadius: '12px',
      fontWeight: 600,
      fontSize: '0.9rem',
      boxShadow: '0 4px 24px rgba(8,145,178,0.35)',
      display: 'flex',
      alignItems: 'center',
      gap: '0.6rem',
      animation: 'slideUp 0.3s ease',
    }}>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
        <polyline points="22 4 12 14.01 9 11.01" />
      </svg>
      Welcome to Ship Safe {label}! Your plan is now active.
      <button
        onClick={() => setPlan(null)}
        style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer', opacity: 0.7, marginLeft: '0.25rem', fontSize: '1rem', lineHeight: 1 }}
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}
