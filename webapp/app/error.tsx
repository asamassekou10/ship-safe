'use client';

import { useEffect } from 'react';
import Link from 'next/link';

export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <html lang="en">
      <body style={{ margin: 0, background: '#0a0a0a', color: '#e5e5e5', fontFamily: 'system-ui, sans-serif', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh' }}>
        <div style={{ textAlign: 'center', padding: '2rem', maxWidth: '28rem' }}>
          <div style={{ fontSize: '4rem', fontWeight: 700, color: '#ef4444', lineHeight: 1 }}>500</div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 600, margin: '1rem 0 0.5rem' }}>Something went wrong</h1>
          <p style={{ color: '#6b7280', margin: '0 0 2rem', fontSize: '0.9rem' }}>
            An unexpected error occurred. Please try again or contact support if the problem persists.
          </p>
          <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <button
              onClick={reset}
              style={{ padding: '0.625rem 1.25rem', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '0.375rem', cursor: 'pointer', fontSize: '0.9rem', fontWeight: 500 }}
            >
              Try again
            </button>
            <Link href="/app/scan" style={{ display: 'inline-block', padding: '0.625rem 1.25rem', background: '#1f2937', color: '#e5e5e5', borderRadius: '0.375rem', textDecoration: 'none', fontSize: '0.9rem', fontWeight: 500 }}>
              Go to Dashboard
            </Link>
          </div>
        </div>
      </body>
    </html>
  );
}
