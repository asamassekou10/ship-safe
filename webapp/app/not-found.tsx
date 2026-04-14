import Link from 'next/link';

export default function NotFound() {
  return (
    <html lang="en">
      <body style={{ margin: 0, background: '#0a0a0a', color: '#e5e5e5', fontFamily: 'system-ui, sans-serif', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh' }}>
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div style={{ fontSize: '4rem', fontWeight: 700, color: '#3b82f6', lineHeight: 1 }}>404</div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 600, margin: '1rem 0 0.5rem' }}>Page not found</h1>
          <p style={{ color: '#6b7280', margin: '0 0 2rem' }}>The page you're looking for doesn't exist or has been moved.</p>
          <Link href="/app/scan" style={{ display: 'inline-block', padding: '0.625rem 1.25rem', background: '#3b82f6', color: '#fff', borderRadius: '0.375rem', textDecoration: 'none', fontSize: '0.9rem', fontWeight: 500 }}>
            Go to Dashboard
          </Link>
        </div>
      </body>
    </html>
  );
}
