'use client';
import { signOut } from 'next-auth/react';

export default function SignOutButton() {
  return (
    <button
      onClick={() => signOut({ callbackUrl: '/' })}
      style={{
        background: 'none',
        border: 'none',
        color: 'var(--text-dim)',
        fontSize: '0.75rem',
        cursor: 'pointer',
        marginLeft: 'auto',
        padding: '0.2rem 0.4rem',
        borderRadius: '4px',
      }}
      title="Sign out"
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
        <polyline points="16 17 21 12 16 7" />
        <line x1="21" y1="12" x2="9" y2="12" />
      </svg>
    </button>
  );
}
