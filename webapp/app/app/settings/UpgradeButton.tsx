'use client';
import { useState } from 'react';

export default function UpgradeButton() {
  const [loading, setLoading] = useState(false);

  async function handleUpgrade() {
    setLoading(true);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan: 'pro' }),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      }
    } catch {
      setLoading(false);
    }
  }

  return (
    <button className="btn btn-primary" onClick={handleUpgrade} disabled={loading}>
      {loading ? 'Redirecting...' : 'Upgrade to Pro — $9'}
    </button>
  );
}
