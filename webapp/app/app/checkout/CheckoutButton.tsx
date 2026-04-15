'use client';

import { useState } from 'react';
import styles from './checkout.module.css';

export default function CheckoutButton({ plan }: { plan: 'pro' | 'team' }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCheckout() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan }),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        setError('Could not create checkout session. Please try again.');
        setLoading(false);
      }
    } catch {
      setError('Something went wrong. Please try again.');
      setLoading(false);
    }
  }

  return (
    <div className={styles.buttonWrap}>
      <button
        className="btn btn-primary"
        onClick={handleCheckout}
        disabled={loading}
        style={{ width: '100%', justifyContent: 'center' }}
      >
        {loading ? 'Redirecting to payment…' : 'Continue to payment →'}
      </button>
      {error && <p className={styles.errorMsg}>{error}</p>}
    </div>
  );
}
