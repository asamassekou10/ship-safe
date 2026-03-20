'use client';
import { useState } from 'react';
import s from './settings.module.css';

type Plan = 'pro' | 'team';

const PLAN_INFO = {
  pro:  { label: 'Pro',  price: '$9',  desc: 'Unlimited scans · Private repos · AI analysis · API access' },
  team: { label: 'Team', price: '$19', desc: 'Everything in Pro · Shared workspace · Role-based access · Webhooks' },
} as const;

export default function UpgradeButton() {
  const [loading, setLoading] = useState<Plan | null>(null);
  const [error, setError] = useState('');

  async function handleUpgrade(plan: Plan) {
    setError('');
    setLoading(plan);
    try {
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Something went wrong. Please try again.');
        setLoading(null);
        return;
      }
      if (data.url) {
        window.location.href = data.url;
      }
    } catch {
      setError('Network error. Please try again.');
      setLoading(null);
    }
  }

  return (
    <div className={s.planOptions}>
      {(['pro', 'team'] as Plan[]).map(plan => (
        <div key={plan} className={s.planOption}>
          <div className={s.planOptionHeader}>
            <span className={s.planOptionName}>{PLAN_INFO[plan].label}</span>
            <span className={s.planOptionPrice}>{PLAN_INFO[plan].price} <span className={s.planOptionOnce}>one-time</span></span>
          </div>
          <p className={s.planOptionDesc}>{PLAN_INFO[plan].desc}</p>
          <button
            className="btn btn-primary"
            onClick={() => handleUpgrade(plan)}
            disabled={loading !== null}
            style={{ width: '100%', marginTop: '0.5rem' }}
          >
            {loading === plan ? 'Redirecting...' : `Upgrade to ${PLAN_INFO[plan].label}`}
          </button>
        </div>
      ))}
      {error && <p className={s.error}>{error}</p>}
    </div>
  );
}
