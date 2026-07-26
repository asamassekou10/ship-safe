'use client';

import { useState } from 'react';
import styles from './ReengageBatch.module.css';

/**
 * One-time re-engagement send to the signup backlog. Idempotent server-side
 * (EmailEvent guards against re-sends), so re-running only reaches users who
 * haven't been re-engaged yet. Batched for deliverability on a fresh domain.
 */
export default function ReengageBatch({ eligible: initialEligible }: { eligible: number }) {
  const [eligible, setEligible] = useState(initialEligible);
  const [limit, setLimit] = useState(20);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState(false);

  async function send() {
    if (busy) return;
    if (!confirm(`Send the re-engagement email to up to ${limit} backlog user(s)? This sends real email.`)) return;
    setBusy(true);
    setMsg(null);
    setErr(false);
    try {
      const res = await fetch('/api/admin/reengage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
      setEligible(data.eligible ?? eligible);
      setMsg(`Sent ${data.sent} of ${data.scanned} scanned. ${data.eligible} still eligible.`);
    } catch (e) {
      setErr(true);
      setMsg(e instanceof Error ? e.message : 'Send failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <div>
          <h2>Re-engagement send</h2>
          <p className={styles.sub}>One-time email to the pre-lifecycle signup backlog.</p>
        </div>
        <span className={styles.badge}>{eligible} eligible</span>
      </div>

      <div className={styles.controls}>
        <label className={styles.limit}>
          Batch size
          <input
            type="number"
            min={1}
            max={50}
            value={limit}
            onChange={(e) => setLimit(Math.min(Math.max(Number(e.target.value) || 1, 1), 50))}
            disabled={busy}
          />
        </label>
        <button onClick={send} disabled={busy || eligible === 0} className={styles.button}>
          {busy ? 'Sending…' : eligible === 0 ? 'No one eligible' : `Send batch of ${Math.min(limit, eligible)}`}
        </button>
      </div>

      {msg && <p className={err ? styles.error : styles.ok}>{msg}</p>}
    </div>
  );
}
