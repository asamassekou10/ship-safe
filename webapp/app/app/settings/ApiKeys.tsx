'use client';
import { useEffect, useState } from 'react';
import s from './settings.module.css';
import { useToast } from '@/app/app/Toast';

interface ApiKeyInfo {
  id: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  createdAt: string;
}

export default function ApiKeys() {
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [error, setError] = useState('');
  const { toast } = useToast();

  useEffect(() => {
    fetch('/api/v1/key').then(r => r.json()).then(d => setKeys(d.keys || []));
  }, []);

  async function createKey() {
    setError('');
    setRevealedKey(null);
    const res = await fetch('/api/v1/key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: newKeyName || 'Default' }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); toast(data.error || 'Failed to create key', 'error'); return; }

    setRevealedKey(data.key);
    setNewKeyName('');
    const r = await fetch('/api/v1/key');
    const d = await r.json();
    setKeys(d.keys || []);
  }

  async function revokeKey(id: string) {
    await fetch('/api/v1/key', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    setKeys(prev => prev.filter(k => k.id !== id));
    toast('API key revoked', 'info');
  }

  return (
    <div className={s.settingsGroup}>
      {/* Create new key */}
      <div className={s.settingsCard}>
        <div className={s.settingsCardTitle}>API Keys</div>
        <div className={s.settingsInputRow}>
          <input
            type="text"
            placeholder="Key name (e.g., CI/CD)"
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            className={s.settingsInput}
          />
          <button onClick={createKey} className="btn btn-primary" style={{ fontSize: '0.82rem', padding: '0.55rem 1rem' }}>
            Generate Key
          </button>
        </div>
        {error && <p className={s.error}>{error}</p>}
      </div>

      {/* Revealed key (one-time) */}
      {revealedKey && (
        <div className={s.keyReveal}>
          <div className={s.keyRevealTitle}>
            Copy your API key — it won&apos;t be shown again
          </div>
          <div
            className={s.keyRevealCode}
            onClick={() => { navigator.clipboard.writeText(revealedKey); toast('Key copied to clipboard', 'success'); }}
            title="Click to copy"
          >
            {revealedKey}
          </div>
          <div className={s.keyRevealHint}>
            Use as: <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>Authorization: Bearer {revealedKey.slice(0, 20)}...</code>
          </div>
        </div>
      )}

      {/* Key list */}
      {keys.length > 0 && (
        <div className={s.settingsCard} style={{ padding: 0, overflow: 'hidden' }}>
          {keys.map((key) => (
            <div key={key.id} className={s.keyRow}>
              <div>
                <div className={s.keyName}>{key.name}</div>
                <div className={s.keyPrefix}>
                  {key.keyPrefix}...
                  {key.lastUsedAt && ` · Last used ${new Date(key.lastUsedAt).toLocaleDateString()}`}
                </div>
              </div>
              <button onClick={() => revokeKey(key.id)} className={s.revokeBtn}>
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      <div className={s.apiTip}>
        Use API keys to trigger scans from CI/CD or external tools.<br />
        <code>
          curl -X POST https://www.shipsafecli.com/api/v1/scans -H &quot;Authorization: Bearer sk_live_...&quot; -d &apos;{'{'}&#34;repo&#34;:&#34;owner/repo&#34;{'}'}&apos;
        </code>
      </div>
    </div>
  );
}
