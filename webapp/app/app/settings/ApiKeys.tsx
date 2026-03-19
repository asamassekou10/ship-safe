'use client';
import { useEffect, useState } from 'react';

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
    if (!res.ok) { setError(data.error); return; }

    setRevealedKey(data.key);
    setNewKeyName('');
    // Refresh list
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
  }

  const cardStyle: React.CSSProperties = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '1rem 1.25rem' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
      {/* Create new key */}
      <div style={cardStyle}>
        <div style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem' }}>API Keys</div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Key name (e.g., CI/CD)"
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.55rem 0.85rem', color: 'var(--text)', fontSize: '0.85rem', fontFamily: 'var(--font-sans)', outline: 'none' }}
          />
          <button onClick={createKey} className="btn btn-primary" style={{ fontSize: '0.82rem', padding: '0.55rem 1rem' }}>
            Generate Key
          </button>
        </div>
        {error && <p style={{ color: 'var(--red)', fontSize: '0.82rem', marginTop: '0.5rem' }}>{error}</p>}
      </div>

      {/* Revealed key (one-time) */}
      {revealedKey && (
        <div style={{
          background: 'rgba(34,211,238,0.06)', border: '1px solid var(--cyan-dim)', borderRadius: '12px', padding: '1rem 1.25rem',
        }}>
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--cyan)', marginBottom: '0.5rem' }}>
            Copy your API key — it won&apos;t be shown again
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: '0.78rem', background: 'var(--bg)', padding: '0.6rem 0.85rem',
            borderRadius: '6px', wordBreak: 'break-all', cursor: 'pointer', border: '1px solid var(--border)',
          }}
            onClick={() => navigator.clipboard.writeText(revealedKey)}
            title="Click to copy"
          >
            {revealedKey}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '0.35rem' }}>
            Use as: <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>Authorization: Bearer {revealedKey.slice(0, 20)}...</code>
          </div>
        </div>
      )}

      {/* Key list */}
      {keys.length > 0 && (
        <div style={{ ...cardStyle, padding: 0, overflow: 'hidden' }}>
          {keys.map((key, i) => (
            <div key={key.id} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 1.25rem',
              borderBottom: i < keys.length - 1 ? '1px solid var(--border)' : 'none',
            }}>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{key.name}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                  {key.keyPrefix}...
                  {key.lastUsedAt && ` · Last used ${new Date(key.lastUsedAt).toLocaleDateString()}`}
                </div>
              </div>
              <button onClick={() => revokeKey(key.id)} style={{
                fontSize: '0.75rem', color: 'var(--red)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-sans)',
              }}>
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.6 }}>
        Use API keys to trigger scans from CI/CD or external tools.<br />
        <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--cyan)' }}>
          curl -X POST https://shipsafe.dev/api/v1/scans -H &quot;Authorization: Bearer sk_live_...&quot; -d &apos;{'{'}&#34;repo&#34;:&#34;owner/repo&#34;{'}'}&apos;
        </code>
      </div>
    </div>
  );
}
