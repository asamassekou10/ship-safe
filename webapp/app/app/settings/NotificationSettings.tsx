'use client';
import { useEffect, useState } from 'react';

interface Settings {
  emailOnComplete: boolean;
  emailOnCritical: boolean;
  emailDigest: string;
  slackWebhookUrl: string | null;
  slackOnComplete: boolean;
  slackOnCritical: boolean;
}

export default function NotificationSettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    fetch('/api/notifications').then(r => r.json()).then(setSettings);
  }, []);

  async function save(updates: Partial<Settings>) {
    setSaving(true);
    setSaved(false);
    const res = await fetch('/api/notifications', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    const data = await res.json();
    setSettings(data);
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  if (!settings) return <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>Loading...</p>;

  const cardStyle: React.CSSProperties = { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '1rem 1.25rem' };
  const rowStyle: React.CSSProperties = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0' };
  const labelStyle: React.CSSProperties = { fontSize: '0.85rem', fontWeight: 500 };
  const descStyle: React.CSSProperties = { fontSize: '0.75rem', color: 'var(--text-dim)' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem' }}>
      <div style={cardStyle}>
        <div style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.5rem' }}>Email Notifications</div>
        <div style={rowStyle}>
          <div><span style={labelStyle}>Scan complete</span><br /><span style={descStyle}>Email when a scan finishes</span></div>
          <input type="checkbox" checked={settings.emailOnComplete} onChange={e => save({ emailOnComplete: e.target.checked })} style={{ accentColor: 'var(--cyan)' }} />
        </div>
        <div style={rowStyle}>
          <div><span style={labelStyle}>Critical findings</span><br /><span style={descStyle}>Email when critical issues are found</span></div>
          <input type="checkbox" checked={settings.emailOnCritical} onChange={e => save({ emailOnCritical: e.target.checked })} style={{ accentColor: 'var(--cyan)' }} />
        </div>
        <div style={rowStyle}>
          <div><span style={labelStyle}>Weekly digest</span><br /><span style={descStyle}>Summary of scan activity</span></div>
          <select value={settings.emailDigest} onChange={e => save({ emailDigest: e.target.value })}
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.35rem 0.6rem', color: 'var(--text)', fontSize: '0.82rem', fontFamily: 'var(--font-sans)' }}>
            <option value="off">Off</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.5rem' }}>Slack Integration</div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem' }}>
          <input
            type="url"
            placeholder="https://hooks.slack.com/services/..."
            value={settings.slackWebhookUrl || ''}
            onChange={e => setSettings(prev => prev ? { ...prev, slackWebhookUrl: e.target.value } : prev)}
            onBlur={e => save({ slackWebhookUrl: e.target.value || null })}
            style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.55rem 0.85rem', color: 'var(--text)', fontSize: '0.85rem', fontFamily: 'var(--font-sans)', outline: 'none' }}
          />
        </div>
        <div style={rowStyle}>
          <div><span style={labelStyle}>Post on scan complete</span></div>
          <input type="checkbox" checked={settings.slackOnComplete} onChange={e => save({ slackOnComplete: e.target.checked })} style={{ accentColor: 'var(--cyan)' }} />
        </div>
        <div style={rowStyle}>
          <div><span style={labelStyle}>Post on critical findings</span></div>
          <input type="checkbox" checked={settings.slackOnCritical} onChange={e => save({ slackOnCritical: e.target.checked })} style={{ accentColor: 'var(--cyan)' }} />
        </div>
      </div>

      {(saving || saved) && (
        <span style={{ fontSize: '0.78rem', color: saved ? 'var(--green)' : 'var(--text-dim)' }}>
          {saving ? 'Saving...' : 'Saved'}
        </span>
      )}
    </div>
  );
}
