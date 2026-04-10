'use client';
import { useEffect, useState } from 'react';
import s from './settings.module.css';
import { useToast } from '@/app/app/Toast';

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
  const { toast } = useToast();

  useEffect(() => {
    fetch('/api/notifications').then(r => r.json()).then(setSettings);
  }, []);

  async function save(updates: Partial<Settings>) {
    setSaving(true);
    const res = await fetch('/api/notifications', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    const data = await res.json();
    setSaving(false);
    if (!res.ok) { toast(data.error || 'Failed to save', 'error'); return; }
    setSettings(data);
    toast('Notifications saved', 'success');
  }

  if (!settings) return <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>Loading...</p>;

  return (
    <div className={s.settingsGroup}>
      <div className={s.settingsCard}>
        <div className={s.settingsCardTitle}>Email Notifications</div>
        <div className={s.settingsRow}>
          <div><span className={s.settingsLabel}>Scan complete</span><br /><span className={s.settingsDesc}>Email when a scan finishes</span></div>
          <input type="checkbox" checked={settings.emailOnComplete} onChange={e => save({ emailOnComplete: e.target.checked })} className={s.checkbox} />
        </div>
        <div className={s.settingsRow}>
          <div><span className={s.settingsLabel}>Critical findings</span><br /><span className={s.settingsDesc}>Email when critical issues are found</span></div>
          <input type="checkbox" checked={settings.emailOnCritical} onChange={e => save({ emailOnCritical: e.target.checked })} className={s.checkbox} />
        </div>
        <div className={s.settingsRow}>
          <div><span className={s.settingsLabel}>Weekly digest</span><br /><span className={s.settingsDesc}>Summary of scan activity</span></div>
          <select value={settings.emailDigest} onChange={e => save({ emailDigest: e.target.value })} className={s.settingsSelect}>
            <option value="off">Off</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
      </div>

      <div className={s.settingsCard}>
        <div className={s.settingsCardTitle}>Slack Integration</div>
        <div className={s.settingsInputRow}>
          <input
            type="url"
            placeholder="https://hooks.slack.com/services/..."
            value={settings.slackWebhookUrl || ''}
            onChange={e => setSettings(prev => prev ? { ...prev, slackWebhookUrl: e.target.value } : prev)}
            onBlur={e => save({ slackWebhookUrl: e.target.value || null })}
            className={s.settingsInput}
          />
        </div>
        <div className={s.settingsRow}>
          <div><span className={s.settingsLabel}>Post on scan complete</span></div>
          <input type="checkbox" checked={settings.slackOnComplete} onChange={e => save({ slackOnComplete: e.target.checked })} className={s.checkbox} />
        </div>
        <div className={s.settingsRow}>
          <div><span className={s.settingsLabel}>Post on critical findings</span></div>
          <input type="checkbox" checked={settings.slackOnCritical} onChange={e => save({ slackOnCritical: e.target.checked })} className={s.checkbox} />
        </div>
      </div>

      {saving && <span className={s.savedMsg}>Saving…</span>}
    </div>
  );
}
