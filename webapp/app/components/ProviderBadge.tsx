import React from 'react';

const LABELS: Record<string, { label: string; color: string; bg: string }> = {
  'deepseek-flash': { label: 'DeepSeek Flash ⚡', color: '#22d3ee', bg: 'rgba(34,211,238,0.10)' },
  deepseek:         { label: 'DeepSeek Pro',       color: '#22d3ee', bg: 'rgba(34,211,238,0.10)' },
  openai:           { label: 'GPT-5.5',            color: '#a78bfa', bg: 'rgba(167,139,250,0.10)' },
  'gpt-5.5':        { label: 'GPT-5.5',            color: '#a78bfa', bg: 'rgba(167,139,250,0.10)' },
  'gpt-5.5-pro':    { label: 'GPT-5.5 Pro',        color: '#a78bfa', bg: 'rgba(167,139,250,0.10)' },
  kimi:             { label: 'Kimi K2.6',           color: '#f97316', bg: 'rgba(249,115,22,0.10)' },
  moonshot:         { label: 'Kimi K2.6',           color: '#f97316', bg: 'rgba(249,115,22,0.10)' },
  anthropic:        { label: 'Claude',              color: '#f59e0b', bg: 'rgba(245,158,11,0.10)' },
  xai:              { label: 'Grok',                color: '#94a3b8', bg: 'rgba(148,163,184,0.10)' },
  google:           { label: 'Gemini',              color: '#34d399', bg: 'rgba(52,211,153,0.10)' },
};

const STYLE: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  fontSize: '0.65rem',
  fontWeight: 700,
  letterSpacing: '0.03em',
  padding: '0.15rem 0.5rem',
  borderRadius: '4px',
  whiteSpace: 'nowrap',
};

export default function ProviderBadge({ provider }: { provider?: string | null }) {
  if (!provider) return null;
  const cfg = LABELS[provider.toLowerCase()] ?? { label: provider, color: 'var(--text-dim)', bg: 'var(--bg)' };
  return (
    <span style={{ ...STYLE, color: cfg.color, background: cfg.bg }}>
      {cfg.label}
    </span>
  );
}
