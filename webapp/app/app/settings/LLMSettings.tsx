'use client';
import { useState, useEffect } from 'react';
import { track } from '@vercel/analytics/react';
import s from './settings.module.css';

const PROVIDERS = [
  { value: 'auto',         label: 'Auto-detect',    desc: 'Use first available key' },
  { value: 'deepseek',     label: 'DeepSeek V4 Pro',  desc: 'Best for deep analysis · 1M ctx' },
  { value: 'deepseek-flash', label: 'DeepSeek V4 Flash', desc: 'Fastest · ideal for swarm' },
  { value: 'openai',       label: 'OpenAI',          desc: 'GPT-5.5 · GPT-5.5 Pro' },
  { value: 'kimi',         label: 'Kimi K3',         desc: 'Moonshot · 1M context' },
  { value: 'anthropic',    label: 'Anthropic',       desc: 'Claude Opus / Sonnet' },
  { value: 'xai',          label: 'xAI',             desc: 'Grok-3 mini' },
];

const MODELS_BY_PROVIDER: Record<string, { value: string; label: string }[]> = {
  auto:          [],
  deepseek:      [{ value: 'deepseek-v4-pro',   label: 'DeepSeek V4 Pro' }],
  'deepseek-flash': [{ value: 'deepseek-v4-flash', label: 'DeepSeek V4 Flash' }],
  openai:        [
    { value: 'gpt-5.5',     label: 'GPT-5.5' },
    { value: 'gpt-5.5-pro', label: 'GPT-5.5 Pro' },
    { value: 'gpt-5.4',     label: 'GPT-5.4' },
    { value: 'gpt-5.4-mini',label: 'GPT-5.4 Mini' },
  ],
  kimi:          [
    { value: 'kimi-k3',           label: 'Kimi K3' },
    { value: 'kimi-k2.7-code-preview', label: 'Kimi K2.7 Code' },
    { value: 'kimi-k2.6',         label: 'Kimi K2.6' },
    { value: 'moonshot-v1-128k',  label: 'Moonshot 128K' },
  ],
  anthropic:     [
    { value: 'claude-opus-4-7',           label: 'Claude Opus 4.7' },
    { value: 'claude-sonnet-4-6',         label: 'Claude Sonnet 4.6' },
    { value: 'claude-haiku-4-5-20251001', label: 'Claude Haiku 4.5' },
  ],
  xai:           [{ value: 'grok-3-mini', label: 'Grok-3 Mini' }],
};

const API_KEY_FOR: Record<string, string> = {
  deepseek:        'DEEPSEEK_API_KEY',
  'deepseek-flash':'DEEPSEEK_API_KEY',
  openai:          'OPENAI_API_KEY',
  kimi:            'MOONSHOT_API_KEY',
  anthropic:       'ANTHROPIC_API_KEY',
  xai:             'XAI_API_KEY',
  google:          'GOOGLE_API_KEY',
};

const ALL_KEYS = [
  { key: 'DEEPSEEK_API_KEY',  label: 'DeepSeek',  placeholder: 'sk-...' },
  { key: 'OPENAI_API_KEY',    label: 'OpenAI',    placeholder: 'sk-...' },
  { key: 'MOONSHOT_API_KEY',  label: 'Kimi / Moonshot', placeholder: 'sk-...' },
  { key: 'KIMI_API_KEY',      label: 'Kimi',      placeholder: 'sk-...' },
  { key: 'ANTHROPIC_API_KEY', label: 'Anthropic', placeholder: 'sk-ant-...' },
  { key: 'XAI_API_KEY',       label: 'xAI',       placeholder: 'xai-...' },
  { key: 'GOOGLE_API_KEY',    label: 'Google',    placeholder: 'AIza...' },
];

interface LLMSettingsData {
  provider: string;
  model: string;
  think: boolean;
  swarm: boolean;
  apiKeys: Record<string, string>;
}

const DEFAULT: LLMSettingsData = {
  provider: 'auto',
  model: '',
  think: false,
  swarm: false,
  apiKeys: {},
};

export default function LLMSettings() {
  const [data, setData]       = useState<LLMSettingsData>(DEFAULT);
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');

  useEffect(() => {
    fetch('/api/user/llm-settings')
      .then(r => r.json())
      .then(({ llmSettings }) => {
        if (llmSettings) setData({ ...DEFAULT, ...llmSettings, apiKeys: llmSettings.apiKeys ?? {} });
      })
      .finally(() => setLoading(false));
  }, []);

  function set<K extends keyof LLMSettingsData>(key: K, val: LLMSettingsData[K]) {
    setData(prev => ({ ...prev, [key]: val }));
    setSaved(false);
  }

  function setApiKey(k: string, v: string) {
    setData(prev => ({ ...prev, apiKeys: { ...prev.apiKeys, [k]: v } }));
    setSaved(false);
  }

  async function save() {
    setSaving(true);
    setError('');
    try {
      const response = await fetch('/api/user/llm-settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const result = await response.json().catch(() => null);
        throw new Error(result?.error || 'Could not save AI settings.');
      }

      setSaved(true);
      track('LLM Provider Configured', {
        provider: data.provider,
        model: data.model || 'default',
        think: data.think,
        swarm: data.swarm,
        hasApiKey: Object.values(data.apiKeys).some(Boolean),
      });
    } catch (saveError) {
      setSaved(false);
      setError(saveError instanceof Error ? saveError.message : 'Could not save AI settings.');
    } finally {
      setSaving(false);
    }
  }

  const models = MODELS_BY_PROVIDER[data.provider] ?? [];
  const thinkSupported = ['openai', 'anthropic', 'kimi'].includes(data.provider);

  if (loading) return <div className={s.llmLoading}>Loading…</div>;

  return (
    <div className={s.llmCard}>

      {/* Provider */}
      <div className={s.llmRow}>
        <div className={s.llmRowLabel}>
          <span className={s.llmLabel}>Default Provider</span>
          <span className={s.llmHint}>Used for deep analysis and AI classification</span>
        </div>
        <div className={s.llmProviderGrid}>
          {PROVIDERS.map(p => (
            <button
              key={p.value}
              type="button"
              className={`${s.providerChip} ${data.provider === p.value ? s.providerChipActive : ''}`}
              onClick={() => { set('provider', p.value); set('model', ''); }}
            >
              <span className={s.providerChipLabel}>{p.label}</span>
              <span className={s.providerChipDesc}>{p.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Model */}
      {models.length > 0 && (
        <div className={s.llmRow}>
          <div className={s.llmRowLabel}>
            <span className={s.llmLabel}>Model</span>
          </div>
          <select
            className={s.llmSelect}
            value={data.model || models[0]?.value}
            onChange={e => set('model', e.target.value)}
          >
            {models.map(m => (
              <option key={m.value} value={m.value}>{m.label}</option>
            ))}
          </select>
        </div>
      )}

      {/* Toggles */}
      <div className={s.llmRow}>
        <div className={s.llmRowLabel}>
          <span className={s.llmLabel}>Options</span>
        </div>
        <div className={s.llmToggles}>
          <label className={`${s.llmToggle} ${!thinkSupported ? s.llmToggleDisabled : ''}`}>
            <input
              type="checkbox"
              checked={data.think && thinkSupported}
              disabled={!thinkSupported}
              onChange={e => set('think', e.target.checked)}
            />
            <span>
              <strong>Think mode</strong>
              <span className={s.llmHint}>Extended reasoning (GPT-5.5 / Claude / Kimi)</span>
            </span>
          </label>
          <label className={s.llmToggle}>
            <input
              type="checkbox"
              checked={data.swarm}
              onChange={e => set('swarm', e.target.checked)}
            />
            <span>
              <strong>Swarm mode</strong>
              <span className={s.llmHint}>29 parallel agents — requires DeepSeek or Kimi key</span>
            </span>
          </label>
        </div>
      </div>

      {/* API Keys */}
      <div className={s.llmRow}>
        <div className={s.llmRowLabel}>
          <span className={s.llmLabel}>API Keys</span>
          <span className={s.llmHint}>Encrypted at rest. Saved values cannot be revealed.</span>
        </div>
        <div className={s.llmKeyList}>
          {ALL_KEYS.map(({ key, label, placeholder }) => {
            const isRequired = API_KEY_FOR[data.provider] === key;
            return (
              <div key={key} className={s.llmKeyRow}>
                <span className={`${s.llmKeyLabel} ${isRequired ? s.llmKeyRequired : ''}`}>
                  {label}{isRequired && <span className={s.reqDot} title="Required for selected provider" />}
                </span>
                <input
                  type="password"
                  className={s.llmKeyInput}
                  placeholder={data.apiKeys[key] ? '●●●●●●●●●●●●' : placeholder}
                  value={data.apiKeys[key] ?? ''}
                  onChange={e => setApiKey(key, e.target.value)}
                  autoComplete="off"
                />
              </div>
            );
          })}
        </div>
      </div>

      <div className={s.llmFooter}>
        <button className={s.llmSaveBtn} onClick={save} disabled={saving}>
          {saving ? 'Saving…' : saved ? '✓ Saved' : 'Save AI Settings'}
        </button>
        {error && <p className={s.error}>{error}</p>}
      </div>
    </div>
  );
}
