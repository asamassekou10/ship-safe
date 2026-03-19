'use client';
import { useEffect, useState } from 'react';
import styles from './policies.module.css';

interface Policy {
  id: string;
  name: string;
  description: string | null;
  rules: PolicyRule[];
  enforcement: string;
  enabled: boolean;
}

interface PolicyRule {
  type: string; // min_score | max_severity | block_category | require_scan
  value: string | number;
  message?: string;
}

const PRESETS: Record<string, { name: string; description: string; rules: PolicyRule[] }> = {
  'soc2': {
    name: 'SOC 2 Compliance',
    description: 'Enforces minimum security standards for SOC 2 compliance',
    rules: [
      { type: 'min_score', value: 75, message: 'Score must be at least 75 for SOC 2' },
      { type: 'max_severity', value: 'critical', message: 'No critical findings allowed' },
      { type: 'block_category', value: 'secrets', message: 'No secrets in source code' },
    ],
  },
  'hipaa': {
    name: 'HIPAA Security',
    description: 'Ensures code handles health data securely',
    rules: [
      { type: 'min_score', value: 80, message: 'Score must be at least 80 for HIPAA' },
      { type: 'max_severity', value: 'high', message: 'No high or critical findings' },
      { type: 'block_category', value: 'secrets', message: 'No hardcoded secrets' },
      { type: 'block_category', value: 'auth', message: 'No auth vulnerabilities' },
    ],
  },
  'strict': {
    name: 'Strict Security',
    description: 'Maximum security enforcement — block on any finding',
    rules: [
      { type: 'min_score', value: 90, message: 'Score must be at least 90' },
      { type: 'max_severity', value: 'medium', message: 'No medium+ findings allowed' },
    ],
  },
};

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [orgId, setOrgId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newRules, setNewRules] = useState<PolicyRule[]>([]);
  const [newEnforcement, setNewEnforcement] = useState('warn');
  const [error, setError] = useState('');

  // Get user's first org
  useEffect(() => {
    fetch('/api/orgs').then(r => r.json()).then(d => {
      if (d.orgs?.length > 0) {
        setOrgId(d.orgs[0].id);
      }
      setLoading(false);
    });
  }, []);

  // Fetch policies when org is selected
  useEffect(() => {
    if (!orgId) return;
    fetch(`/api/policies?orgId=${orgId}`).then(r => r.json()).then(d => {
      setPolicies(d.policies || []);
    });
  }, [orgId]);

  function applyPreset(key: string) {
    const preset = PRESETS[key];
    if (!preset) return;
    setNewName(preset.name);
    setNewDesc(preset.description);
    setNewRules(preset.rules);
    setShowCreate(true);
  }

  async function createPolicy() {
    setError('');
    if (!orgId || !newName) return;
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgId, name: newName, description: newDesc, rules: newRules, enforcement: newEnforcement }),
    });
    const data = await res.json();
    if (!res.ok) { setError(data.error); return; }
    setPolicies(prev => [data, ...prev]);
    setShowCreate(false);
    setNewName('');
    setNewDesc('');
    setNewRules([]);
  }

  async function togglePolicy(id: string, enabled: boolean) {
    await fetch('/api/policies', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, enabled }),
    });
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, enabled } : p));
  }

  if (loading) return <div className={styles.page}><p style={{ color: 'var(--text-dim)' }}>Loading...</p></div>;

  if (!orgId) {
    return (
      <div className={styles.page}>
        <div className={styles.header}>
          <h1>Security Policies</h1>
          <p className={styles.subtitle}>Create an organization first to set up security policies.</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1>Security Policies</h1>
          <p className={styles.subtitle}>Enforce security standards across your organization</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="btn btn-primary">
          New Policy
        </button>
      </div>

      {/* Compliance presets */}
      <div className={styles.presets}>
        <h3>Quick Start with Compliance Presets</h3>
        <div className={styles.presetGrid}>
          {Object.entries(PRESETS).map(([key, preset]) => (
            <button key={key} className={styles.presetCard} onClick={() => applyPreset(key)}>
              <span className={styles.presetName}>{preset.name}</span>
              <span className={styles.presetDesc}>{preset.description}</span>
              <span className={styles.presetRules}>{preset.rules.length} rules</span>
            </button>
          ))}
        </div>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className={styles.createForm}>
          <input type="text" placeholder="Policy name" value={newName} onChange={e => setNewName(e.target.value)} className={styles.input} />
          <input type="text" placeholder="Description (optional)" value={newDesc} onChange={e => setNewDesc(e.target.value)} className={styles.input} />
          <div className={styles.rulesPreview}>
            {newRules.map((r, i) => (
              <div key={i} className={styles.ruleChip}>
                <span>{r.type}: {String(r.value)}</span>
                <button onClick={() => setNewRules(prev => prev.filter((_, j) => j !== i))} className={styles.ruleRemove}>✕</button>
              </div>
            ))}
          </div>
          <div className={styles.enforcementRow}>
            <label>Enforcement:</label>
            <select value={newEnforcement} onChange={e => setNewEnforcement(e.target.value)} className={styles.select}>
              <option value="warn">Warn (notify but don&apos;t block)</option>
              <option value="block">Block (fail CI/CD checks)</option>
            </select>
          </div>
          {error && <p className={styles.error}>{error}</p>}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button onClick={createPolicy} className="btn btn-primary" disabled={!newName.trim()}>Create Policy</button>
            <button onClick={() => setShowCreate(false)} className="btn btn-ghost">Cancel</button>
          </div>
        </div>
      )}

      {/* Policy list */}
      {policies.length === 0 && !showCreate ? (
        <div className={styles.emptyState}>
          <p>No policies yet. Create one from a preset above or build a custom policy.</p>
        </div>
      ) : (
        <div className={styles.policyList}>
          {policies.map(policy => (
            <div key={policy.id} className={`${styles.policyCard} ${!policy.enabled ? styles.disabled : ''}`}>
              <div className={styles.policyHeader}>
                <div>
                  <span className={styles.policyName}>{policy.name}</span>
                  {policy.description && <span className={styles.policyDesc}>{policy.description}</span>}
                </div>
                <div className={styles.policyActions}>
                  <span className={`${styles.enforceBadge} ${policy.enforcement === 'block' ? styles.enforceBlock : styles.enforceWarn}`}>
                    {policy.enforcement}
                  </span>
                  <label className={styles.toggle}>
                    <input type="checkbox" checked={policy.enabled} onChange={e => togglePolicy(policy.id, e.target.checked)} />
                    <span className={styles.toggleSlider} />
                  </label>
                </div>
              </div>
              <div className={styles.rulesList}>
                {policy.rules.map((rule, i) => (
                  <div key={i} className={styles.ruleItem}>
                    <span className={styles.ruleType}>{rule.type}</span>
                    <span className={styles.ruleValue}>{String(rule.value)}</span>
                    {rule.message && <span className={styles.ruleMsg}>{rule.message}</span>}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
