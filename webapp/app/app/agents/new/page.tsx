'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import styles from './new.module.css';
import TEMPLATES from '@/lib/agent-templates';

const HERMES_TOOLS = [
  { name: 'web_search',     label: 'Web Search',     desc: 'Search the internet' },
  { name: 'terminal',       label: 'Terminal',        desc: 'Run shell commands' },
  { name: 'read_file',      label: 'Read File',       desc: 'Read local files' },
  { name: 'write_file',     label: 'Write File',      desc: 'Write to local files' },
  { name: 'list_files',     label: 'List Files',      desc: 'Browse directory trees' },
  { name: 'grep_codebase',  label: 'Grep Codebase',   desc: 'Search code by pattern' },
  { name: 'browser',        label: 'Browser',         desc: 'Control a headless browser' },
  { name: 'delegate_task',  label: 'Delegate Task',   desc: 'Spawn sub-agents (MAX_DEPTH 2)' },
];

const MEMORY_OPTIONS = [
  { value: 'builtin',   label: 'Built-in',  desc: 'MEMORY.md + USER.md (default)' },
  { value: 'honcho',    label: 'Honcho',    desc: 'Cloud memory via Honcho API' },
  { value: 'mem0',      label: 'Mem0',      desc: 'Cloud memory via Mem0 API' },
  { value: 'hindsight', label: 'Hindsight', desc: 'Cloud memory via Hindsight' },
  { value: 'none',      label: 'None',      desc: 'Stateless — no memory' },
];

const LLM_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY', 'MOONSHOT_API_KEY', 'XAI_API_KEY'];

type Step = 0 | 1 | 2 | 3;

interface EnvVar { key: string; value: string }

export default function NewAgentPage() {
  const router = useRouter();

  // Step 1 — Identity
  const [name, setName]         = useState('');
  const [description, setDesc]  = useState('');
  const [ciProvider, setCI]     = useState<'github' | 'gitlab' | 'none'>('github');

  // Step 2 — Config
  const [selectedTools, setTools] = useState<string[]>(['web_search', 'read_file']);
  const [customTool, setCustom]   = useState('');
  const [memoryProvider, setMem]  = useState('builtin');
  const [maxDepth, setDepth]      = useState(2);

  // Step 3 — Env vars (pre-filled with required LLM key)
  const [envVars, setEnvVars] = useState<EnvVar[]>([
    { key: 'ANTHROPIC_API_KEY', value: '' },
  ]);

  const [step, setStep]       = useState<Step>(0);
  const [saving, setSaving]   = useState(false);
  const [error, setError]     = useState('');

  function toggleTool(name: string) {
    setTools(prev => prev.includes(name) ? prev.filter(t => t !== name) : [...prev, name]);
  }

  function addCustomTool() {
    const t = customTool.trim().toLowerCase().replace(/\s+/g, '_');
    if (!t || selectedTools.includes(t)) return;
    setTools(prev => [...prev, t]);
    setCustom('');
  }

  function updateEnv(i: number, field: 'key' | 'value', val: string) {
    setEnvVars(prev => prev.map((e, idx) => idx === i ? { ...e, [field]: val } : e));
  }

  function addEnvRow() { setEnvVars(prev => [...prev, { key: '', value: '' }]); }
  function removeEnvRow(i: number) { setEnvVars(prev => prev.filter((_, idx) => idx !== i)); }

  async function save() {
    setError('');
    setSaving(true);
    try {
      const envObj = Object.fromEntries(
        envVars.filter(e => e.key.trim()).map(e => [e.key.trim(), e.value])
      );
      const res = await fetch('/api/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name, description, ciProvider,
          tools: selectedTools.map(n => ({ name: n })),
          memoryProvider, maxDepth,
          envVars: envObj,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create agent');
      router.push(`/app/agents/${data.agent.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong');
      setSaving(false);
    }
  }

  function applyTemplate(templateId: string) {
    const tpl = TEMPLATES.find(t => t.id === templateId);
    if (!tpl) { setStep(1); return; }
    setName(tpl.name);
    setDesc(tpl.description);
    setTools(tpl.tools);
    setMem(tpl.memoryProvider);
    setDepth(tpl.maxDepth);
    setStep(1);
  }

  const canStep1 = name.trim().length >= 2;
  const hasLLMKey = envVars.some(
    e => LLM_KEYS.includes(e.key.trim().toUpperCase()) && e.value.trim().length > 0
  );

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <a href="/app/agents" className={styles.back}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polyline points="15 18 9 12 15 6"/></svg>
          Agents
        </a>
        <h1>New Agent</h1>
        <p className={styles.subtitle}>Configure a Hermes agent — you can deploy it in the next step.</p>
      </div>

      {/* Step indicator */}
      <div className={styles.steps}>
        {(['Template', 'Identity', 'Configuration', 'Environment'] as const).map((label, i) => {
          const n = i as Step;
          return (
            <div key={label} className={`${styles.stepItem} ${step === n ? styles.stepActive : step > n ? styles.stepDone : ''}`}>
              <div className={styles.stepNum}>{step > n ? '✓' : n + 1}</div>
              <span>{label}</span>
            </div>
          );
        })}
      </div>

      <div className={styles.card}>
        {/* ── Step 0: Template picker ──────────────────────────── */}
        {step === 0 && (
          <div className={styles.stepBody}>
            <div className={styles.field}>
              <label className={styles.label}>Start from a template</label>
              <span className={styles.hint}>Pick a pre-configured security agent or start from scratch.</span>
            </div>
            <div className={styles.templateGrid}>
              {TEMPLATES.map(tpl => (
                <button
                  key={tpl.id}
                  type="button"
                  className={styles.templateCard}
                  onClick={() => applyTemplate(tpl.id)}
                >
                  <span className={styles.templateIcon}>{tpl.icon}</span>
                  <span className={styles.templateName}>{tpl.name}</span>
                  <span className={styles.templateDesc}>{tpl.description}</span>
                  <span className={styles.templateHint}>{tpl.promptHint}</span>
                </button>
              ))}
            </div>
            <div className={styles.actions}>
              <button className={styles.ghostBtn} type="button" onClick={() => setStep(1)}>
                Skip — start from scratch →
              </button>
            </div>
          </div>
        )}

        {/* ── Step 1: Identity ────────────────────────────────── */}
        {step === 1 && (
          <div className={styles.stepBody}>
            <div className={styles.field}>
              <label className={styles.label}>Agent name <span className={styles.req}>*</span></label>
              <input
                className={styles.input}
                placeholder="my-research-agent"
                value={name}
                onChange={e => setName(e.target.value)}
                maxLength={80}
                autoFocus
              />
              <span className={styles.hint}>Used as the agent&apos;s ID and subdomain slug.</span>
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Description</label>
              <textarea
                className={styles.textarea}
                placeholder="What does this agent do?"
                value={description}
                onChange={e => setDesc(e.target.value)}
                maxLength={300}
                rows={3}
              />
            </div>

            <div className={styles.field}>
              <label className={styles.label}>CI provider</label>
              <select className={styles.select} value={ciProvider} onChange={e => setCI(e.target.value as typeof ciProvider)}>
                <option value="github">GitHub Actions</option>
                <option value="gitlab">GitLab CI</option>
                <option value="none">None</option>
              </select>
              <span className={styles.hint}>Generates a workflow file that runs Ship Safe on every push.</span>
            </div>

            <div className={styles.actions}>
              <button className={styles.ghostBtn} onClick={() => setStep(0)} type="button">← Templates</button>
              <button className={styles.primaryBtn} onClick={() => setStep(2)} disabled={!canStep1}>
                Continue →
              </button>
            </div>
          </div>
        )}

        {/* ── Step 2: Configuration ───────────────────────────── */}
        {step === 2 && (
          <div className={styles.stepBody}>
            <div className={styles.field}>
              <label className={styles.label}>Tools</label>
              <span className={styles.hint}>Select the tools this agent is allowed to use.</span>
              <div className={styles.toolGrid}>
                {HERMES_TOOLS.map(t => (
                  <label key={t.name} className={`${styles.toolChip} ${selectedTools.includes(t.name) ? styles.toolSelected : ''}`}>
                    <input type="checkbox" checked={selectedTools.includes(t.name)} onChange={() => toggleTool(t.name)} className={styles.sr} />
                    <span className={styles.toolName}>{t.label}</span>
                    <span className={styles.toolDesc}>{t.desc}</span>
                  </label>
                ))}
              </div>
              <div className={styles.customToolRow}>
                <input
                  className={styles.input}
                  placeholder="custom_tool_name"
                  value={customTool}
                  onChange={e => setCustom(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addCustomTool()}
                />
                <button className={styles.addBtn} onClick={addCustomTool} type="button">Add</button>
              </div>
              {selectedTools.filter(t => !HERMES_TOOLS.find(h => h.name === t)).map(t => (
                <span key={t} className={styles.customTag}>
                  {t}
                  <button onClick={() => setTools(prev => prev.filter(x => x !== t))} className={styles.tagRemove}>×</button>
                </span>
              ))}
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Memory provider</label>
              <div className={styles.memGrid}>
                {MEMORY_OPTIONS.map(o => (
                  <label key={o.value} className={`${styles.memChip} ${memoryProvider === o.value ? styles.memSelected : ''}`}>
                    <input type="radio" name="mem" value={o.value} checked={memoryProvider === o.value} onChange={() => setMem(o.value)} className={styles.sr} />
                    <span className={styles.memLabel}>{o.label}</span>
                    <span className={styles.memDesc}>{o.desc}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Max delegation depth</label>
              <div className={styles.depthRow}>
                <button className={styles.depthBtn} onClick={() => setDepth(1)} disabled={maxDepth === 1} type="button">1</button>
                <button className={styles.depthBtn} onClick={() => setDepth(2)} disabled={maxDepth === 2} type="button">2</button>
                <span className={styles.depthNote}>
                  {maxDepth === 1 ? 'No sub-agents' : 'Parent → child (Hermes MAX_DEPTH)'}
                </span>
              </div>
            </div>

            <div className={styles.actions}>
              <button className={styles.ghostBtn} onClick={() => setStep(1)} type="button">← Back</button>
              <button className={styles.primaryBtn} onClick={() => setStep(3)} disabled={selectedTools.length === 0} type="button">
                Continue →
              </button>
            </div>
          </div>
        )}

        {/* ── Step 3: Env vars + review ───────────────────────── */}
        {step === 3 && (
          <div className={styles.stepBody}>
            <div className={styles.llmBanner}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
              <div>
                <strong>LLM API key required.</strong> Add at least one key below. Supported providers:
                {' '}<code>ANTHROPIC_API_KEY</code>, <code>OPENAI_API_KEY</code>, <code>DEEPSEEK_API_KEY</code>, <code>MOONSHOT_API_KEY</code>, <code>XAI_API_KEY</code>.
              </div>
            </div>

            <div className={styles.field}>
              <label className={styles.label}>Environment variables</label>
              <span className={styles.hint}>API keys and secrets your tools need. Stored securely in your agent config.</span>
              <div className={styles.envList}>
                {envVars.map((e, i) => (
                  <div key={i} className={styles.envRow}>
                    <input
                      className={styles.input}
                      placeholder="VARIABLE_NAME"
                      value={e.key}
                      onChange={ev => updateEnv(i, 'key', ev.target.value)}
                    />
                    <input
                      className={styles.input}
                      placeholder="value"
                      value={e.value}
                      onChange={ev => updateEnv(i, 'value', ev.target.value)}
                      type="password"
                    />
                    <button className={styles.removeBtn} onClick={() => removeEnvRow(i)} type="button" title="Remove">×</button>
                  </div>
                ))}
              </div>
              <button className={styles.ghostBtn} onClick={addEnvRow} type="button">+ Add variable</button>
            </div>

            <div className={styles.review}>
              <div className={styles.reviewTitle}>Review</div>
              <div className={styles.reviewGrid}>
                <span className={styles.reviewKey}>Name</span>
                <span className={styles.reviewVal}>{name}</span>
                <span className={styles.reviewKey}>Tools</span>
                <span className={styles.reviewVal}>{selectedTools.join(', ')}</span>
                <span className={styles.reviewKey}>Memory</span>
                <span className={styles.reviewVal}>{memoryProvider}</span>
                <span className={styles.reviewKey}>Max depth</span>
                <span className={styles.reviewVal}>{maxDepth}</span>
                <span className={styles.reviewKey}>CI</span>
                <span className={styles.reviewVal}>{ciProvider}</span>
              </div>
            </div>

            {!hasLLMKey && (
              <div className={styles.keyWarning}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Add an LLM API key above before creating the agent.
              </div>
            )}

            {error && <div className={styles.error}>{error}</div>}

            <div className={styles.actions}>
              <button className={styles.ghostBtn} onClick={() => setStep(2)} type="button">← Back</button>
              <button className={styles.primaryBtn} onClick={save} disabled={saving || !hasLLMKey} type="button">
                {saving ? 'Saving…' : 'Create Agent'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
