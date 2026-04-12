'use client';
import { useState } from 'react';
import styles from './deploy.module.css';

// ── Types ──────────────────────────────────────────────────────────────────

interface Tool {
  name: string;
  sourceUrl: string;
}

interface WizardState {
  // Step 1 — Project
  projectName: string;
  repoUrl: string;
  framework: string;
  // Step 2 — Hermes config
  tools: Tool[];
  memoryLayers: ('episodic' | 'semantic' | 'working')[];
  hasSubAgents: boolean;
  hasManifest: boolean;
  manifestPath: string;
  ciProvider: 'github' | 'gitlab' | 'none';
}

const STEPS = ['Project', 'Configure', 'Review', 'Deploy'];

// ── Step 1 — Project info ──────────────────────────────────────────────────

function Step1({ state, set }: { state: WizardState; set: (s: Partial<WizardState>) => void }) {
  return (
    <div className={styles.fieldGroup}>
      <div className={styles.field}>
        <label className={styles.label}>
          Project name <span className={styles.labelHint}>optional</span>
        </label>
        <input
          className={styles.input}
          placeholder="my-hermes-agent"
          value={state.projectName}
          onChange={e => set({ projectName: e.target.value })}
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label}>
          Repository URL <span className={styles.labelHint}>optional — for setup guide</span>
        </label>
        <input
          className={styles.input}
          placeholder="https://github.com/your-org/your-repo"
          value={state.repoUrl}
          onChange={e => set({ repoUrl: e.target.value })}
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label}>CI provider</label>
        <div className={styles.selectWrap}>
          <select
            className={styles.select}
            value={state.ciProvider}
            onChange={e => set({ ciProvider: e.target.value as WizardState['ciProvider'] })}
          >
            <option value="github">GitHub Actions</option>
            <option value="gitlab">GitLab CI</option>
            <option value="none">None / I'll add it manually</option>
          </select>
          <svg className={styles.selectChevron} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
      </div>
    </div>
  );
}

// ── Step 2 — Hermes configuration ─────────────────────────────────────────

function Step2({ state, set }: { state: WizardState; set: (s: Partial<WizardState>) => void }) {
  function addTool() {
    set({ tools: [...state.tools, { name: '', sourceUrl: '' }] });
  }

  function updateTool(i: number, field: keyof Tool, val: string) {
    const tools = [...state.tools];
    tools[i] = { ...tools[i], [field]: val };
    set({ tools });
  }

  function removeTool(i: number) {
    set({ tools: state.tools.filter((_, idx) => idx !== i) });
  }

  function toggleMemory(layer: 'episodic' | 'semantic' | 'working') {
    const has = state.memoryLayers.includes(layer);
    set({
      memoryLayers: has
        ? state.memoryLayers.filter(l => l !== layer)
        : [...state.memoryLayers, layer],
    });
  }

  return (
    <div className={styles.fieldGroup}>
      {/* Tool registry */}
      <div className={styles.field}>
        <label className={styles.label}>
          Registered tools
          <span className={styles.labelHint}>from your Hermes tool registry</span>
        </label>
        <div className={styles.toolList}>
          {state.tools.map((tool, i) => (
            <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              <div className={styles.toolRow}>
                <input
                  className={styles.input}
                  placeholder={`tool_name_${i + 1}`}
                  value={tool.name}
                  onChange={e => updateTool(i, 'name', e.target.value)}
                />
                <button className={styles.removeBtn} onClick={() => removeTool(i)} aria-label="Remove tool">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              </div>
              <div className={styles.toolRowUrl}>
                <input
                  className={styles.input}
                  placeholder="https://... (leave blank if local)"
                  value={tool.sourceUrl}
                  onChange={e => updateTool(i, 'sourceUrl', e.target.value)}
                />
              </div>
            </div>
          ))}
          <button className={styles.addToolBtn} onClick={addTool}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add tool
          </button>
        </div>
      </div>

      {/* Memory layers */}
      <div className={styles.field}>
        <label className={styles.label}>Memory layers used</label>
        <div className={styles.checkGrid}>
          {(['episodic', 'semantic', 'working'] as const).map(layer => {
            const checked = state.memoryLayers.includes(layer);
            return (
              <label key={layer} className={styles.checkItem}>
                <input type="checkbox" checked={checked} onChange={() => toggleMemory(layer)} />
                <div className={`${styles.checkBox} ${checked ? styles.checked : ''}`}>
                  {checked && <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>}
                </div>
                <span className={styles.checkLabel}>{layer.charAt(0).toUpperCase() + layer.slice(1)}</span>
              </label>
            );
          })}
        </div>
      </div>

      {/* Sub-agents */}
      <div className={styles.toggleRow}>
        <div>
          <div className={styles.toggleLabel}>Uses sub-agents</div>
          <div className={styles.toggleSub}>Enables multi-agent trust boundary checks (max recursion depth)</div>
        </div>
        <button
          className={`${styles.toggle} ${state.hasSubAgents ? styles.on : ''}`}
          onClick={() => set({ hasSubAgents: !state.hasSubAgents })}
          aria-label="Toggle sub-agents"
        >
          <div className={styles.toggleThumb} />
        </button>
      </div>

      {/* Manifest */}
      <div className={styles.toggleRow}>
        <div>
          <div className={styles.toggleLabel}>Has existing agent manifest</div>
          <div className={styles.toggleSub}>We'll patch it with integrity hashes instead of creating a new one</div>
        </div>
        <button
          className={`${styles.toggle} ${state.hasManifest ? styles.on : ''}`}
          onClick={() => set({ hasManifest: !state.hasManifest })}
          aria-label="Toggle manifest"
        >
          <div className={styles.toggleThumb} />
        </button>
      </div>

      {state.hasManifest && (
        <div className={styles.field}>
          <label className={styles.label}>Manifest file path</label>
          <input
            className={styles.input}
            placeholder="agent-manifest.json"
            value={state.manifestPath}
            onChange={e => set({ manifestPath: e.target.value })}
          />
        </div>
      )}
    </div>
  );
}

// ── Step 3 — Review ────────────────────────────────────────────────────────

function Step3({ state }: { state: WizardState }) {
  const files = [
    { path: state.manifestPath || 'agent-manifest.json', desc: 'Hardened manifest with integrity hashes' },
    { path: '.ship-safe/agents/hermes-policy.js', desc: `Allowlist: ${state.tools.filter(t => t.name).map(t => t.name).join(', ') || 'none'}` },
    { path: '.ship-safe/hermes-baseline.json', desc: 'Baseline score (populate with first audit)' },
    ...(state.ciProvider === 'github' ? [{ path: '.github/workflows/ship-safe-hermes.yml', desc: 'GitHub Actions CI workflow' }] : []),
    ...(state.ciProvider === 'gitlab' ? [{ path: 'ship-safe-hermes-ci.yml', desc: 'GitLab CI job (append to .gitlab-ci.yml)' }] : []),
    { path: 'SHIP_SAFE_SETUP.md', desc: 'Step-by-step setup guide' },
  ];

  return (
    <div className={styles.fieldGroup}>
      <div className={styles.reviewGrid}>
        <div className={styles.reviewItem}>
          <div className={styles.reviewKey}>Project</div>
          <div className={styles.reviewVal}>{state.projectName || '(unnamed)'}</div>
        </div>
        <div className={styles.reviewItem}>
          <div className={styles.reviewKey}>Tools registered</div>
          <div className={styles.reviewVal}>{state.tools.filter(t => t.name).length}</div>
        </div>
        <div className={styles.reviewItem}>
          <div className={styles.reviewKey}>Memory layers</div>
          <div className={styles.reviewVal}>{state.memoryLayers.length > 0 ? state.memoryLayers.join(', ') : 'None'}</div>
        </div>
        <div className={styles.reviewItem}>
          <div className={styles.reviewKey}>Sub-agents</div>
          <div className={styles.reviewVal}>{state.hasSubAgents ? 'Yes — depth limit: 3' : 'No'}</div>
        </div>
        <div className={styles.reviewItem}>
          <div className={styles.reviewKey}>CI provider</div>
          <div className={styles.reviewVal}>{state.ciProvider === 'github' ? 'GitHub Actions' : state.ciProvider === 'gitlab' ? 'GitLab CI' : 'None'}</div>
        </div>
        <div className={styles.reviewItem}>
          <div className={styles.reviewKey}>Files generated</div>
          <div className={styles.reviewVal}>{files.length}</div>
        </div>
      </div>

      <div className={styles.field}>
        <label className={styles.label}>Files in your bundle</label>
        <div className={styles.fileList}>
          {files.map(f => (
            <div key={f.path} className={styles.fileRow}>
              <svg className={styles.fileIcon} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
              <span className={styles.filePath}>{f.path}</span>
              <span className={styles.fileDesc}>{f.desc}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: '0.85rem 1rem', background: 'var(--cyan-glow)', border: '1px solid rgba(8,145,178,0.15)', borderRadius: 'var(--radius)', fontSize: '0.83rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--cyan)' }}>Everything stays local.</strong> No code is uploaded to Ship Safe servers. The bundle is generated from your configuration answers and downloaded directly to your machine.
      </div>
    </div>
  );
}

// ── Step 4 — Deploy (success) ──────────────────────────────────────────────

function Step4({ projectName, ciProvider }: { projectName: string; ciProvider: string }) {
  return (
    <div className={styles.successCard}>
      <div className={styles.successIcon}>
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
      <div className={styles.successTitle}>Bundle downloaded!</div>
      <div className={styles.successSub}>
        Extract the zip into your project root and follow the steps below to activate your Hermes security agents.
      </div>
      <div className={styles.nextSteps}>
        <h3>Next steps</h3>
        <div className={styles.stepsList}>
          <div className={styles.stepsListItem}>
            <div className={styles.stepsListNum}>1</div>
            <div className={styles.stepsListText}>
              Extract the zip into your project root — all files go to their correct paths automatically.
            </div>
          </div>
          <div className={styles.stepsListItem}>
            <div className={styles.stepsListNum}>2</div>
            <div className={styles.stepsListText}>
              For remote tools, generate integrity hashes: <code>npx ship-safe hash &lt;source-url&gt;</code> and add them to your manifest.
            </div>
          </div>
          <div className={styles.stepsListItem}>
            <div className={styles.stepsListNum}>3</div>
            <div className={styles.stepsListText}>
              Run your first audit to populate the baseline: <code>npx ship-safe audit .</code>
            </div>
          </div>
          <div className={styles.stepsListItem}>
            <div className={styles.stepsListNum}>4</div>
            <div className={styles.stepsListText}>
              {ciProvider === 'github'
                ? 'Commit all files and push — CI will run on your next PR and post a security score comment.'
                : ciProvider === 'gitlab'
                ? 'Append ship-safe-hermes-ci.yml to your .gitlab-ci.yml and push.'
                : 'Commit all files. Run ship-safe audit . locally before each deploy.'}
            </div>
          </div>
          <div className={styles.stepsListItem}>
            <div className={styles.stepsListNum}>5</div>
            <div className={styles.stepsListText}>
              Auto-fix findings: <code>npx ship-safe audit . --agentic 3 --agentic-target 80</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main wizard ────────────────────────────────────────────────────────────

const DEFAULT: WizardState = {
  projectName: '',
  repoUrl: '',
  framework: '',
  tools: [{ name: '', sourceUrl: '' }],
  memoryLayers: [],
  hasSubAgents: false,
  hasManifest: false,
  manifestPath: 'agent-manifest.json',
  ciProvider: 'github',
};

export default function DeployPage() {
  const [step, setStep] = useState(0);
  const [state, setState] = useState<WizardState>(DEFAULT);
  const [loading, setLoading] = useState(false);
  const [deployed, setDeployed] = useState(false);
  const [error, setError] = useState('');

  function set(partial: Partial<WizardState>) {
    setState(s => ({ ...s, ...partial }));
  }

  const validTools = state.tools.filter(t => t.name.trim());

  function canAdvance() {
    if (step === 1) return validTools.length > 0;
    return true;
  }

  async function handleDownload() {
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/generate-hermes-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...state,
          tools: validTools,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to generate config');
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const slug = (state.projectName || 'hermes-project').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40);
      a.download = `ship-safe-hermes-${slug}.zip`;
      a.click();
      URL.revokeObjectURL(url);

      setDeployed(true);
      setStep(3);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={styles.page}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerTop}>
          <div className={styles.hermesBadge}>
            <span className={styles.hermesDot} />
            Hermes Agent Security
          </div>
        </div>
        <h1>Deploy 22 security agents</h1>
        <p className={styles.headerSub}>
          Answer 4 questions. Get a hardened config bundle — allowlists, integrity hashes, and CI — ready to drop into your project.
        </p>
      </div>

      {/* Stepper */}
      <div className={styles.stepper}>
        {STEPS.map((label, i) => {
          const isDone = i < step;
          const isActive = i === step;
          return (
            <div key={label} className={styles.stepItem}>
              <div className={`${styles.stepNum} ${isActive ? styles.active : ''} ${isDone ? styles.done : ''}`}>
                {isDone
                  ? <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                  : i + 1}
              </div>
              <span className={`${styles.stepLabel} ${isActive ? styles.active : ''} ${isDone ? styles.done : ''}`}>{label}</span>
              {i < STEPS.length - 1 && <div className={`${styles.stepConnector} ${isDone ? styles.done : ''}`} />}
            </div>
          );
        })}
      </div>

      {/* Step content */}
      {deployed ? (
        <Step4 projectName={state.projectName} ciProvider={state.ciProvider} />
      ) : (
        <div className={styles.card}>
          <div className={styles.cardTitle}>
            {step === 0 && <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg> About your project</>}
            {step === 1 && <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Hermes configuration</>}
            {step === 2 && <><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg> Review your bundle</>}
          </div>

          {step === 0 && <Step1 state={state} set={set} />}
          {step === 1 && <Step2 state={state} set={set} />}
          {step === 2 && <Step3 state={state} />}

          {error && (
            <div style={{ padding: '0.75rem 1rem', background: 'rgba(220,38,38,0.06)', border: '1px solid rgba(220,38,38,0.2)', borderRadius: 'var(--radius)', fontSize: '0.85rem', color: 'var(--red)' }}>
              {error}
            </div>
          )}

          <div className={styles.actions}>
            <div>
              {step > 0 && (
                <button className={styles.btnBack} onClick={() => setStep(s => s - 1)}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"/></svg>
                  Back
                </button>
              )}
            </div>
            <div className={styles.actionsRight}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
                Step {step + 1} of {STEPS.length - 1}
              </span>
              {step < 2 && (
                <button
                  className={styles.btnNext}
                  onClick={() => setStep(s => s + 1)}
                  disabled={!canAdvance()}
                >
                  Next
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"/></svg>
                </button>
              )}
              {step === 2 && (
                <button className={styles.btnDownload} onClick={handleDownload} disabled={loading}>
                  {loading ? (
                    <><span className={styles.loadingSpinner} /> Generating…</>
                  ) : (
                    <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Download bundle</>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
