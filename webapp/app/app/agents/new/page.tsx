'use client';
import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { track } from '@vercel/analytics/react';
import styles from './new.module.css';
import TEMPLATES, { type AgentTemplateIcon } from '@/lib/agent-templates';

const HERMES_TOOLS = [
  { name: 'web_search', label: 'Web search' },
  { name: 'terminal', label: 'Terminal' },
  { name: 'read_file', label: 'Read files' },
  { name: 'write_file', label: 'Write files' },
  { name: 'list_files', label: 'List files' },
  { name: 'grep_codebase', label: 'Search code' },
  { name: 'browser', label: 'Browser' },
  { name: 'delegate_task', label: 'Sub-agents' },
];

const PROVIDERS = [
  { key: 'ANTHROPIC_API_KEY', label: 'Anthropic' },
  { key: 'OPENAI_API_KEY', label: 'OpenAI' },
  { key: 'KIMI_API_KEY', label: 'Kimi' },
  { key: 'MOONSHOT_API_KEY', label: 'Moonshot' },
  { key: 'DEEPSEEK_API_KEY', label: 'DeepSeek' },
  { key: 'OPENROUTER_API_KEY', label: 'OpenRouter' },
  { key: 'XAI_API_KEY', label: 'xAI' },
] as const;

const MEMORY_OPTIONS = [
  { value: 'builtin', label: 'Built-in memory' },
  { value: 'none', label: 'Stateless' },
  { value: 'honcho', label: 'Honcho' },
  { value: 'mem0', label: 'Mem0' },
  { value: 'hindsight', label: 'Hindsight' },
];

type Step = 0 | 1 | 2;
interface EnvVar { key: string; value: string }

function TemplateIcon({ icon }: { icon: AgentTemplateIcon }) {
  const common = { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8 };
  if (icon === 'network') return <svg {...common}><circle cx="6" cy="12" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="m8 11 8-4M8 13l8 4"/></svg>;
  if (icon === 'target') return <svg {...common}><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M22 12h-3M12 22v-3M2 12h3"/></svg>;
  if (icon === 'key') return <svg {...common}><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8M15 8l2 2M17 6l2 2"/></svg>;
  if (icon === 'package') return <svg {...common}><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z"/><path d="m4.5 7.8 7.5 4.3 7.5-4.3M12 12v9"/></svg>;
  if (icon === 'api') return <svg {...common}><path d="M8 9 4 12l4 3M16 9l4 3-4 3M14 5l-4 14"/></svg>;
  return <svg {...common}><path d="M12 3 4 7v5c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10V7l-8-4Z"/><path d="m9 12 2 2 4-4"/></svg>;
}

export default function NewAgentPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>(0);
  const [templateId, setTemplateId] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedTools, setTools] = useState<string[]>(['read_file', 'grep_codebase']);
  const [memoryProvider, setMemoryProvider] = useState('builtin');
  const [maxDepth, setMaxDepth] = useState(2);
  const [ciProvider, setCiProvider] = useState<'github' | 'gitlab' | 'none'>('none');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [providerKey, setProviderKey] = useState<(typeof PROVIDERS)[number]['key']>('ANTHROPIC_API_KEY');
  const [apiKey, setApiKey] = useState('');
  const [extraEnv, setExtraEnv] = useState<EnvVar[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  function chooseTemplate(id: string) {
    const template = TEMPLATES.find(item => item.id === id);
    if (!template) return;
    setTemplateId(template.id);
    setName(template.name);
    setDescription(template.description);
    setTools(template.tools);
    setMemoryProvider(template.memoryProvider);
    setMaxDepth(template.maxDepth);
    track('Agent Template Selected', { template: template.id });
    setStep(1);
  }

  function startBlank() {
    setTemplateId('custom');
    setName('');
    setDescription('');
    setTools(['read_file', 'grep_codebase']);
    track('Agent Template Selected', { template: 'custom' });
    setStep(1);
  }

  function toggleTool(tool: string) {
    setTools(previous => previous.includes(tool) ? previous.filter(item => item !== tool) : [...previous, tool]);
  }

  function updateExtraEnv(index: number, field: keyof EnvVar, value: string) {
    setExtraEnv(previous => previous.map((item, itemIndex) => itemIndex === index ? { ...item, [field]: value } : item));
  }

  async function createAgent() {
    setSaving(true);
    setError('');
    try {
      const envVars = Object.fromEntries([
        ...extraEnv.filter(item => item.key.trim()).map(item => [item.key.trim(), item.value]),
        [providerKey, apiKey.trim()],
      ]);
      const response = await fetch('/api/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          description,
          tools: selectedTools.map(tool => ({ name: tool })),
          memoryProvider,
          maxDepth,
          ciProvider,
          envVars,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error === '__AGENT_LIMIT__' ? data.message : data.error || 'Unable to create agent');
      track('Agent Created', { template: templateId || 'custom', provider: providerKey });
      router.push(`/app/agents/${data.agent.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to create agent');
      setSaving(false);
    }
  }

  const selectedTemplate = TEMPLATES.find(item => item.id === templateId);
  const canContinue = name.trim().length >= 2 && selectedTools.length > 0;

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <Link href="/app/agents" className={styles.back}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m15 18-6-6 6-6"/></svg>
          AI Agents
        </Link>
        <h1>Create an agent</h1>
        <p>Start with a focused security job. You can tune and deploy it after creation.</p>
      </header>

      <nav className={styles.steps} aria-label="Agent setup progress">
        {['Choose a job', 'Confirm details', 'Connect provider'].map((label, index) => (
          <button
            key={label}
            type="button"
            disabled={index > step}
            className={`${styles.step} ${step === index ? styles.stepActive : ''} ${step > index ? styles.stepDone : ''}`}
            onClick={() => index < step && setStep(index as Step)}
          >
            <span>{step > index ? '✓' : index + 1}</span>{label}
          </button>
        ))}
      </nav>

      {step === 0 && (
        <section className={styles.panel}>
          <div className={styles.sectionHeading}>
            <div><h2>What should this agent protect?</h2><p>Each template starts with a focused tool set and safe defaults.</p></div>
          </div>
          <div className={styles.templateGrid}>
            {TEMPLATES.map(template => (
              <button key={template.id} type="button" className={styles.templateCard} onClick={() => chooseTemplate(template.id)}>
                <span className={styles.templateIcon}><TemplateIcon icon={template.icon} /></span>
                <span className={styles.templateContent}>
                  <strong>{template.name}</strong>
                  <span>{template.description}</span>
                </span>
                <svg className={styles.arrow} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m9 18 6-6-6-6"/></svg>
              </button>
            ))}
          </div>
          <button type="button" className={styles.textButton} onClick={startBlank}>Start with a blank agent</button>
        </section>
      )}

      {step === 1 && (
        <section className={styles.panel}>
          <div className={styles.sectionHeading}>
            <div><h2>Confirm the agent</h2><p>Keep the job narrow. Focused agents produce clearer findings.</p></div>
            {selectedTemplate && <span className={styles.templateLabel}>{selectedTemplate.name}</span>}
          </div>

          <div className={styles.fieldGrid}>
            <label><span>Name</span><input value={name} onChange={event => setName(event.target.value)} maxLength={80} autoFocus /></label>
            <label className={styles.fullField}><span>Description</span><textarea value={description} onChange={event => setDescription(event.target.value)} rows={3} maxLength={300} /></label>
          </div>

          {selectedTemplate && (
            <div className={styles.recommendedPrompt}>
              <span>Suggested first task</span>
              <p>{selectedTemplate.promptHint}</p>
            </div>
          )}

          <details className={styles.advanced} open={advancedOpen} onToggle={event => setAdvancedOpen(event.currentTarget.open)}>
            <summary>Advanced configuration</summary>
            <div className={styles.advancedBody}>
              <div className={styles.configGroup}>
                <span>Allowed tools</span>
                <div className={styles.toolGrid}>
                  {HERMES_TOOLS.map(tool => (
                    <label key={tool.name} className={selectedTools.includes(tool.name) ? styles.optionSelected : ''}>
                      <input type="checkbox" checked={selectedTools.includes(tool.name)} onChange={() => toggleTool(tool.name)} />
                      {tool.label}
                    </label>
                  ))}
                </div>
              </div>
              <div className={styles.configRow}>
                <label><span>Memory</span><select value={memoryProvider} onChange={event => setMemoryProvider(event.target.value)}>{MEMORY_OPTIONS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
                <label><span>Delegation depth</span><select value={maxDepth} onChange={event => setMaxDepth(Number(event.target.value))}><option value={1}>No sub-agents</option><option value={2}>Allow one level</option></select></label>
                <label><span>CI workflow</span><select value={ciProvider} onChange={event => setCiProvider(event.target.value as typeof ciProvider)}><option value="none">None</option><option value="github">GitHub Actions</option><option value="gitlab">GitLab CI</option></select></label>
              </div>
            </div>
          </details>

          {selectedTools.length === 0 && <p className={styles.warning}>Select at least one tool.</p>}
          <div className={styles.actions}><button className={styles.secondaryButton} onClick={() => setStep(0)}>Back</button><button className={styles.primaryButton} disabled={!canContinue} onClick={() => setStep(2)}>Connect provider</button></div>
        </section>
      )}

      {step === 2 && (
        <section className={styles.panel}>
          <div className={styles.sectionHeading}>
            <div><h2>Connect an AI provider</h2><p>This key is required when the agent runs. You can replace it later.</p></div>
          </div>

          <div className={styles.providerRow}>
            <label><span>Provider</span><select value={providerKey} onChange={event => setProviderKey(event.target.value as typeof providerKey)}>{PROVIDERS.map(provider => <option key={provider.key} value={provider.key}>{provider.label}</option>)}</select></label>
            <label className={styles.keyField}><span>API key</span><input type="password" value={apiKey} onChange={event => setApiKey(event.target.value)} placeholder="Paste provider key" autoComplete="off" /></label>
          </div>

          <details className={styles.advanced}>
            <summary>Additional environment variables</summary>
            <div className={styles.envList}>
              {extraEnv.map((item, index) => (
                <div key={index} className={styles.envRow}>
                  <input value={item.key} onChange={event => updateExtraEnv(index, 'key', event.target.value)} placeholder="VARIABLE_NAME" />
                  <input type="password" value={item.value} onChange={event => updateExtraEnv(index, 'value', event.target.value)} placeholder="value" />
                  <button type="button" aria-label="Remove variable" onClick={() => setExtraEnv(previous => previous.filter((_, itemIndex) => itemIndex !== index))}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 7h16M9 7V4h6v3M8 11v7M12 11v7M16 11v7M6 7l1 14h10l1-14"/></svg>
                  </button>
                </div>
              ))}
              <button type="button" className={styles.textButton} onClick={() => setExtraEnv(previous => [...previous, { key: '', value: '' }])}>Add variable</button>
            </div>
          </details>

          <div className={styles.review}>
            <div><span>Agent</span><strong>{name}</strong></div>
            <div><span>Tools</span><strong>{selectedTools.length}</strong></div>
            <div><span>Memory</span><strong>{MEMORY_OPTIONS.find(item => item.value === memoryProvider)?.label}</strong></div>
            <div><span>Deployment</span><strong>Draft first</strong></div>
          </div>

          {error && <p className={styles.error} role="alert">{error}</p>}
          {!apiKey.trim() && <p className={styles.warning}>Add a provider API key to create this agent.</p>}
          <div className={styles.actions}><button className={styles.secondaryButton} onClick={() => setStep(1)}>Back</button><button className={styles.primaryButton} disabled={!apiKey.trim() || saving} onClick={createAgent}>{saving ? 'Creating...' : 'Create agent'}</button></div>
        </section>
      )}
    </div>
  );
}
