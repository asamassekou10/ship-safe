'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import styles from './content-agent.module.css';

export default function ContentAgentControls() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [settingUp, setSettingUp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [hermesAgent, setHermesAgent] = useState<{ id: string; status: string; deployments?: Array<{ status: string; port: number | null }> } | null>(null);

  useEffect(() => {
    fetch('/api/content-agent/hermes/setup')
      .then((res) => res.ok ? res.json() : null)
      .then((data) => setHermesAgent(data?.agent ?? null))
      .catch(() => {});
  }, []);

  async function runAgent() {
    setRunning(true);
    setError(null);
    setNotice(null);

    try {
      const res = await fetch('/api/content-agent/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'draft',
          ...(hermesAgent?.deployments?.[0]?.status === 'running' ? { hermesAgentId: hermesAgent.id } : {}),
        }),
      });

      const data = await res.json() as {
        error?: string;
        result?: { status?: string; candidateCount?: number; selectedCount?: number; guardrails?: string[]; post?: { title?: string } };
      };
      if (!res.ok) throw new Error(data.error ?? 'Content agent failed');
      if (data.result?.status === 'skipped') {
        setNotice(data.result.guardrails?.[0] ?? `Scanned ${data.result.candidateCount ?? 0} candidates, but no draft passed guardrails.`);
      } else {
        setNotice(data.result?.post?.title ? `Draft created: ${data.result.post.title}` : 'Discovery run complete.');
      }
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Content agent failed');
    } finally {
      setRunning(false);
    }
  }

  async function setupHermesAgent() {
    setSettingUp(true);
    setError(null);
    setNotice(null);

    try {
      const res = await fetch('/api/content-agent/hermes/setup', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Failed to set up Hermes agent');
      setHermesAgent(data.agent);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to set up Hermes agent');
    } finally {
      setSettingUp(false);
    }
  }

  return (
    <div className={styles.controls}>
      <button className={styles.primaryButton} onClick={runAgent} disabled={running}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
        </svg>
        {running ? 'Running...' : 'Run discovery'}
      </button>
      {hermesAgent ? (
        <a className={styles.secondaryButton} href={`/app/agents/${hermesAgent.id}`} title="Open Hermes content agent">
          Hermes: {hermesAgent.deployments?.[0]?.status === 'running' ? 'Live' : 'Ready'}
        </a>
      ) : (
        <button className={styles.secondaryButton} onClick={setupHermesAgent} disabled={settingUp}>
          {settingUp ? 'Setting up...' : 'Set up Hermes'}
        </button>
      )}
      {error && <span className={styles.errorText}>{error}</span>}
      {notice && <span className={styles.noticeText}>{notice}</span>}
    </div>
  );
}
