'use client';

import { useState, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { track } from '@vercel/analytics/react';
import styles from './page.module.css';

type Goal = 'scan' | 'agent' | 'guardian';

const goals: Array<{ id: Goal; title: string; description: string; href: string; meta: string; icon: ReactNode }> = [
  {
    id: 'scan',
    title: 'Scan a repository',
    description: 'Find secrets, vulnerable dependencies, and exploitable code paths.',
    href: '/app/scan',
    meta: 'Fastest path to your first result',
    icon: <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
  },
  {
    id: 'agent',
    title: 'Secure an AI agent',
    description: 'Configure tools, memory, permissions, and deployment safeguards.',
    href: '/app/agents/new',
    meta: 'For Hermes and tool-using agents',
    icon: <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="7" width="16" height="13" rx="3"/><path d="M9 3h6M12 3v4M8 12h.01M16 12h.01M8 16h8"/></svg>,
  },
  {
    id: 'guardian',
    title: 'Protect pull requests',
    description: 'Review changes, diagnose failures, and apply guarded fixes before merge.',
    href: '/app/guardian',
    meta: 'For continuous GitHub protection',
    icon: <svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>,
  },
];

export default function GoalPicker() {
  const router = useRouter();
  const [loading, setLoading] = useState<Goal | 'skip' | null>(null);
  const [error, setError] = useState('');

  async function choose(goal: Goal | null, href: string) {
    setLoading(goal ?? 'skip');
    setError('');
    const response = await fetch('/api/onboarding', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ goal }),
    });

    if (!response.ok) {
      setLoading(null);
      setError('We could not save your choice. Please try again.');
      return;
    }

    track('Onboarding Goal Selected', { goal: goal ?? 'skip' });
    router.push(href);
  }

  return (
    <div className={styles.goalArea}>
      <div className={styles.goals}>
        {goals.map((goal, index) => (
          <button key={goal.id} type="button" className={`${styles.goal} ${index === 0 ? styles.goalPrimary : ''}`} onClick={() => choose(goal.id, goal.href)} disabled={loading !== null}>
            <span className={styles.goalIcon}>{goal.icon}</span>
            <span className={styles.goalCopy}>
              <strong>{goal.title}</strong>
              <span>{goal.description}</span>
              <small>{goal.meta}</small>
            </span>
            <span className={styles.goalArrow}>{loading === goal.id ? '...' : '→'}</span>
          </button>
        ))}
      </div>
      {error && <p className={styles.error}>{error}</p>}
      <button type="button" className={styles.skip} onClick={() => choose(null, '/app')} disabled={loading !== null}>
        {loading === 'skip' ? 'Opening workspace...' : 'Explore the workspace first'}
      </button>
    </div>
  );
}
