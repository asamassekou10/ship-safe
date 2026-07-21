'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { track } from '@vercel/analytics/react';
import styles from './onboarding.module.css';

interface Props {
  hasScanned: boolean;
  hasMonitoredRepo: boolean;
  hasSlack: boolean;
  hasTeam: boolean;
}

const DISMISS_KEY = 'shipsafe_onboarding_dismissed';

export default function OnboardingChecklist({ hasScanned, hasMonitoredRepo, hasSlack, hasTeam }: Props) {
  const [dismissed, setDismissed] = useState(true);

  useEffect(() => {
    setDismissed(localStorage.getItem(DISMISS_KEY) === '1');
  }, []);

  const steps = [
    { id: 'scan',  label: 'Run your first scan',     desc: 'Scan a repo and see your security score',              href: '/app/scan',     done: hasScanned },
    { id: 'repo',  label: 'Monitor a repository',    desc: 'Set up automatic scheduled scans',                     href: '/app/repos',    done: hasMonitoredRepo },
    { id: 'slack', label: 'Connect Slack',           desc: 'Get notified when scans finish or find critical issues', href: '/app/settings', done: hasSlack },
    { id: 'team',  label: 'Invite a teammate',       desc: 'Share scans and collaborate on fixes',                  href: '/app/team',     done: hasTeam },
  ];

  const completed = steps.filter(s => s.done).length;
  const nextStep = steps.find(step => !step.done);

  function dismiss() {
    localStorage.setItem(DISMISS_KEY, '1');
    setDismissed(true);
  }

  if (dismissed || completed === steps.length || !nextStep) return null;

  return (
    <div className={styles.checklist}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <span className={styles.title}>Recommended next step</span>
          <div className={styles.progressRow}>
            <div className={styles.progressTrack}>
              <div className={styles.progressFill} style={{ width: `${(completed / steps.length) * 100}%` }} />
            </div>
            <span className={styles.progressText}>{completed} of {steps.length}</span>
          </div>
        </div>
        <button className={styles.dismissBtn} onClick={dismiss} aria-label="Dismiss checklist">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M18 6L6 18M6 6l12 12"/></svg>
        </button>
      </div>
      <Link href={nextStep.href} className={styles.nextStep} onClick={() => track('Onboarding Next Step Clicked', { step: nextStep.id })}>
        <div className={styles.nextStepNumber}>{completed + 1}</div>
        <div className={styles.stepBody}>
          <div className={styles.stepLabel}>{nextStep.label}</div>
          <div className={styles.stepDesc}>{nextStep.desc}</div>
        </div>
        <span className={styles.nextAction}>Continue</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={styles.arrow}><path d="M9 18l6-6-6-6"/></svg>
      </Link>
    </div>
  );
}
