'use client';

import { useEffect, useRef, useState } from 'react';
import LazyVideo from './LazyVideo';
import styles from './IntelScrolly.module.css';

const steps = [
  {
    label: 'Fresh signal',
    title: 'New CVE in your Docker setup.',
    body: 'Ship Safe ingests advisories, vendor blogs, Hacker News, and security feeds the moment they break — not the next morning.',
  },
  {
    label: 'Ranked',
    title: 'Three advisories match repos you scanned this week.',
    body: 'Generic feeds bury what matters. We rank against your repos, dependencies, and recent scans — so the top of the list is the top of your worry list.',
  },
  {
    label: 'Action',
    title: 'Patch path generated, ready to open as a PR.',
    body: 'Each ranked signal turns into a concrete next step: a remediation snippet, a rotation checklist, or a one-click PR through Hermes.',
  },
];

export default function IntelScrolly() {
  const [active, setActive] = useState(0);
  const stepRefs = useRef<(HTMLDivElement | null)[]>([]);

  useEffect(() => {
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            const idx = Number((e.target as HTMLElement).dataset.step);
            if (!Number.isNaN(idx)) setActive(idx);
          }
        });
      },
      { rootMargin: '-40% 0px -40% 0px', threshold: 0 }
    );
    stepRefs.current.forEach((el) => el && obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <section className={styles.section}>
      <div className={styles.inner}>
        <div className={styles.copy}>
          <div className={styles.intro}>
            <span className={styles.label}>// 03 — intelligence</span>
            <h2>Security news becomes app-specific action.</h2>
            <p>
              Ship Safe turns fresh incidents, CVEs, and social signals into ranked next steps for
              your own application — not a generic feed you have to triage yourself.
            </p>
          </div>

          <div className={styles.steps}>
            {steps.map((step, i) => (
              <div
                key={step.label}
                data-step={i}
                ref={(el) => { stepRefs.current[i] = el; }}
                className={`${styles.step} ${active === i ? styles.stepActive : ''}`}
              >
                <span className={styles.stepRail} aria-hidden="true">
                  <i />
                </span>
                <div className={styles.stepBody}>
                  <span className={styles.stepLabel}>{step.label}</span>
                  <strong>{step.title}</strong>
                  <p>{step.body}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className={styles.mediaWrap}>
          <div className={styles.media}>
            <div className={styles.mediaFrame}>
              <LazyVideo
                src="/demo%20app%20intelligence.mov"
                poster="/app%20intelligence.png"
                className={styles.video}
                ariaLabel="Ship Safe Security Intelligence demo"
              />
              <div className={styles.mediaProgress} aria-hidden="true">
                {steps.map((_, i) => (
                  <span key={i} className={i <= active ? styles.progressOn : ''} />
                ))}
              </div>
            </div>
            <div className={styles.mediaCaption}>
              <span>{steps[active].label}</span>
              <strong>{steps[active].title}</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
