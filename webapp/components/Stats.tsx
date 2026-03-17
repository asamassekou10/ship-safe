'use client';
import { useEffect, useRef } from 'react';
import styles from './Stats.module.css';

function easeOut(t: number) { return 1 - Math.pow(1 - t, 3); }

function animateCounter(el: HTMLElement) {
  const target = parseInt(el.dataset.target || '0');
  const suffix = el.dataset.suffix || '';
  const prefix = el.dataset.prefix || '';
  const duration = 1200;
  const start = performance.now();

  function setCounter(value: string | number, sfx: string, pfx: string) {
    el.textContent = '';
    if (pfx) el.appendChild(document.createTextNode(pfx));
    const span = document.createElement('span');
    span.textContent = String(value);
    el.appendChild(span);
    if (sfx) el.appendChild(document.createTextNode(sfx));
  }

  if (target === 0) {
    setCounter(prefix ? '5' : '0', suffix, prefix);
    return;
  }

  function tick(now: number) {
    const progress = Math.min((now - start) / duration, 1);
    const value = Math.round(easeOut(progress) * target);
    setCounter(value, suffix, '');
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

export default function Stats() {
  const barRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const bar = barRef.current;
    if (!bar) return;
    const obs = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          bar.querySelectorAll<HTMLElement>('[data-target]').forEach(animateCounter);
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });
    obs.observe(bar);
    return () => obs.disconnect();
  }, []);

  return (
    <section className={styles.statsSection}>
      <div className="container">
        <div className={`${styles.statsBar} card`} ref={barRef} data-animate>
          <div className={styles.stat}>
            <span className={styles.statNum} data-target="16">0</span>
            <span className={styles.statLabel}>Security agents</span>
          </div>
          <div className={styles.statSep} aria-hidden="true" />
          <div className={styles.stat}>
            <span className={styles.statNum} data-target="80" data-suffix="+">0</span>
            <span className={styles.statLabel}>Attack classes</span>
          </div>
          <div className={styles.statSep} aria-hidden="true" />
          <div className={styles.stat}>
            <span className={styles.statNum} data-target="5">0</span>
            <span className={styles.statLabel}>OWASP standards</span>
          </div>
          <div className={styles.statSep} aria-hidden="true" />
          <div className={styles.stat}>
            <span className={styles.statNum} data-target="0" data-prefix="<" data-suffix="5s">0</span>
            <span className={styles.statLabel}>To run</span>
          </div>
        </div>
      </div>
    </section>
  );
}
