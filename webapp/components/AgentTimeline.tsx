'use client';

import { useEffect, useRef, useState } from 'react';
import type { NetworkEvent } from './AgentNetwork';
import styles from './AgentTimeline.module.css';

const stages = [
  { id: 'thinking', label: 'thinking' },
  { id: 'scanning', label: 'scanning' },
  { id: 'reading',  label: 'reading'  },
  { id: 'flagging', label: 'flagging' },
  { id: 'done',     label: 'done'     },
] as const;

type StageId = typeof stages[number]['id'];

const stageForEvent = (e: NetworkEvent): StageId => {
  switch (e.kind) {
    case 'pulse': {
      // map src/target prefix to stage so it feels purposeful
      const t = e.to;
      if (t.startsWith('a')) return 'scanning';
      if (t.startsWith('m')) return 'reading';
      if (t.startsWith('r')) return 'reading';
      return 'thinking';
    }
    case 'flash': return 'flagging';
    case 'tick':  return 'done';
  }
};

type Props = {
  event: NetworkEvent | null;
};

export default function AgentTimeline({ event }: Props) {
  const [active, setActive] = useState<StageId>('thinking');
  const [highlightedAt, setHighlightedAt] = useState<Record<StageId, number>>({
    thinking: 0, scanning: 0, reading: 0, flagging: 0, done: 0,
  });
  const cycleRef = useRef(0);

  // Drive the active pill from the live event stream
  useEffect(() => {
    if (!event) return;
    const stage = stageForEvent(event);
    setActive(stage);
    setHighlightedAt((prev) => ({ ...prev, [stage]: event.t }));
  }, [event]);

  // Idle ambient cycle so the row feels alive even when no events fire
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) return;
    const id = setInterval(() => {
      cycleRef.current = (cycleRef.current + 1) % stages.length;
      setActive((prev) => {
        // Don't override a fresh event-driven highlight
        const lastEventTs = Math.max(...Object.values(highlightedAt));
        if (Date.now() - lastEventTs < 1400) return prev;
        return stages[cycleRef.current].id;
      });
    }, 1900);
    return () => clearInterval(id);
  }, [highlightedAt]);

  return (
    <div className={styles.timeline} aria-label="Scan stages">
      <span className={styles.label}>scan</span>
      <ol className={styles.pills}>
        {stages.map((s, i) => (
          <li
            key={s.id}
            className={`${styles.pill} ${active === s.id ? styles.active : ''}`}
            data-stage={s.id}
          >
            <span className={styles.dot} />
            <span className={styles.text}>{s.label}</span>
            {i < stages.length - 1 && <span className={styles.connector} aria-hidden="true" />}
          </li>
        ))}
      </ol>
    </div>
  );
}
