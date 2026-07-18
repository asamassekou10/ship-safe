'use client';

import { useEffect, useRef, useState } from 'react';
import { useReducedMotion } from 'motion/react';
import styles from './HomeRedesign.module.css';

export function CommandType({ command, delay = 160 }: { command: string; delay?: number }) {
  const ref = useRef<HTMLElement>(null);
  const [visibleCommand, setVisibleCommand] = useState('');
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    if (reduceMotion) {
      setVisibleCommand(command);
      return;
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    let typingTimer: ReturnType<typeof setInterval> | undefined;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        observer.disconnect();
        timer = setTimeout(() => {
          let index = 0;
          typingTimer = setInterval(() => {
            index += 1;
            setVisibleCommand(command.slice(0, index));
            if (index >= command.length && typingTimer) clearInterval(typingTimer);
          }, 16);
        }, delay);
      },
      { threshold: 0.45 },
    );

    observer.observe(element);
    return () => {
      observer.disconnect();
      if (timer) clearTimeout(timer);
      if (typingTimer) clearInterval(typingTimer);
    };
  }, [command, delay, reduceMotion]);

  return (
    <code ref={ref} className={styles.typedCommand} aria-label={command}>
      <span aria-hidden="true">{visibleCommand}</span>
      <i aria-hidden="true" />
    </code>
  );
}

export function StatusSequence({
  items,
  tone = 'cyan',
}: {
  items: string[];
  tone?: 'cyan' | 'risk' | 'success';
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(0);
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    const element = ref.current;
    if (!element || reduceMotion) {
      setActive(items.length - 1);
      return;
    }

    let sequenceTimer: ReturnType<typeof setInterval> | undefined;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        observer.disconnect();
        let index = 0;
        sequenceTimer = setInterval(() => {
          index += 1;
          setActive(Math.min(index, items.length - 1));
          if (index >= items.length - 1 && sequenceTimer) clearInterval(sequenceTimer);
        }, 720);
      },
      { threshold: 0.5 },
    );

    observer.observe(element);
    return () => {
      observer.disconnect();
      if (sequenceTimer) clearInterval(sequenceTimer);
    };
  }, [items.length, reduceMotion]);

  return (
    <div
      ref={ref}
      className={`${styles.statusSequence} ${styles[`status_${tone}`]}`}
      role="img"
      aria-label={items.join(', then ')}
    >
      {items.map((item, index) => (
        <span key={item} className={index <= active ? styles.statusComplete : undefined}>
          <i aria-hidden="true" />
          {item}
        </span>
      ))}
    </div>
  );
}
