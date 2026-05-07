'use client';

import { useEffect, useRef, useState } from 'react';
import NumberFlow from '@number-flow/react';

type Props = { value: number; suffix?: string; compact?: boolean };

export default function StatsCounter({ value, suffix = '', compact = false }: Props) {
  const [shown, setShown] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const startedRef = useRef(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const el = ref.current;
    if (!el) return;

    const reveal = () => {
      if (startedRef.current) return;
      startedRef.current = true;
      setShown(value);
    };

    if (reduced) {
      reveal();
      return;
    }

    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            reveal();
            obs.disconnect();
          }
        });
      },
      { threshold: 0.4 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [value]);

  return (
    <span ref={ref}>
      <NumberFlow value={shown} format={compact ? { notation: 'compact' } : undefined} />
      {suffix}
    </span>
  );
}
