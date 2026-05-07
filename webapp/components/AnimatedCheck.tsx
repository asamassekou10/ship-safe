'use client';

import { useEffect, useRef, useState } from 'react';

type Variant = 'check' | 'cross';

type Props = {
  variant?: Variant;
  size?: number;
  delay?: number;
  className?: string;
};

export default function AnimatedCheck({ variant = 'check', size = 14, delay = 0, className }: Props) {
  const ref = useRef<SVGSVGElement>(null);
  const [drawn, setDrawn] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      setDrawn(true);
      return;
    }
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            setTimeout(() => setDrawn(true), delay);
            obs.disconnect();
          }
        });
      },
      { threshold: 0.6 }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [delay]);

  const path = variant === 'check' ? 'M5 13l4 4L19 7' : 'M6 6l12 12M18 6L6 18';

  return (
    <svg
      ref={ref}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={3}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path
        d={path}
        style={{
          strokeDasharray: 36,
          strokeDashoffset: drawn ? 0 : 36,
          transition: 'stroke-dashoffset 0.55s cubic-bezier(0.65, 0, 0.35, 1)',
        }}
      />
    </svg>
  );
}
