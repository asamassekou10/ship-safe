'use client';

import { useEffect, useRef } from 'react';

type Props = {
  children: React.ReactNode;
  className?: string;
};

export default function CursorGlow({ children, className }: Props) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) return;

    let raf = 0;
    let pending: { el: HTMLElement; x: number; y: number } | null = null;

    const flush = () => {
      raf = 0;
      if (pending) {
        pending.el.style.setProperty('--mx', `${pending.x}px`);
        pending.el.style.setProperty('--my', `${pending.y}px`);
        pending = null;
      }
    };

    const onMove = (e: MouseEvent) => {
      const target = (e.target as HTMLElement | null)?.closest<HTMLElement>('[data-glow]');
      if (!target) return;
      const rect = target.getBoundingClientRect();
      pending = { el: target, x: e.clientX - rect.left, y: e.clientY - rect.top };
      if (!raf) raf = requestAnimationFrame(flush);
    };

    root.addEventListener('mousemove', onMove);
    return () => {
      root.removeEventListener('mousemove', onMove);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <div ref={ref} className={className}>
      {children}
    </div>
  );
}
