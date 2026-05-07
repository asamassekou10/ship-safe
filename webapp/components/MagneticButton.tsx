'use client';

import { useEffect, useRef } from 'react';

type Props = {
  children: React.ReactNode;
  className?: string;
  /** Maximum pixel offset the child translates to (clamped). Default 8. */
  strength?: number;
  /** Activation radius in pixels around the element. Default 90. */
  radius?: number;
};

/**
 * Wraps a single interactive child (button/link) and translates it toward the
 * cursor when the cursor is within `radius` of the element. Spring back when
 * the cursor leaves. Disabled under prefers-reduced-motion.
 */
export default function MagneticButton({ children, className, strength = 8, radius = 90 }: Props) {
  const wrapRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) return;

    const child = wrap.firstElementChild as HTMLElement | null;
    if (!child) return;

    let raf = 0;
    let target = { x: 0, y: 0 };
    let current = { x: 0, y: 0 };

    const tick = () => {
      raf = 0;
      // Lerp current → target
      current.x += (target.x - current.x) * 0.18;
      current.y += (target.y - current.y) * 0.18;
      child.style.transform = `translate3d(${current.x}px, ${current.y}px, 0)`;
      if (Math.abs(target.x - current.x) > 0.05 || Math.abs(target.y - current.y) > 0.05) {
        raf = requestAnimationFrame(tick);
      }
    };

    const onMove = (e: MouseEvent) => {
      const rect = wrap.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dx = e.clientX - cx;
      const dy = e.clientY - cy;
      const dist = Math.hypot(dx, dy);
      if (dist > radius) {
        target = { x: 0, y: 0 };
      } else {
        const pull = 1 - dist / radius;
        target = {
          x: Math.max(-strength, Math.min(strength, dx * pull * 0.35)),
          y: Math.max(-strength, Math.min(strength, dy * pull * 0.35)),
        };
      }
      if (!raf) raf = requestAnimationFrame(tick);
    };

    const onLeave = () => {
      target = { x: 0, y: 0 };
      if (!raf) raf = requestAnimationFrame(tick);
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseout', onLeave);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseout', onLeave);
      if (raf) cancelAnimationFrame(raf);
      child.style.transform = '';
    };
  }, [strength, radius]);

  return (
    <span ref={wrapRef} className={className} style={{ display: 'inline-flex' }}>
      {children}
    </span>
  );
}
