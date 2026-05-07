'use client';

import { useEffect, useRef, useState } from 'react';

export default function ScrollProgress() {
  const [supportsTimeline, setSupportsTimeline] = useState(true);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    // Probe for CSS scroll-timeline support; if missing, fall back to JS scroll listener
    const supports = CSS.supports?.('animation-timeline: scroll(root)') ?? false;
    setSupportsTimeline(supports);

    if (supports) return;

    const el = ref.current;
    if (!el) return;
    let raf = 0;
    const onScroll = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        const max = document.documentElement.scrollHeight - window.innerHeight;
        const pct = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
        el.style.setProperty('--p', String(pct));
      });
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <div
      ref={ref}
      aria-hidden="true"
      className={supportsTimeline ? 'scroll-progress scroll-progress--css' : 'scroll-progress'}
    />
  );
}
