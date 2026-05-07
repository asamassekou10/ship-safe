'use client';

import { useEffect, useRef } from 'react';

type Props = {
  src: string;
  poster?: string;
  className?: string;
  ariaLabel?: string;
};

export default function LazyVideo({ src, poster, className, ariaLabel }: Props) {
  const ref = useRef<HTMLVideoElement>(null);
  const loadedRef = useRef(false);

  useEffect(() => {
    const video = ref.current;
    if (!video) return;

    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            if (!loadedRef.current) {
              video.src = src;
              loadedRef.current = true;
            }
            video.play().catch(() => {});
          } else {
            video.pause();
          }
        });
      },
      { threshold: 0.4 }
    );
    obs.observe(video);
    return () => obs.disconnect();
  }, [src]);

  return (
    <video
      ref={ref}
      className={className}
      poster={poster}
      muted
      loop
      playsInline
      preload="none"
      aria-label={ariaLabel}
    />
  );
}
