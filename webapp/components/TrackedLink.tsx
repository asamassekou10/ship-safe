'use client';

import Link from 'next/link';
import { track } from '@vercel/analytics/react';
import type { AnchorHTMLAttributes, MouseEventHandler, ReactNode } from 'react';

type Props = AnchorHTMLAttributes<HTMLAnchorElement> & {
  href: string;
  event: string;
  payload?: Record<string, string | number | boolean>;
  children: ReactNode;
};

export default function TrackedLink({ href, event, payload, children, onClick, ...props }: Props) {
  const handleClick: MouseEventHandler<HTMLAnchorElement> = (clickEvent) => {
    track(event, payload);
    onClick?.(clickEvent);
  };

  const isExternal = /^https?:\/\//.test(href) || href.startsWith('mailto:');

  if (isExternal) {
    return (
      <a href={href} onClick={handleClick} {...props}>
        {children}
      </a>
    );
  }

  return (
    <Link href={href} onClick={handleClick} {...props}>
      {children}
    </Link>
  );
}
