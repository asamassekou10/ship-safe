'use client';

import Link from 'next/link';
import { useState } from 'react';
import { track } from '@vercel/analytics/react';
import styles from './post.module.css';

export default function BlogFooterCta({ slug }: { slug: string }) {
  const [copied, setCopied] = useState(false);

  async function copyCommand() {
    await navigator.clipboard.writeText('npx ship-safe audit .');
    setCopied(true);
    track('Command Copied', { source: 'blog_footer', slug });
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <div className={styles.cta}>
      <h3>Scan your project now</h3>
      <button type="button" className={styles.ctaCodeButton} onClick={copyCommand}>
        <code>npx ship-safe audit .</code>
        <span>{copied ? 'Copied' : 'Copy'}</span>
      </button>
      <p>29 agents. 80+ attack classes. Free and open source.</p>
      <div className={styles.ctaLinks}>
        <a
          href="https://github.com/asamassekou10/ship-safe"
          className="btn btn-primary"
          onClick={() => track('Blog CTA Clicked', { item: 'github', slug })}
        >
          View on GitHub
        </a>
        <a
          href="https://github.com/asamassekou10/ship-safe/contribute"
          className="btn btn-ghost"
          onClick={() => track('Blog CTA Clicked', { item: 'contribute', slug })}
        >
          Contribute
        </a>
        <Link
          href="/pricing"
          className="btn btn-ghost"
          onClick={() => track('Blog CTA Clicked', { item: 'pricing', slug })}
        >
          See pricing
        </Link>
      </div>
    </div>
  );
}
