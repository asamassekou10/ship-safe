import Nav from '@/components/Nav';
import Link from 'next/link';
import { posts } from '@/data/blog';
import CursorGlow from '@/components/CursorGlow';
import ScrollAnimator from '@/components/ScrollAnimator';
import styles from './blog.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/og2.png';

export const metadata: Metadata = {
  title: 'Blog',
  description: 'Security guides, vulnerability research, and best practices for developers. Learn how to find and fix security issues in your codebase.',
  keywords: ['application security blog', 'LLM vulnerability research', 'RAG poisoning prevention', 'MCP configuration security', 'AI agent security', 'DevSecOps blog', 'security best practices', 'code security guides'],
  alternates: {
    canonical: 'https://www.shipsafecli.com/blog',
  },
  openGraph: {
    title: 'Security guides for developers — Ship Safe Blog',
    description: 'Vulnerability research, supply chain deep-dives, and practical security advice from the Ship Safe team.',
    type: 'website',
    url: 'https://www.shipsafecli.com/blog',
    siteName: 'Ship Safe CLI',
    images: [{ url: ogImage, width: 1200, height: 628, alt: 'Ship Safe Blog' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Security guides for developers — Ship Safe Blog',
    description: 'Vulnerability research, supply chain deep-dives, and practical security advice from the Ship Safe team.',
    images: [ogImage],
  },
};

export default function Blog() {
  return (
    <>
      <ScrollAnimator />
      <Nav />
      <main className={styles.page}>
        {/* ── Hero ──────────────────────────────────── */}
        <section className={styles.hero}>
          <div className={styles.heroInner}>
            <span className={styles.sectionLabel}>// blog</span>
            <h1>
              Security guides, <span className={styles.gradientText}>vulnerability research,</span> and
              the latest from the field.
            </h1>
            <p>
              Practical security advice, supply-chain deep-dives, and what we&apos;re catching in the wild.
            </p>
          </div>
        </section>

        {/* ── Post grid ─────────────────────────────── */}
        <section className={styles.postSection}>
          <CursorGlow className={styles.postGrid}>
            {posts.map((post, i) => (
              <Link
                key={post.slug}
                href={`/blog/${post.slug}`}
                data-glow
                data-animate
                data-delay={String(i * 50)}
                className={styles.postCard}
              >
                <div className={styles.postTags}>
                  {post.tags.map((tag) => (
                    <span key={tag} className={styles.tag}>{tag}</span>
                  ))}
                </div>
                <h2 className={styles.postTitle}>{post.title}</h2>
                <p className={styles.postDesc}>{post.description}</p>
                <div className={styles.postMeta}>
                  <span>{post.author}</span>
                  <span className={styles.tabular}>
                    {new Date(post.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                  </span>
                </div>
              </Link>
            ))}
          </CursorGlow>
        </section>
      </main>
    </>
  );
}
