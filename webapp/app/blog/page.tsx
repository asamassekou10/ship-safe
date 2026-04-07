import Nav from '@/components/Nav';
import Link from 'next/link';
import { posts } from '@/data/blog';
import styles from './blog.module.css';
import type { Metadata } from 'next';

const ogImage = 'https://www.shipsafecli.com/api/og?title=Security+Guides+for+Developers&description=Vulnerability+research%2C+supply+chain+deep-dives%2C+and+practical+security+advice+from+the+Ship+Safe+team.&label=Blog';

export const metadata: Metadata = {
  title: 'Blog',
  description: 'Security guides, vulnerability research, and best practices for developers. Learn how to find and fix security issues in your codebase.',
  keywords: ['application security blog', 'LLM vulnerability research', 'RAG poisoning prevention', 'MCP configuration security', 'AI agent security', 'DevSecOps blog', 'security best practices', 'code security guides'],
  alternates: {
    canonical: 'https://www.shipsafecli.com/blog',
  },
  openGraph: {
    title: 'Security Guides for Developers — Ship Safe Blog',
    description: 'Vulnerability research, supply chain deep-dives, and practical security advice from the Ship Safe team.',
    url: 'https://www.shipsafecli.com/blog',
    images: [{ url: ogImage, width: 1200, height: 630, alt: 'Ship Safe Blog' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Security Guides for Developers — Ship Safe Blog',
    description: 'Vulnerability research, supply chain deep-dives, and practical security advice from the Ship Safe team.',
    images: [ogImage],
  },
};

export default function Blog() {
  return (
    <>
      <Nav />
      <main className={styles.blogPage}>
        <div className="container">
          <section className={styles.hero}>
            <span className="section-label">Blog</span>
            <h1>Security guides for developers</h1>
            <p className="section-sub">
              Practical security advice, vulnerability research, and best practices from the Ship Safe team.
            </p>
          </section>

          <section className={styles.postGrid}>
            {posts.map((post) => (
              <Link key={post.slug} href={`/blog/${post.slug}`} className={styles.postCard}>
                <div className={styles.postTags}>
                  {post.tags.map((tag) => (
                    <span key={tag} className={styles.tag}>{tag}</span>
                  ))}
                </div>
                <h2 className={styles.postTitle}>{post.title}</h2>
                <p className={styles.postDesc}>{post.description}</p>
                <div className={styles.postMeta}>
                  <span>{post.author}</span>
                  <span>{new Date(post.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
                </div>
              </Link>
            ))}
          </section>
        </div>
      </main>
    </>
  );
}
