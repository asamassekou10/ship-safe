import Nav from '@/components/Nav';
import Link from 'next/link';
import { posts, getPostBySlug, getAllSlugs } from '@/data/blog';
import styles from './post.module.css';
import ShareButtons from './ShareButtons';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

interface Props {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  return getAllSlugs().map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) return {};

  const ogImageUrl = `https://shipsafecli.com/api/og/blog?slug=${post.slug}`;

  return {
    title: post.title,
    description: post.description,
    keywords: post.keywords,
    alternates: {
      canonical: `https://shipsafecli.com/blog/${post.slug}`,
    },
    openGraph: {
      title: post.title,
      description: post.description,
      type: 'article',
      url: `https://shipsafecli.com/blog/${post.slug}`,
      siteName: 'Ship Safe',
      publishedTime: post.date,
      authors: [post.author],
      tags: post.tags,
      images: [{ url: ogImageUrl, width: 1200, height: 630, alt: post.title }],
    },
    twitter: {
      card: 'summary_large_image',
      title: post.title,
      description: post.description,
      images: [ogImageUrl],
    },
  };
}

function renderContent(content: string) {
  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Code blocks
    if (line.startsWith('```')) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      elements.push(
        <pre key={elements.length} className={styles.codeBlock} data-lang={lang || undefined}>
          <code>{codeLines.join('\n')}</code>
        </pre>
      );
      continue;
    }

    // Headings
    if (line.startsWith('## ')) {
      elements.push(<h2 key={elements.length} className={styles.h2}>{line.slice(3)}</h2>);
      i++;
      continue;
    }
    if (line.startsWith('### ')) {
      elements.push(<h3 key={elements.length} className={styles.h3}>{line.slice(4)}</h3>);
      i++;
      continue;
    }

    // Tables
    if (line.includes('|') && line.trim().startsWith('|')) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i].includes('|') && lines[i].trim().startsWith('|')) {
        tableLines.push(lines[i]);
        i++;
      }
      const headerCells = tableLines[0].split('|').filter(Boolean).map((c) => c.trim());
      const bodyRows = tableLines.slice(2); // skip header + separator
      elements.push(
        <div key={elements.length} className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>{headerCells.map((c, j) => <th key={j}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {bodyRows.map((row, ri) => {
                const cells = row.split('|').filter(Boolean).map((c) => c.trim());
                return <tr key={ri}>{cells.map((c, j) => <td key={j}>{c}</td>)}</tr>;
              })}
            </tbody>
          </table>
        </div>
      );
      continue;
    }

    // List items
    if (line.startsWith('- ')) {
      const items: string[] = [];
      while (i < lines.length && lines[i].startsWith('- ')) {
        items.push(lines[i].slice(2));
        i++;
      }
      elements.push(
        <ul key={elements.length} className={styles.list}>
          {items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}
        </ul>
      );
      continue;
    }

    // Empty line
    if (line.trim() === '') {
      i++;
      continue;
    }

    // Paragraph
    elements.push(<p key={elements.length} className={styles.paragraph}>{renderInline(line)}</p>);
    i++;
  }

  return elements;
}

function renderInline(text: string): React.ReactNode {
  // Handle bold, inline code, and links
  const parts: React.ReactNode[] = [];
  let remaining = text;
  let key = 0;

  while (remaining.length > 0) {
    // Bold
    const boldMatch = remaining.match(/\*\*(.+?)\*\*/);
    // Inline code
    const codeMatch = remaining.match(/`(.+?)`/);
    // Link
    const linkMatch = remaining.match(/\[(.+?)\]\((.+?)\)/);

    const matches = [
      boldMatch && { type: 'bold', index: boldMatch.index!, match: boldMatch },
      codeMatch && { type: 'code', index: codeMatch.index!, match: codeMatch },
      linkMatch && { type: 'link', index: linkMatch.index!, match: linkMatch },
    ].filter(Boolean).sort((a, b) => a!.index - b!.index);

    if (matches.length === 0) {
      parts.push(remaining);
      break;
    }

    const first = matches[0]!;
    if (first.index > 0) {
      parts.push(remaining.slice(0, first.index));
    }

    if (first.type === 'bold') {
      parts.push(<strong key={key++}>{first.match![1]}</strong>);
      remaining = remaining.slice(first.index + first.match![0].length);
    } else if (first.type === 'code') {
      parts.push(<code key={key++} className={styles.inlineCode}>{first.match![1]}</code>);
      remaining = remaining.slice(first.index + first.match![0].length);
    } else if (first.type === 'link') {
      parts.push(<a key={key++} href={first.match![2]} className={styles.link}>{first.match![1]}</a>);
      remaining = remaining.slice(first.index + first.match![0].length);
    }
  }

  return parts.length === 1 ? parts[0] : parts;
}

export default async function BlogPost({ params }: Props) {
  const { slug } = await params;
  const post = getPostBySlug(slug);
  if (!post) notFound();

  const morePosts = posts.filter((p) => p.slug !== slug).slice(0, 3);
  const postUrl = `https://shipsafecli.com/blog/${post.slug}`;

  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: post.title,
    description: post.description,
    datePublished: post.date,
    dateModified: post.date,
    image: `https://shipsafecli.com/api/og/blog?slug=${post.slug}`,
    author: {
      '@type': 'Person',
      name: post.author,
      url: 'https://shipsafecli.com',
    },
    publisher: {
      '@type': 'Organization',
      name: 'Ship Safe',
      url: 'https://shipsafecli.com',
      logo: {
        '@type': 'ImageObject',
        url: 'https://shipsafecli.com/logo.png',
      },
    },
    mainEntityOfPage: {
      '@type': 'WebPage',
      '@id': `https://shipsafecli.com/blog/${post.slug}`,
    },
    keywords: post.keywords.join(', '),
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} // ship-safe-ignore — static JSON-LD, no user input
      />
      <Nav />
      <main className={styles.postPage}>
        <article className={styles.article}>
          <header className={styles.header}>
            <Link href="/blog" className={styles.backLink}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M19 12H5M12 19l-7-7 7-7" />
              </svg>
              All posts
            </Link>
            <div className={styles.postTags}>
              {post.tags.map((tag) => (
                <span key={tag} className={styles.tag}>{tag}</span>
              ))}
            </div>
            <h1 className={styles.title}>{post.title}</h1>
            <div className={styles.meta}>
              <span>{post.author}</span>
              <span>{new Date(post.date).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}</span>
            </div>
            <ShareButtons title={post.title} url={postUrl} />
          </header>

          <div className={styles.content}>
            {renderContent(post.content)}
          </div>

          <footer className={styles.footer}>
            <ShareButtons title={post.title} url={postUrl} />
            <div className={styles.cta}>
              <h3>Scan your project now</h3>
              <pre className={styles.ctaCode}><code>npx ship-safe audit .</code></pre>
              <p>23 agents. 80+ attack classes. Free and open source.</p>
              <div className={styles.ctaLinks}>
                <a href="https://github.com/asamassekou10/ship-safe" className="btn btn-primary">View on GitHub</a>
                <Link href="/pricing" className="btn btn-ghost">See pricing</Link>
              </div>
            </div>

            {morePosts.length > 0 && (
              <div className={styles.morePosts}>
                <h3>More from the blog</h3>
                <ul className={styles.moreList}>
                  {morePosts.map((p) => (
                    <li key={p.slug}>
                      <Link href={`/blog/${p.slug}`} className={styles.moreLink}>
                        <span className={styles.moreLinkTitle}>{p.title}</span>
                        <span className={styles.moreLinkDate}>
                          {new Date(p.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
                <Link href="/blog" className={styles.allPostsLink}>All posts →</Link>
              </div>
            )}
          </footer>
        </article>
      </main>
    </>
  );
}
