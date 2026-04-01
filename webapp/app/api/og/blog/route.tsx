import { ImageResponse } from 'next/og';
import { getPostBySlug } from '@/data/blog';

export const runtime = 'edge';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const slug = searchParams.get('slug') ?? '';

  const post = getPostBySlug(slug);

  const title = post?.title ?? 'Ship Safe Blog';
  const description = post?.description ?? 'Security guides for developers.';
  const tags = post?.tags ?? [];
  const date = post?.date
    ? new Date(post.date).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
    : '';

  // Truncate long titles for the card
  const displayTitle = title.length > 72 ? title.slice(0, 72).trimEnd() + '…' : title;
  const displayDesc = description.length > 120 ? description.slice(0, 120).trimEnd() + '…' : description;

  return new ImageResponse(
    (
      <div
        style={{
          width: '1200px',
          height: '630px',
          display: 'flex',
          flexDirection: 'column',
          background: '#0a0f1a',
          position: 'relative',
          overflow: 'hidden',
          fontFamily: 'system-ui, -apple-system, sans-serif',
        }}
      >
        {/* Grid lines background */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage:
              'linear-gradient(rgba(8,145,178,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(8,145,178,0.04) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
            display: 'flex',
          }}
        />

        {/* Top glow */}
        <div
          style={{
            position: 'absolute',
            top: '-120px',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '800px',
            height: '400px',
            background: 'radial-gradient(ellipse, rgba(8,145,178,0.18) 0%, transparent 70%)',
            display: 'flex',
          }}
        />

        {/* Content */}
        <div
          style={{
            position: 'relative',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            height: '100%',
            padding: '52px 64px',
          }}
        >
          {/* Top — logo + wordmark */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {/* Shield icon */}
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
                fill="rgba(8,145,178,0.25)"
                stroke="#0891b2"
                strokeWidth="1.5"
              />
              <path d="M9 12l2 2 4-4" stroke="#0891b2" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span style={{ fontSize: '20px', fontWeight: 700, color: '#0891b2', letterSpacing: '-0.01em' }}>
              Ship Safe
            </span>
            <span style={{ fontSize: '14px', color: 'rgba(148,163,184,0.5)', marginLeft: '4px' }}>
              / Blog
            </span>
          </div>

          {/* Middle — tags + title + description */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: '960px' }}>
            {/* Tags */}
            {tags.length > 0 && (
              <div style={{ display: 'flex', gap: '8px' }}>
                {tags.slice(0, 3).map((tag) => (
                  <div
                    key={tag}
                    style={{
                      fontSize: '12px',
                      fontWeight: 600,
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                      color: '#0891b2',
                      background: 'rgba(8,145,178,0.1)',
                      border: '1px solid rgba(8,145,178,0.25)',
                      padding: '4px 12px',
                      borderRadius: '4px',
                      display: 'flex',
                    }}
                  >
                    {tag}
                  </div>
                ))}
              </div>
            )}

            {/* Title */}
            <div
              style={{
                fontSize: displayTitle.length > 50 ? '40px' : '48px',
                fontWeight: 800,
                color: '#f1f5f9',
                lineHeight: 1.15,
                letterSpacing: '-0.02em',
                display: 'flex',
              }}
            >
              {displayTitle}
            </div>

            {/* Description */}
            <div
              style={{
                fontSize: '20px',
                color: 'rgba(148,163,184,0.85)',
                lineHeight: 1.5,
                display: 'flex',
              }}
            >
              {displayDesc}
            </div>
          </div>

          {/* Bottom — author + date + domain */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {/* Author avatar placeholder */}
              <div
                style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #0891b2, #0e7490)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '16px',
                  fontWeight: 700,
                  color: '#fff',
                }}
              >
                S
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                <span style={{ fontSize: '14px', fontWeight: 600, color: '#e2e8f0' }}>Ship Safe Team</span>
                {date && (
                  <span style={{ fontSize: '13px', color: 'rgba(148,163,184,0.65)' }}>{date}</span>
                )}
              </div>
            </div>

            <span style={{ fontSize: '14px', color: 'rgba(148,163,184,0.45)', letterSpacing: '0.02em' }}>
              shipsafecli.com
            </span>
          </div>
        </div>
      </div>
    ),
    {
      width: 1200,
      height: 630,
    }
  );
}
