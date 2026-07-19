import { ImageResponse } from 'next/og';

export const runtime = 'edge';

// Shared OG image for all site pages.
// Usage: /api/og?title=...&description=...&label=...&badge=...
//
// Params:
//   title       — main heading (required)
//   description — subtext below the title
//   label       — small pill at the top (e.g. "Pricing", "Documentation")
//   badge       — optional secondary pill (e.g. "Free forever", "v6.3.0")

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);

  const title       = searchParams.get('title')       ?? 'Ship Safe';
  const description = searchParams.get('description') ?? 'AI-Powered Security Scanner for Developers';
  const label       = searchParams.get('label')       ?? '';
  const badge       = searchParams.get('badge')       ?? '';

  // Truncate to fit the card
  const displayTitle = title.length > 60 ? title.slice(0, 60).trimEnd() + '…' : title;
  const displayDesc  = description.length > 130 ? description.slice(0, 130).trimEnd() + '…' : description;

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
        {/* Grid */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage:
              'linear-gradient(rgba(8,145,178,0.04) 1px, transparent 1px),' +
              'linear-gradient(90deg, rgba(8,145,178,0.04) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
            display: 'flex',
          }}
        />

        {/* Radial glow — top centre */}
        <div
          style={{
            position: 'absolute',
            top: '-140px',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '900px',
            height: '500px',
            background: 'radial-gradient(ellipse, rgba(8,145,178,0.16) 0%, transparent 70%)',
            display: 'flex',
          }}
        />

        {/* Bottom-right accent glow */}
        <div
          style={{
            position: 'absolute',
            bottom: '-80px',
            right: '-80px',
            width: '400px',
            height: '400px',
            background: 'radial-gradient(ellipse, rgba(8,145,178,0.07) 0%, transparent 70%)',
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
            padding: '52px 72px',
          }}
        >
          {/* Top row — logo + wordmark */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <svg width="38" height="38" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
                fill="rgba(8,145,178,0.2)"
                stroke="#0891b2"
                strokeWidth="1.5"
              />
              <path
                d="M9 12l2 2 4-4"
                stroke="#0891b2"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span style={{ fontSize: '22px', fontWeight: 700, color: '#0891b2', letterSpacing: '0' }}>
              Ship Safe CLI
            </span>
          </div>

          {/* Middle — label pills + title + description */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '980px' }}>
            {/* Pills row */}
            {(label || badge) && (
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                {label && (
                  <div
                    style={{
                      fontSize: '13px',
                      fontWeight: 600,
                      letterSpacing: '0.07em',
                      textTransform: 'uppercase',
                      color: '#0891b2',
                      background: 'rgba(8,145,178,0.1)',
                      border: '1px solid rgba(8,145,178,0.25)',
                      padding: '5px 14px',
                      borderRadius: '4px',
                      display: 'flex',
                    }}
                  >
                    {label}
                  </div>
                )}
                {badge && (
                  <div
                    style={{
                      fontSize: '13px',
                      fontWeight: 600,
                      letterSpacing: '0.07em',
                      textTransform: 'uppercase',
                      color: '#64748b',
                      background: 'rgba(100,116,139,0.08)',
                      border: '1px solid rgba(100,116,139,0.18)',
                      padding: '5px 14px',
                      borderRadius: '4px',
                      display: 'flex',
                    }}
                  >
                    {badge}
                  </div>
                )}
              </div>
            )}

            {/* Title */}
            <div
              style={{
                fontSize: displayTitle.length > 40 ? '52px' : '62px',
                fontWeight: 800,
                color: '#f1f5f9',
                lineHeight: 1.1,
                letterSpacing: '0',
                display: 'flex',
              }}
            >
              {displayTitle}
            </div>

            {/* Description */}
            <div
              style={{
                fontSize: '22px',
                color: 'rgba(148,163,184,0.8)',
                lineHeight: 1.55,
                display: 'flex',
              }}
            >
              {displayDesc}
            </div>
          </div>

          {/* Bottom row — URL + version pill */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <span style={{ fontSize: '15px', color: 'rgba(148,163,184,0.4)', letterSpacing: '0.02em' }}>
              shipsafecli.com
            </span>

            {/* Decorative stat bar */}
            <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
              {[
                { value: '29', label: 'agents' },
                { value: '80+', label: 'attack classes' },
                { value: 'MIT', label: 'open source' },
              ].map((stat) => (
                <div
                  key={stat.label}
                  style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px' }}
                >
                  <span style={{ fontSize: '18px', fontWeight: 700, color: '#0891b2' }}>{stat.value}</span>
                  <span style={{ fontSize: '11px', color: 'rgba(148,163,184,0.4)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{stat.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    ),
    { width: 1200, height: 630 }
  );
}
