import { notFound } from 'next/navigation';
import { prisma } from '@/lib/prisma';
import type { Metadata } from 'next';
import Nav from '@/components/Nav';
import { CANONICAL_URL } from '@/lib/site';

type Props = { params: Promise<{ token: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { token } = await params;
  const report = await prisma.sharedReport.findUnique({ where: { token } });
  if (!report) return { title: 'Report not found — Ship Safe' };
  const label = report.repo ? `${report.repo} — ` : '';
  return {
    title: `${label}Security Report — Ship Safe`,
    description: `Score: ${report.score ?? '?'}/100 ${report.grade ?? ''} · ${report.findings} finding(s)`,
  };
}

const gradeColor: Record<string, string> = {
  'A+': '#22c55e', A: '#22c55e', B: '#84cc16',
  C: '#eab308', D: '#f97316', F: '#ef4444',
};

export default async function SharePage({ params }: Props) {
  const { token } = await params;
  const shared = await prisma.sharedReport.findUnique({ where: { token } });

  if (!shared || shared.expiresAt < new Date()) notFound();

  const report = shared.report as Record<string, unknown>;
  const categories = report.categories as Record<string, { label: string; findingCount?: number; deduction?: number }> | undefined;
  const color = gradeColor[shared.grade ?? 'F'] ?? '#ef4444';

  return (
    <>
      <Nav />
      <main style={{ maxWidth: 780, margin: '0 auto', padding: '2rem 1rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          {shared.repo && (
            <p style={{ color: '#94a3b8', marginBottom: '0.5rem', fontSize: '0.9rem' }}>{shared.repo}</p>
          )}
          <div style={{ fontSize: '4rem', fontWeight: 800, color, lineHeight: 1 }}>
            {shared.score ?? '?'}<span style={{ fontSize: '1.5rem', color: '#64748b' }}>/100</span>
          </div>
          <div style={{ fontSize: '2rem', color, fontWeight: 700 }}>{shared.grade ?? 'F'}</div>
          <p style={{ color: '#94a3b8', marginTop: '0.5rem' }}>
            {shared.findings} finding{shared.findings !== 1 ? 's' : ''} ·{' '}
            scanned with <a href="${CANONICAL_URL}" style={{ color: '#38bdf8' }}>Ship Safe</a>
          </p>
        </div>

        {categories && (
          <div style={{ background: '#0f172a', borderRadius: 12, padding: '1.5rem', marginBottom: '2rem' }}>
            <h2 style={{ color: '#f1f5f9', fontSize: '1rem', marginBottom: '1rem' }}>Category Breakdown</h2>
            {Object.entries(categories).map(([key, cat]) => {
              const count = cat.findingCount ?? 0;
              return (
                <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid #1e293b' }}>
                  <span style={{ color: '#cbd5e1' }}>{cat.label ?? key}</span>
                  <span style={{ color: count === 0 ? '#22c55e' : '#f87171' }}>
                    {count === 0 ? '✔ clean' : `${count} issue${count !== 1 ? 's' : ''}`}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        <div style={{ textAlign: 'center' }}>
          <a
            href="${CANONICAL_URL}"
            style={{ display: 'inline-block', background: '#0ea5e9', color: '#fff', padding: '0.75rem 2rem', borderRadius: 8, fontWeight: 600, textDecoration: 'none' }}
          >
            Scan your own repo — free
          </a>
          <p style={{ color: '#475569', fontSize: '0.8rem', marginTop: '1rem' }}>
            This report expires {shared.expiresAt.toLocaleDateString()}.
          </p>
        </div>
      </main>
    </>
  );
}
