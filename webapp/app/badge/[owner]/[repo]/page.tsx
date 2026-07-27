import { notFound } from 'next/navigation';
import { prisma } from '@/lib/prisma';
import type { Metadata } from 'next';
import Nav from '@/components/Nav';
import { CANONICAL_URL } from '@/lib/site';

type Props = { params: Promise<{ owner: string; repo: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { owner, repo } = await params;
  return { title: `${owner}/${repo} — Ship Safe Security Score` };
}

const gradeColor: Record<string, string> = {
  'A+': '#22c55e', A: '#22c55e', B: '#84cc16',
  C: '#eab308', D: '#f97316', F: '#ef4444',
};

export default async function BadgePage({ params }: Props) {
  const { owner, repo } = await params;
  const fullName = `${owner}/${repo}`;

  const scan = await prisma.scan.findFirst({
    where: { repo: { equals: fullName }, status: 'done' },
    orderBy: { createdAt: 'desc' },
    select: { score: true, grade: true, findings: true, secrets: true, vulns: true, createdAt: true },
  });

  if (!scan) notFound();

  const color = gradeColor[scan.grade ?? 'F'] ?? '#ef4444';
  const badgeUrl = `${CANONICAL_URL}/api/badge?score=${scan.score ?? 0}&grade=${encodeURIComponent(scan.grade ?? 'F')}`;

  return (
    <>
      <Nav />
      <main style={{ maxWidth: 620, margin: '4rem auto', padding: '0 1rem', textAlign: 'center' }}>
        <h1 style={{ color: '#f1f5f9', fontSize: '1.2rem', marginBottom: '0.5rem' }}>{fullName}</h1>
        <p style={{ color: '#64748b', fontSize: '0.85rem', marginBottom: '2rem' }}>
          Last scanned {new Date(scan.createdAt).toLocaleDateString()}
        </p>

        <div style={{ fontSize: '5rem', fontWeight: 800, color, lineHeight: 1 }}>
          {scan.score ?? '?'}<span style={{ fontSize: '2rem', color: '#64748b' }}>/100</span>
        </div>
        <div style={{ fontSize: '2.5rem', fontWeight: 700, color, marginBottom: '1.5rem' }}>{scan.grade ?? 'F'}</div>

        <div style={{ display: 'flex', gap: '1.5rem', justifyContent: 'center', marginBottom: '2rem' }}>
          {[
            { label: 'Findings', value: scan.findings },
            { label: 'Secrets', value: scan.secrets },
            { label: 'Vulns', value: scan.vulns },
          ].map(({ label, value }) => (
            <div key={label} style={{ background: '#0f172a', borderRadius: 10, padding: '0.75rem 1.25rem' }}>
              <div style={{ color: value > 0 ? '#f87171' : '#22c55e', fontSize: '1.5rem', fontWeight: 700 }}>{value}</div>
              <div style={{ color: '#64748b', fontSize: '0.75rem' }}>{label}</div>
            </div>
          ))}
        </div>

        <div style={{ background: '#0f172a', borderRadius: 12, padding: '1.25rem', marginBottom: '2rem', textAlign: 'left' }}>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.75rem' }}>Add this badge to your README:</p>
          <code style={{ color: '#38bdf8', fontSize: '0.75rem', wordBreak: 'break-all', display: 'block' }}>
            {`[![Ship Safe](${badgeUrl})](${CANONICAL_URL}/badge/${fullName})`}
          </code>
        </div>

        <a
          href="${CANONICAL_URL}"
          style={{ display: 'inline-block', background: '#0ea5e9', color: '#fff', padding: '0.75rem 2rem', borderRadius: 8, fontWeight: 600, textDecoration: 'none' }}
        >
          Scan your repo — free
        </a>
      </main>
    </>
  );
}
