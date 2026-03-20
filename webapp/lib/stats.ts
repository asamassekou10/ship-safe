import { unstable_cache } from 'next/cache';

const GITHUB_OWNER = 'asamassekou10';
const GITHUB_REPO = 'ship-safe';
const NPM_PACKAGE = 'ship-safe';

const FALLBACK = { stars: 1200, downloads: 8000 };

export function formatNumber(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(n);
}

async function fetchRepoStats(): Promise<{ stars: number; downloads: number }> {
  const [stars, downloads] = await Promise.all([
    fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}`, {
      headers: { Accept: 'application/vnd.github.v3+json' },
      next: { revalidate: 3600 },
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d?.stargazers_count ?? FALLBACK.stars)
      .catch(() => FALLBACK.stars),

    fetch(`https://api.npmjs.org/downloads/point/last-week/${NPM_PACKAGE}`, {
      next: { revalidate: 3600 },
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d?.downloads ?? FALLBACK.downloads)
      .catch(() => FALLBACK.downloads),
  ]);

  return { stars, downloads };
}

export const getRepoStats = unstable_cache(fetchRepoStats, ['repo-stats'], {
  revalidate: 3600,
});
