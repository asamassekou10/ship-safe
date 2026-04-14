import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    unoptimized: true,
  },
  // Fix: webpack enhanced-resolve on Windows calls readlink() inside dynamic route
  // directories like [id] and gets EISDIR. Disabling symlinks resolving works
  // around this. Linux/Vercel builds are unaffected.
  webpack(config) {
    config.resolve.symlinks = false;
    return config;
  },
  // Pin trace root to webapp/ so Next.js doesn't crawl into the parent monorepo.
  // Vercel sets its own root, so this only matters for local Windows builds.
  outputFileTracingRoot: resolve(__dirname),
  // Exclude ship-safe from webpack bundling so its files are deployed as-is
  // and can be found by the scan API route at runtime via process.cwd().
  serverExternalPackages: ['ship-safe'],
  // Explicitly include ship-safe files in the Lambda bundle — nft won't trace
  // them automatically because we run ship-safe as a subprocess (no import).
  outputFileTracingIncludes: {
    '/api/scan': ['./node_modules/ship-safe/**/*'],
    '/api/cron': ['./node_modules/ship-safe/**/*'],
    '/api/og': ['./public/og-shipsafe.jpg'],
  },
  // Prevent nft from including build-time artifacts in the Lambda bundle.
  // .next/cache alone is 200+ MB and is never needed at runtime.
  outputFileTracingExcludes: {
    '*': [
      './.next/cache/**/*',
      './tsconfig.tsbuildinfo',
      './.next/static/**/*',
      './node_modules/ship-safe/node_modules/**/*',
      './node_modules/ship-safe/website/**/*',
      './node_modules/ship-safe/snippets/**/*',
      './node_modules/ship-safe/docs/**/*',
      './node_modules/ship-safe/article-assets/**/*',
      './node_modules/ship-safe/marketing/**/*',
    ],
  },
};

export default nextConfig;
