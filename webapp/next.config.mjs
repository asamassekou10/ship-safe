import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    unoptimized: true,
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
  },
};

export default nextConfig;
