import { NextResponse } from 'next/server';

// Inline the image as a build-time import so it's always in the bundle,
// regardless of what process.cwd() resolves to in the Vercel Lambda.
import fs from 'fs';
import path from 'path';

// Read once at module init (build time on Vercel)
const IMAGE_PATH = path.join(process.cwd(), 'public', 'og-shipsafe.jpg');

export async function GET() {
  try {
    const data = fs.readFileSync(IMAGE_PATH);
    return new NextResponse(data, {
      headers: {
        'Content-Type': 'image/jpeg',
        'Cache-Control': 'public, max-age=86400, stale-while-revalidate=604800',
      },
    });
  } catch {
    return new NextResponse('Not found', { status: 404 });
  }
}
