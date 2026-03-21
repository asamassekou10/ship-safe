import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Lightweight middleware — only check for session token existence.
// Full auth validation happens in API routes / server components via auth().
// This avoids pulling Prisma into the Edge Runtime (1MB limit).
export function middleware(req: NextRequest) {
  const token =
    req.cookies.get('authjs.session-token')?.value || // ship-safe-ignore — reading Auth.js session cookies, not setting them; httpOnly/Secure flags are managed by Auth.js
    req.cookies.get('__Secure-authjs.session-token')?.value;

  if (!token) {
    const loginUrl = new URL('/login', req.url); // ship-safe-ignore — redirect middleware; actual auth+rate-limiting enforced by Auth.js, not here
    loginUrl.searchParams.set('callbackUrl', req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/app/:path*',
    '/api/scan/:path*',
    '/api/scans/:path*',
    '/api/checkout/:path*',
    '/api/notifications/:path*',
    '/api/orgs/:path*',
    '/api/repos/:path*',
    '/api/policies/:path*',
    '/api/reports/:path*',
    '/api/fix/:path*',
    '/api/guardian/:path*',
    '/api/v1/key/:path*',
  ],
};
