export { auth as middleware } from '@/lib/auth';

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
