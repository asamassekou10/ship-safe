export { auth as middleware } from '@/lib/auth';

export const config = {
  matcher: ['/app/:path*', '/api/scan/:path*', '/api/scans/:path*', '/api/checkout/:path*'],
};
