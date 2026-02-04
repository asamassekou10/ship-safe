/**
 * Next.js Middleware Rate Limiting
 * =================================
 *
 * Rate limiting at the edge using Next.js middleware.
 * No external dependencies - uses in-memory store (resets on deploy).
 *
 * WHY USE MIDDLEWARE:
 * - Blocks requests before they hit your API
 * - Runs at the edge (faster)
 * - Protects all routes with one file
 *
 * LIMITATIONS:
 * - In-memory store resets on deploy/restart
 * - Doesn't sync across serverless instances
 * - For production, use Upstash Redis instead
 *
 * USAGE:
 * Copy this to middleware.ts in your Next.js project root.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// =============================================================================
// CONFIGURATION
// =============================================================================

const RATE_LIMIT_CONFIG = {
  // Requests per window
  maxRequests: 60,
  // Window size in seconds
  windowSizeSeconds: 60,
  // Paths to rate limit (regex patterns)
  protectedPaths: [
    /^\/api\//,           // All API routes
  ],
  // Stricter limits for sensitive paths
  strictPaths: [
    { pattern: /^\/api\/auth\//, maxRequests: 5 },
    { pattern: /^\/api\/ai\//, maxRequests: 10 },
  ],
  // Paths to exclude from rate limiting
  excludedPaths: [
    /^\/api\/health/,     // Health checks
    /^\/_next\//,         // Next.js internals
    /^\/favicon\.ico/,
  ],
};

// =============================================================================
// IN-MEMORY RATE LIMIT STORE
// =============================================================================

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

// Simple in-memory store (use Redis for production)
const rateLimitStore = new Map<string, RateLimitEntry>();

// Clean up old entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (entry.resetTime < now) {
      rateLimitStore.delete(key);
    }
  }
}, 60000); // Clean every minute

// =============================================================================
// RATE LIMIT LOGIC
// =============================================================================

function getClientIP(request: NextRequest): string {
  // Check various headers for the real IP
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }

  const realIP = request.headers.get('x-real-ip');
  if (realIP) {
    return realIP;
  }

  // Fallback
  return 'unknown';
}

function checkRateLimit(
  ip: string,
  maxRequests: number,
  windowSeconds: number
): { allowed: boolean; remaining: number; resetTime: number } {
  const now = Date.now();
  const key = `ratelimit:${ip}`;
  const windowMs = windowSeconds * 1000;

  let entry = rateLimitStore.get(key);

  // Create new entry if doesn't exist or window expired
  if (!entry || entry.resetTime < now) {
    entry = {
      count: 0,
      resetTime: now + windowMs,
    };
  }

  entry.count++;
  rateLimitStore.set(key, entry);

  const remaining = Math.max(0, maxRequests - entry.count);
  const allowed = entry.count <= maxRequests;

  return { allowed, remaining, resetTime: entry.resetTime };
}

function getMaxRequests(pathname: string): number {
  // Check strict paths first
  for (const strict of RATE_LIMIT_CONFIG.strictPaths) {
    if (strict.pattern.test(pathname)) {
      return strict.maxRequests;
    }
  }
  return RATE_LIMIT_CONFIG.maxRequests;
}

function shouldRateLimit(pathname: string): boolean {
  // Check exclusions first
  for (const pattern of RATE_LIMIT_CONFIG.excludedPaths) {
    if (pattern.test(pathname)) {
      return false;
    }
  }

  // Check if path is protected
  for (const pattern of RATE_LIMIT_CONFIG.protectedPaths) {
    if (pattern.test(pathname)) {
      return true;
    }
  }

  return false;
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

export function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Skip if path is not rate limited
  if (!shouldRateLimit(pathname)) {
    return NextResponse.next();
  }

  const ip = getClientIP(request);
  const maxRequests = getMaxRequests(pathname);

  const { allowed, remaining, resetTime } = checkRateLimit(
    ip,
    maxRequests,
    RATE_LIMIT_CONFIG.windowSizeSeconds
  );

  // Add rate limit headers to response
  const response = allowed
    ? NextResponse.next()
    : NextResponse.json(
        {
          error: 'Too Many Requests',
          message: 'Rate limit exceeded. Please try again later.',
          retryAfter: Math.ceil((resetTime - Date.now()) / 1000),
        },
        { status: 429 }
      );

  response.headers.set('X-RateLimit-Limit', maxRequests.toString());
  response.headers.set('X-RateLimit-Remaining', remaining.toString());
  response.headers.set('X-RateLimit-Reset', resetTime.toString());

  if (!allowed) {
    response.headers.set(
      'Retry-After',
      Math.ceil((resetTime - Date.now()) / 1000).toString()
    );
  }

  return response;
}

// =============================================================================
// MATCHER CONFIGURATION
// =============================================================================

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|public/).*)',
  ],
};
