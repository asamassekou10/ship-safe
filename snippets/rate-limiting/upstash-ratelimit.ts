/**
 * Rate Limiting with Upstash Redis
 * =================================
 *
 * Copy this file to your Next.js project.
 *
 * WHY RATE LIMITING MATTERS:
 * - Prevents brute force attacks on auth endpoints
 * - Protects against API abuse and scraping
 * - Controls costs for AI/LLM endpoints
 * - Required for production apps
 *
 * SETUP:
 * 1. Create account at upstash.com
 * 2. Create a Redis database
 * 3. Copy UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN to .env
 * 4. npm install @upstash/ratelimit @upstash/redis
 *
 * USAGE:
 *   import { ratelimit, checkRateLimit } from '@/lib/ratelimit';
 *
 *   // In API route
 *   const { success, remaining } = await checkRateLimit(request);
 *   if (!success) {
 *     return new Response('Too many requests', { status: 429 });
 *   }
 */

import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

// =============================================================================
// REDIS CLIENT
// =============================================================================

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

// =============================================================================
// RATE LIMITERS FOR DIFFERENT USE CASES
// =============================================================================

/**
 * General API rate limiter
 * 60 requests per minute per IP
 */
export const ratelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(60, '1 m'),
  analytics: true,
  prefix: 'ratelimit:api',
});

/**
 * Auth endpoints rate limiter (stricter)
 * 5 requests per minute per IP
 * Prevents brute force attacks
 */
export const authRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(5, '1 m'),
  analytics: true,
  prefix: 'ratelimit:auth',
});

/**
 * AI/LLM endpoints rate limiter
 * 10 requests per minute per user
 * Prevents cost explosion
 */
export const aiRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(10, '1 m'),
  analytics: true,
  prefix: 'ratelimit:ai',
});

/**
 * Expensive operations rate limiter
 * 100 requests per day per user
 * For operations like exports, reports
 */
export const expensiveRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(100, '1 d'),
  analytics: true,
  prefix: 'ratelimit:expensive',
});

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Get identifier for rate limiting
 * Uses user ID if authenticated, otherwise IP address
 */
export function getIdentifier(request: Request, userId?: string): string {
  if (userId) {
    return `user:${userId}`;
  }

  // Get IP from headers (works with Vercel, Cloudflare, etc.)
  const forwarded = request.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0].trim() : 'unknown';

  return `ip:${ip}`;
}

/**
 * Check rate limit and return result
 * Returns success, remaining requests, and reset time
 */
export async function checkRateLimit(
  request: Request,
  userId?: string,
  limiter: Ratelimit = ratelimit
): Promise<{
  success: boolean;
  remaining: number;
  reset: number;
  limit: number;
}> {
  const identifier = getIdentifier(request, userId);

  const { success, remaining, reset, limit } = await limiter.limit(identifier);

  return { success, remaining, reset, limit };
}

/**
 * Rate limit middleware for Next.js API routes
 * Returns Response if rate limited, undefined if OK
 */
export async function rateLimitMiddleware(
  request: Request,
  userId?: string,
  limiter: Ratelimit = ratelimit
): Promise<Response | undefined> {
  const { success, remaining, reset, limit } = await checkRateLimit(
    request,
    userId,
    limiter
  );

  if (!success) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        message: 'Please try again later',
        retryAfter: Math.ceil((reset - Date.now()) / 1000),
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'X-RateLimit-Limit': limit.toString(),
          'X-RateLimit-Remaining': remaining.toString(),
          'X-RateLimit-Reset': reset.toString(),
          'Retry-After': Math.ceil((reset - Date.now()) / 1000).toString(),
        },
      }
    );
  }

  return undefined;
}

// =============================================================================
// USAGE EXAMPLES
// =============================================================================

/**
 * Example: API route with rate limiting
 *
 * // app/api/data/route.ts
 * import { rateLimitMiddleware } from '@/lib/ratelimit';
 *
 * export async function GET(request: Request) {
 *   // Check rate limit
 *   const rateLimitResponse = await rateLimitMiddleware(request);
 *   if (rateLimitResponse) return rateLimitResponse;
 *
 *   // Your API logic here
 *   return Response.json({ data: 'Hello!' });
 * }
 */

/**
 * Example: Auth route with stricter limits
 *
 * // app/api/auth/login/route.ts
 * import { rateLimitMiddleware, authRatelimit } from '@/lib/ratelimit';
 *
 * export async function POST(request: Request) {
 *   // Stricter rate limit for auth
 *   const rateLimitResponse = await rateLimitMiddleware(request, undefined, authRatelimit);
 *   if (rateLimitResponse) return rateLimitResponse;
 *
 *   // Login logic here
 * }
 */

/**
 * Example: AI endpoint with user-based limits
 *
 * // app/api/ai/generate/route.ts
 * import { rateLimitMiddleware, aiRatelimit } from '@/lib/ratelimit';
 * import { auth } from '@/lib/auth';
 *
 * export async function POST(request: Request) {
 *   const session = await auth();
 *   if (!session?.user) {
 *     return new Response('Unauthorized', { status: 401 });
 *   }
 *
 *   // Rate limit by user ID for AI endpoints
 *   const rateLimitResponse = await rateLimitMiddleware(
 *     request,
 *     session.user.id,
 *     aiRatelimit
 *   );
 *   if (rateLimitResponse) return rateLimitResponse;
 *
 *   // AI logic here
 * }
 */
