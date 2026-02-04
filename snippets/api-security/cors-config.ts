/**
 * CORS Configuration Examples
 * ===========================
 *
 * Cross-Origin Resource Sharing (CORS) configurations for common frameworks.
 *
 * WHY CORS MATTERS:
 * - Prevents unauthorized websites from calling your API
 * - Blocks cross-site request forgery (CSRF) attacks
 * - Controls which domains can access your resources
 *
 * COMMON MISTAKES:
 * - Setting origin: '*' in production (allows any site)
 * - Not validating origin properly (regex bypass)
 * - Forgetting credentials handling
 */

// =============================================================================
// NEXT.JS API ROUTES
// =============================================================================

/**
 * Next.js API route with CORS
 * Use in: pages/api/*.ts or app/api/*/route.ts
 */
export const nextjsCorsConfig = `
// next.config.js - Basic headers approach
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            // CHANGE THIS to your frontend domain
            value: process.env.FRONTEND_URL || 'https://yourapp.com',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET, POST, PUT, DELETE, OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value: 'Content-Type, Authorization',
          },
          {
            key: 'Access-Control-Allow-Credentials',
            value: 'true',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
`;

/**
 * Next.js API route handler with manual CORS
 */
export const nextjsRouteHandler = `
// app/api/example/route.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Allowed origins - ADD YOUR DOMAINS HERE
const ALLOWED_ORIGINS = [
  'https://yourapp.com',
  'https://www.yourapp.com',
  process.env.NODE_ENV === 'development' && 'http://localhost:3000',
].filter(Boolean) as string[];

function getCorsHeaders(origin: string | null) {
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400', // 24 hours
  };

  // Only allow specific origins
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return headers;
}

// Handle preflight requests
export async function OPTIONS(request: NextRequest) {
  const origin = request.headers.get('origin');
  return new NextResponse(null, {
    status: 204,
    headers: getCorsHeaders(origin),
  });
}

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin');

  // Your logic here
  const data = { message: 'Hello!' };

  return NextResponse.json(data, {
    headers: getCorsHeaders(origin),
  });
}

export async function POST(request: NextRequest) {
  const origin = request.headers.get('origin');

  // Validate origin for mutations
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return new NextResponse('Forbidden', { status: 403 });
  }

  // Your logic here
  const body = await request.json();

  return NextResponse.json({ success: true }, {
    headers: getCorsHeaders(origin),
  });
}
`;

// =============================================================================
// EXPRESS.JS
// =============================================================================

export const expressCorsConfig = `
// Express CORS configuration
import cors from 'cors';
import express from 'express';

const app = express();

// BAD: Allows any origin
// app.use(cors()); // DON'T DO THIS IN PRODUCTION

// GOOD: Specific origins
const ALLOWED_ORIGINS = [
  'https://yourapp.com',
  'https://www.yourapp.com',
  process.env.NODE_ENV === 'development' && 'http://localhost:3000',
].filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    // Remove this if you want to block those too
    if (!origin) {
      return callback(null, true);
    }

    if (ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400, // 24 hours
};

app.use(cors(corsOptions));

// Handle CORS errors
app.use((err, req, res, next) => {
  if (err.message === 'CORS not allowed') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  next(err);
});
`;

// =============================================================================
// FASTIFY
// =============================================================================

export const fastifyCorsConfig = `
// Fastify CORS configuration
import Fastify from 'fastify';
import cors from '@fastify/cors';

const fastify = Fastify();

const ALLOWED_ORIGINS = [
  'https://yourapp.com',
  'https://www.yourapp.com',
];

await fastify.register(cors, {
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});
`;

// =============================================================================
// HONO (EDGE)
// =============================================================================

export const honoCorsConfig = `
// Hono CORS configuration (for Cloudflare Workers, etc.)
import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

const ALLOWED_ORIGINS = [
  'https://yourapp.com',
  'https://www.yourapp.com',
];

app.use('/*', cors({
  origin: (origin) => {
    if (ALLOWED_ORIGINS.includes(origin)) {
      return origin;
    }
    return null; // Block the request
  },
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));
`;

// =============================================================================
// VERCEL EDGE FUNCTIONS
// =============================================================================

export const vercelEdgeCors = `
// Vercel Edge Function with CORS
// api/example.ts
import type { NextRequest } from 'next/server';

export const config = {
  runtime: 'edge',
};

const ALLOWED_ORIGINS = [
  'https://yourapp.com',
  'https://www.yourapp.com',
];

export default async function handler(request: NextRequest) {
  const origin = request.headers.get('origin') || '';

  // Validate origin
  const isAllowed = ALLOWED_ORIGINS.includes(origin);

  // Handle preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': isAllowed ? origin : '',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  // Block non-allowed origins for mutations
  if (request.method !== 'GET' && !isAllowed) {
    return new Response('Forbidden', { status: 403 });
  }

  // Your logic here
  const data = { message: 'Hello from the edge!' };

  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': isAllowed ? origin : '',
      'Access-Control-Allow-Credentials': 'true',
    },
  });
}
`;

// =============================================================================
// ANTI-PATTERNS
// =============================================================================

export const corsAntiPatterns = `
// CORS ANTI-PATTERNS - DON'T DO THESE

// 1. Wildcard origin (allows any site to call your API)
app.use(cors({ origin: '*' }));

// 2. Reflecting any origin (same problem as wildcard)
app.use(cors({
  origin: (origin, callback) => callback(null, origin), // BAD!
}));

// 3. Regex without anchors (can be bypassed)
// Attacker can use: https://yourapp.com.evil.com
const UNSAFE_PATTERN = /yourapp\\.com/; // BAD!
const SAFE_PATTERN = /^https:\\/\\/(www\\.)?yourapp\\.com$/; // GOOD

// 4. Not handling credentials properly
// If you need cookies/auth headers, you MUST specify exact origins
// Wildcard doesn't work with credentials

// 5. Long maxAge without reviewing
// If you change CORS config, users won't see it for maxAge seconds
`;
