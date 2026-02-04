/**
 * Input Validation Patterns
 * =========================
 *
 * Validation patterns and utilities for API endpoints.
 *
 * VALIDATION PRINCIPLES:
 * 1. Validate ALL input - query params, body, headers, cookies
 * 2. Whitelist, don't blacklist - define what's allowed
 * 3. Validate type, format, length, and range
 * 4. Fail fast - reject invalid input early
 * 5. Never trust client-side validation alone
 */

// =============================================================================
// ZOD SCHEMAS (RECOMMENDED)
// =============================================================================

import { z } from 'zod';

/**
 * Common validation schemas
 */
export const schemas = {
  // User ID - UUID format
  userId: z.string().uuid('Invalid user ID format'),

  // Email - standard email format
  email: z.string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .transform(email => email.toLowerCase().trim()),

  // Password - secure requirements
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password too long')
    .regex(/[a-z]/, 'Password must contain a lowercase letter')
    .regex(/[A-Z]/, 'Password must contain an uppercase letter')
    .regex(/[0-9]/, 'Password must contain a number'),

  // Username - alphanumeric with limits
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),

  // URL - valid URL format
  url: z.string()
    .url('Invalid URL format')
    .max(2048, 'URL too long'),

  // Safe URL - prevents SSRF
  safeUrl: z.string()
    .url('Invalid URL format')
    .max(2048, 'URL too long')
    .refine(
      (url) => {
        try {
          const parsed = new URL(url);
          // Block internal addresses
          const blocked = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '169.254.',    // Link-local
            '10.',         // Private Class A
            '172.16.',     // Private Class B
            '192.168.',    // Private Class C
          ];
          return !blocked.some(b => parsed.hostname.startsWith(b));
        } catch {
          return false;
        }
      },
      'URL not allowed'
    ),

  // Pagination
  pagination: z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
  }),

  // Sort order
  sortOrder: z.enum(['asc', 'desc']).default('desc'),

  // Date - ISO format
  isoDate: z.string().datetime('Invalid date format'),

  // Phone number - E.164 format
  phone: z.string()
    .regex(/^\+[1-9]\d{1,14}$/, 'Invalid phone format (use E.164: +1234567890)'),

  // Positive integer
  positiveInt: z.coerce.number().int().positive(),

  // Non-empty string with max length
  nonEmptyString: (maxLength = 1000) =>
    z.string()
      .min(1, 'Field cannot be empty')
      .max(maxLength, `Field too long (max ${maxLength} characters)`)
      .transform(s => s.trim()),

  // Safe HTML text (strips dangerous content)
  safeText: z.string()
    .max(10000, 'Text too long')
    .transform(text => {
      // Remove script tags and event handlers
      return text
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/on\w+="[^"]*"/gi, '')
        .replace(/javascript:/gi, '');
    }),
};

// =============================================================================
// REQUEST VALIDATION MIDDLEWARE
// =============================================================================

/**
 * Validate request body with Zod schema
 */
export function validateBody<T>(schema: z.ZodSchema<T>) {
  return async (request: Request): Promise<{ data: T } | { error: string; details: z.ZodError }> => {
    try {
      const body = await request.json();
      const data = schema.parse(body);
      return { data };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          error: 'Validation failed',
          details: error,
        };
      }
      return { error: 'Invalid JSON body', details: error as z.ZodError };
    }
  };
}

/**
 * Validate query parameters with Zod schema
 */
export function validateQuery<T>(schema: z.ZodSchema<T>) {
  return (url: URL): { data: T } | { error: string; details: z.ZodError } => {
    try {
      const params = Object.fromEntries(url.searchParams.entries());
      const data = schema.parse(params);
      return { data };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          error: 'Validation failed',
          details: error,
        };
      }
      return { error: 'Invalid query parameters', details: error as z.ZodError };
    }
  };
}

// =============================================================================
// NEXT.JS API ROUTE EXAMPLE
// =============================================================================

export const nextjsValidationExample = `
// app/api/users/route.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';

// Define schema for this endpoint
const createUserSchema = z.object({
  email: z.string().email().max(255).transform(e => e.toLowerCase()),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100).trim(),
});

export async function POST(request: NextRequest) {
  try {
    // Parse and validate
    const body = await request.json();
    const result = createUserSchema.safeParse(body);

    if (!result.success) {
      return NextResponse.json(
        {
          error: 'Validation failed',
          issues: result.error.issues.map(i => ({
            field: i.path.join('.'),
            message: i.message,
          })),
        },
        { status: 400 }
      );
    }

    const { email, password, name } = result.data;

    // Now safe to use validated data
    // ... create user logic

    return NextResponse.json({ success: true });

  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid request body' },
      { status: 400 }
    );
  }
}
`;

// =============================================================================
// EXPRESS VALIDATION EXAMPLE
// =============================================================================

export const expressValidationExample = `
// Express with Zod validation middleware
import express from 'express';
import { z } from 'zod';

const app = express();
app.use(express.json());

// Validation middleware factory
function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse({
      body: req.body,
      query: req.query,
      params: req.params,
    });

    if (!result.success) {
      return res.status(400).json({
        error: 'Validation failed',
        issues: result.error.issues,
      });
    }

    req.validated = result.data;
    next();
  };
}

// Define route schema
const updateUserSchema = z.object({
  params: z.object({
    id: z.string().uuid(),
  }),
  body: z.object({
    name: z.string().min(1).max(100).optional(),
    email: z.string().email().optional(),
  }),
});

// Use in route
app.put('/users/:id', validate(updateUserSchema), (req, res) => {
  const { params, body } = req.validated;
  // Safe to use validated data
  res.json({ success: true });
});
`;

// =============================================================================
// FILE UPLOAD VALIDATION
// =============================================================================

export const fileValidation = {
  // Allowed MIME types by category
  mimeTypes: {
    images: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    documents: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    spreadsheets: ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  },

  // Validate file upload
  validateFile: (
    file: { type: string; size: number; name: string },
    options: {
      allowedTypes: string[];
      maxSizeBytes: number;
      allowedExtensions?: string[];
    }
  ) => {
    const errors: string[] = [];

    // Check MIME type
    if (!options.allowedTypes.includes(file.type)) {
      errors.push(`File type ${file.type} not allowed`);
    }

    // Check size
    if (file.size > options.maxSizeBytes) {
      const maxMB = options.maxSizeBytes / (1024 * 1024);
      errors.push(`File too large (max ${maxMB}MB)`);
    }

    // Check extension
    if (options.allowedExtensions) {
      const ext = file.name.split('.').pop()?.toLowerCase();
      if (!ext || !options.allowedExtensions.includes(ext)) {
        errors.push(`File extension .${ext} not allowed`);
      }
    }

    return errors.length === 0 ? { valid: true } : { valid: false, errors };
  },
};

export const fileUploadExample = `
// File upload validation
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

export async function POST(request: NextRequest) {
  const formData = await request.formData();
  const file = formData.get('file') as File | null;

  if (!file) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 });
  }

  // Validate MIME type
  if (!ALLOWED_TYPES.includes(file.type)) {
    return NextResponse.json(
      { error: 'Invalid file type. Allowed: JPEG, PNG, WebP' },
      { status: 400 }
    );
  }

  // Validate size
  if (file.size > MAX_SIZE) {
    return NextResponse.json(
      { error: 'File too large. Maximum size: 5MB' },
      { status: 400 }
    );
  }

  // Additional: Verify file signature (magic bytes)
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer.slice(0, 4));

  const signatures = {
    jpeg: [0xFF, 0xD8, 0xFF],
    png: [0x89, 0x50, 0x4E, 0x47],
  };

  const isValidJpeg = signatures.jpeg.every((b, i) => bytes[i] === b);
  const isValidPng = signatures.png.every((b, i) => bytes[i] === b);

  if (!isValidJpeg && !isValidPng) {
    return NextResponse.json(
      { error: 'File content does not match declared type' },
      { status: 400 }
    );
  }

  // Safe to process file
  // ...

  return NextResponse.json({ success: true });
}
`;

// =============================================================================
// SQL INJECTION PREVENTION
// =============================================================================

export const sqlInjectionPrevention = `
// SQL Injection Prevention

// BAD: String concatenation (SQL injection vulnerable)
const query = \`SELECT * FROM users WHERE id = '\${userId}'\`;

// GOOD: Parameterized queries

// With Prisma (recommended)
const user = await prisma.user.findUnique({
  where: { id: userId },
});

// With raw SQL (use parameters)
const [user] = await sql\`
  SELECT * FROM users WHERE id = \${userId}
\`;

// With pg (node-postgres)
const { rows } = await pool.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);

// With mysql2
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);

// NEVER build queries with template literals or concatenation!
`;

// =============================================================================
// COMMON VALIDATION PATTERNS
// =============================================================================

export const validationPatterns = {
  // Slug - URL-safe string
  slug: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,

  // Hex color
  hexColor: /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/,

  // Credit card (basic - use payment provider's validation)
  creditCard: /^\d{13,19}$/,

  // IP address (v4)
  ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,

  // Semantic version
  semver: /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/,

  // JWT (basic structure check)
  jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/,
};
