/**
 * Supabase Secure Client Configuration
 * =====================================
 *
 * Copy this file to your project and customize for your needs.
 *
 * WHY THIS MATTERS:
 * - Separates anon (public) and service_role (admin) clients
 * - Adds type safety for environment variables
 * - Includes helpers for common secure patterns
 *
 * USAGE:
 *   // In client components (React, Vue, etc.)
 *   import { supabase } from '@/lib/supabase';
 *
 *   // In server-side code (API routes, server components)
 *   import { supabaseAdmin } from '@/lib/supabase';
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';

// =============================================================================
// ENVIRONMENT VARIABLE VALIDATION
// =============================================================================

/**
 * Validates that required environment variables are set.
 * Call this at app startup to fail fast if misconfigured.
 */
function validateEnv() {
  const required = ['NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];

  for (const key of required) {
    if (!process.env[key]) {
      throw new Error(
        `Missing required environment variable: ${key}\n` +
        `Add it to your .env.local file.`
      );
    }
  }
}

// Validate on module load (comment out if causing issues in edge runtime)
// validateEnv();

// =============================================================================
// SUPABASE URL AND KEYS
// =============================================================================

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

// Service role key - ONLY available server-side
// This key bypasses RLS and should NEVER be exposed to the client
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

// =============================================================================
// CLIENT-SIDE SUPABASE CLIENT (uses anon key)
// =============================================================================

/**
 * Public Supabase client for use in browser/client components.
 *
 * SECURITY NOTES:
 * - Uses the anon key (safe to expose)
 * - All operations are subject to RLS policies
 * - User must be authenticated for protected operations
 */
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    // Persist sessions in localStorage
    persistSession: true,
    // Automatically refresh tokens
    autoRefreshToken: true,
    // Detect session from URL (for OAuth callbacks)
    detectSessionInUrl: true,
  },
});

// =============================================================================
// SERVER-SIDE SUPABASE CLIENT (uses service_role key)
// =============================================================================

/**
 * Admin Supabase client for use in server-side code ONLY.
 *
 * SECURITY NOTES:
 * - Uses the service_role key (NEVER expose to client)
 * - Bypasses ALL Row Level Security policies
 * - Use only in: API routes, server actions, cron jobs
 * - Always validate user permissions before using
 *
 * WHEN TO USE:
 * - Admin operations (deleting users, bulk updates)
 * - Background jobs that need full database access
 * - Webhooks from external services
 *
 * WHEN NOT TO USE:
 * - Any client-side code
 * - Operations where user context matters
 * - When RLS should apply
 */
export const supabaseAdmin: SupabaseClient | null = supabaseServiceRoleKey
  ? createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: {
        // Don't persist sessions for admin client
        persistSession: false,
        autoRefreshToken: false,
      },
    })
  : null;

/**
 * Get admin client with error if not configured.
 * Use this when service_role key is required.
 */
export function getSupabaseAdmin(): SupabaseClient {
  if (!supabaseAdmin) {
    throw new Error(
      'SUPABASE_SERVICE_ROLE_KEY is not configured.\n' +
      'This operation requires admin privileges.'
    );
  }
  return supabaseAdmin;
}

// =============================================================================
// HELPER: SERVER-SIDE CLIENT WITH USER CONTEXT
// =============================================================================

/**
 * Creates a Supabase client that acts as a specific user.
 * Useful for server-side operations that should respect RLS.
 *
 * @param accessToken - The user's JWT access token
 * @returns Supabase client authenticated as the user
 *
 * USAGE:
 *   // In API route or server action
 *   const token = request.headers.get('Authorization')?.replace('Bearer ', '');
 *   const userClient = createUserClient(token);
 *   const { data } = await userClient.from('posts').select('*');
 *   // This respects RLS - user only sees their allowed data
 */
export function createUserClient(accessToken: string): SupabaseClient {
  return createClient(supabaseUrl, supabaseAnonKey, {
    global: {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

// =============================================================================
// HELPER: VALIDATE USER BEFORE ADMIN OPERATIONS
// =============================================================================

/**
 * Validates that the current user has permission before admin operations.
 * Always use this before using supabaseAdmin for user-triggered actions.
 *
 * @param userId - The user's ID to check
 * @param requiredRole - The minimum role required (e.g., 'admin')
 * @returns True if user has permission
 *
 * USAGE:
 *   const hasPermission = await validateUserPermission(userId, 'admin');
 *   if (!hasPermission) {
 *     return new Response('Forbidden', { status: 403 });
 *   }
 *   // Now safe to use supabaseAdmin
 */
export async function validateUserPermission(
  userId: string,
  requiredRole: string
): Promise<boolean> {
  const admin = getSupabaseAdmin();

  const { data: profile } = await admin
    .from('profiles')
    .select('role')
    .eq('id', userId)
    .single();

  if (!profile) return false;

  // Customize this based on your role hierarchy
  const roleHierarchy: Record<string, number> = {
    viewer: 0,
    editor: 1,
    admin: 2,
    super_admin: 3,
  };

  const userRoleLevel = roleHierarchy[profile.role] ?? 0;
  const requiredRoleLevel = roleHierarchy[requiredRole] ?? 999;

  return userRoleLevel >= requiredRoleLevel;
}

// =============================================================================
// TYPE DEFINITIONS (customize for your database)
// =============================================================================

/**
 * Generate types with:
 * npx supabase gen types typescript --project-id your-project > types/database.ts
 *
 * Then import and use:
 * import { Database } from '@/types/database';
 * const supabase = createClient<Database>(url, key);
 */

// Example type for user profiles
export interface Profile {
  id: string;
  email: string;
  role: 'viewer' | 'editor' | 'admin';
  created_at: string;
}
