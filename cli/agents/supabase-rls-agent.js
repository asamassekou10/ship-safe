/**
 * SupabaseRLSAgent
 * =================
 *
 * Detects missing or weak Row Level Security (RLS) in Supabase projects.
 * Checks SQL migrations, client-side service_role key usage,
 * unprotected storage operations, and anon-key data mutations.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// Patterns for client-side code
const CLIENT_PATTERNS = [
  {
    rule: 'SUPABASE_SERVICE_KEY_CLIENT',
    title: 'Supabase: Service Role Key in Client Code',
    regex: /SUPABASE_SERVICE_ROLE_KEY|service_role_key|serviceRoleKey|supabaseAdmin/g,
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    description: 'Service role key bypasses RLS entirely. Never expose it in client-side code.',
    fix: 'Use the anon key on the client. Move service_role operations to a backend/edge function.',
  },
  {
    rule: 'SUPABASE_RLS_DISABLED',
    title: 'Supabase: RLS Bypass via .rpc() or Admin Client',
    regex: /\.rpc\s*\(\s*['"][^'"]+['"]/g,
    severity: 'high',
    cwe: 'CWE-284',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'Supabase .rpc() calls execute database functions that may bypass RLS policies.',
    fix: 'Ensure the underlying SQL function uses SECURITY DEFINER carefully, or set search_path.',
  },
  {
    rule: 'SUPABASE_PUBLIC_ANON_INSERT',
    title: 'Supabase: Unguarded Insert/Update/Delete',
    regex: /supabase\s*\.from\s*\(\s*['"][^'"]+['"]\s*\)\s*\.(?:insert|update|delete|upsert)\s*\(/g,
    severity: 'high',
    cwe: 'CWE-284',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'Supabase data mutation without visible auth check. Ensure RLS policies protect this table.',
    fix: 'Verify RLS is enabled on the table and policies restrict mutations to authenticated users.',
  },
  {
    rule: 'SUPABASE_UNPROTECTED_STORAGE',
    title: 'Supabase: Storage Operation Without Auth',
    regex: /supabase\s*\.storage\s*\.from\s*\(\s*['"][^'"]+['"]\s*\)\s*\.(?:upload|remove|move|createSignedUrl|list)\s*\(/g,
    severity: 'medium',
    cwe: 'CWE-284',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'Supabase storage operation detected. Ensure storage policies restrict access.',
    fix: 'Configure storage bucket policies to require authentication.',
  },
];

// Client-side directories (findings here are more severe)
const CLIENT_DIRS = /(?:^|[/\\])(?:src|pages|app|components|hooks|lib|utils)[/\\]/i;

export class SupabaseRLSAgent extends BaseAgent {
  constructor() {
    super('SupabaseRLSAgent', 'Supabase Row Level Security audit', 'auth');
  }

  async analyze(context) {
    const { rootPath, files } = context;
    let findings = [];

    // ── 1. Scan client-side code for Supabase security issues ─────────────────
    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.vue', '.svelte'].includes(ext);
    });

    for (const file of codeFiles) {
      const fileFindings = this.scanFileWithPatterns(file, CLIENT_PATTERNS);
      // Elevate severity for findings in client-side directories
      const relPath = path.relative(rootPath, file).replace(/\\/g, '/');
      if (CLIENT_DIRS.test(relPath)) {
        for (const f of fileFindings) {
          if (f.rule === 'SUPABASE_SERVICE_KEY_CLIENT') {
            f.severity = 'critical';
          }
        }
      }
      findings = findings.concat(fileFindings);
    }

    // ── 2. Scan SQL migrations for missing RLS ────────────────────────────────
    const sqlFiles = files.filter(f => path.extname(f).toLowerCase() === '.sql');
    const tablesWithRLS = new Set();
    const tablesWithoutRLS = [];

    for (const file of sqlFiles) {
      const content = this.readFile(file);
      if (!content) continue;

      // Find tables that have RLS enabled
      const rlsMatches = content.matchAll(/ALTER\s+TABLE\s+(?:(?:public|auth|storage)\.)?["']?(\w+)["']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi);
      for (const m of rlsMatches) {
        tablesWithRLS.add(m[1].toLowerCase());
      }

      // Find CREATE TABLE statements
      const createMatches = content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:public|auth|storage)\.)?["']?(\w+)["']?/gi);
      for (const m of createMatches) {
        const tableName = m[1].toLowerCase();
        // Skip Supabase internal tables
        if (['_prisma_migrations', 'schema_migrations', 'knex_migrations'].includes(tableName)) continue;

        // Check if RLS is enabled in the same file
        const rlsInFile = new RegExp(
          `ALTER\\s+TABLE\\s+(?:(?:public|auth|storage)\\.)?["']?${tableName}["']?\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
          'gi'
        ).test(content);

        if (!rlsInFile && !tablesWithRLS.has(tableName)) {
          tablesWithoutRLS.push({ table: tableName, file });
        }
      }
    }

    // Report tables missing RLS
    for (const { table, file } of tablesWithoutRLS) {
      // Double-check across all SQL files
      if (tablesWithRLS.has(table)) continue;
      findings.push(createFinding({
        file,
        line: 0,
        severity: 'critical',
        category: 'auth',
        rule: 'SUPABASE_NO_RLS_POLICY',
        title: `Supabase: Table "${table}" Missing RLS`,
        description: `Table "${table}" is created without enabling Row Level Security. Any user with the anon key can read/write all rows.`,
        matched: `CREATE TABLE ${table}`,
        fix: `Add: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\nThen create appropriate policies with CREATE POLICY.`,
      }));
    }

    return findings;
  }
}

export default SupabaseRLSAgent;
