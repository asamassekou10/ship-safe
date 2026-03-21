/**
 * Cache Manager
 * =============
 *
 * Provides incremental scanning by caching file hashes and findings.
 * On subsequent runs, only changed files are re-scanned.
 *
 * Cache location: .ship-safe/context.json
 *
 * USAGE:
 *   import { CacheManager } from './cache-manager.js';
 *   const cache = new CacheManager(rootPath);
 *   const { changedFiles, cachedFindings } = await cache.getChangedFiles(currentFiles);
 *   // ... scan only changedFiles ...
 *   cache.save(allFiles, allFindings, recon, scoreResult);
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Read version from package.json
const __filename = fileURLToPath(import.meta.url); // ship-safe-ignore — module's own path via import.meta.url, not user input
const __dirname = dirname(__filename);
const PACKAGE_VERSION = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8')).version;

// Cache TTL: 24 hours
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export class CacheManager {
  /**
   * @param {string} rootPath — Absolute path to project root
   */
  constructor(rootPath) {
    this.rootPath = rootPath;
    this.cacheDir = path.join(rootPath, '.ship-safe');
    this.cachePath = path.join(this.cacheDir, 'context.json');
    this.cache = null;
  }

  /**
   * Load the cache from disk. Returns null if cache is missing, expired, or invalid.
   */
  load() {
    try {
      if (!fs.existsSync(this.cachePath)) return null;

      const raw = fs.readFileSync(this.cachePath, 'utf-8');
      const cache = JSON.parse(raw);

      // Version mismatch — patterns may have changed
      if (cache.version !== PACKAGE_VERSION) return null;

      // TTL expired
      const age = Date.now() - new Date(cache.generatedAt).getTime();
      if (age > CACHE_TTL_MS) return null;

      this.cache = cache;
      return cache;
    } catch {
      return null;
    }
  }

  /**
   * Compute SHA-256 hash of a file's contents.
   */
  hashFile(filePath) {
    try {
      const content = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch {
      return null;
    }
  }

  /**
   * Compare current files against cached file index to find what changed.
   *
   * @param {string[]} currentFiles — Array of absolute file paths
   * @returns {{ changedFiles: string[], cachedFindings: object[], unchangedCount: number, newCount: number, modifiedCount: number, deletedCount: number }}
   */
  diff(currentFiles) {
    if (!this.cache || !this.cache.fileIndex) {
      return {
        changedFiles: currentFiles,
        cachedFindings: [],
        unchangedCount: 0,
        newCount: currentFiles.length,
        modifiedCount: 0,
        deletedCount: 0,
      };
    }

    const cachedIndex = this.cache.fileIndex;
    const cachedFindings = this.cache.lastFindings || {};
    const changedFiles = [];
    const reusedFindings = [];
    let unchangedCount = 0;
    let newCount = 0;
    let modifiedCount = 0;

    const currentSet = new Set(currentFiles);

    for (const file of currentFiles) {
      const relPath = path.relative(this.rootPath, file).replace(/\\/g, '/');
      const cached = cachedIndex[relPath];

      if (!cached) {
        // New file — needs scanning
        changedFiles.push(file);
        newCount++;
        continue;
      }

      // Quick size check before expensive hash
      try {
        const stats = fs.statSync(file);
        if (stats.size !== cached.size) {
          changedFiles.push(file);
          modifiedCount++;
          continue;
        }
      } catch {
        changedFiles.push(file);
        modifiedCount++;
        continue;
      }

      // Hash check
      const currentHash = this.hashFile(file);
      if (currentHash !== cached.hash) {
        changedFiles.push(file);
        modifiedCount++;
        continue;
      }

      // File unchanged — reuse cached findings
      unchangedCount++;
      if (cachedFindings[relPath]) {
        // Restore absolute paths for cached findings
        for (const finding of cachedFindings[relPath]) {
          reusedFindings.push({ ...finding, file });
        }
      }
    }

    // Count deleted files (in cache but not in current)
    const currentRelPaths = new Set(
      currentFiles.map(f => path.relative(this.rootPath, f).replace(/\\/g, '/'))
    );
    const deletedCount = Object.keys(cachedIndex).filter(p => !currentRelPaths.has(p)).length;

    return {
      changedFiles,
      cachedFindings: reusedFindings,
      unchangedCount,
      newCount,
      modifiedCount,
      deletedCount,
    };
  }

  /**
   * Save the cache to disk.
   *
   * @param {string[]} allFiles — All scanned file paths
   * @param {object[]} allFindings — All findings from the scan
   * @param {object} recon — ReconAgent output
   * @param {object} [scoreResult] — Optional score result
   */
  save(allFiles, allFindings, recon, scoreResult) {
    try {
      // Ensure .ship-safe directory exists
      if (!fs.existsSync(this.cacheDir)) {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      }

      // Build file index with hashes
      const fileIndex = {};
      for (const file of allFiles) {
        const relPath = path.relative(this.rootPath, file).replace(/\\/g, '/');
        const hash = this.hashFile(file);
        if (hash) {
          try {
            const stats = fs.statSync(file);
            fileIndex[relPath] = {
              hash,
              size: stats.size,
              lastScanned: new Date().toISOString(),
            };
          } catch {
            // Skip files we can't stat
          }
        }
      }

      // Group findings by file (relative paths)
      const lastFindings = {};
      for (const f of allFindings) {
        const relPath = path.relative(this.rootPath, f.file).replace(/\\/g, '/');
        if (!lastFindings[relPath]) lastFindings[relPath] = [];
        // Store a lightweight copy (no absolute paths)
        lastFindings[relPath].push({
          line: f.line,
          column: f.column,
          severity: f.severity,
          category: f.category,
          rule: f.rule,
          title: f.title,
          description: f.description,
          matched: f.matched,
          confidence: f.confidence,
          cwe: f.cwe,
          owasp: f.owasp,
          fix: f.fix,
        });
      }

      const cache = {
        version: PACKAGE_VERSION,
        generatedAt: new Date().toISOString(),
        rootPath: this.rootPath,
        recon: recon || null,
        fileIndex,
        lastFindings,
        stats: {
          totalFiles: allFiles.length,
          totalFindings: allFindings.length,
          lastScore: scoreResult?.score ?? null,
          lastGrade: scoreResult?.grade?.letter ?? null,
        },
      };

      fs.writeFileSync(this.cachePath, JSON.stringify(cache, null, 2));
    } catch {
      // Silent failure — caching should never break a scan
    }
  }

  /**
   * Delete the cache file.
   */
  invalidate() {
    try {
      if (fs.existsSync(this.cachePath)) {
        fs.unlinkSync(this.cachePath);
      }
    } catch {
      // Silent
    }
  }

  // ===========================================================================
  // LLM CLASSIFICATION CACHE
  // ===========================================================================

  get llmCachePath() {
    return path.join(this.cacheDir, 'llm-cache.json');
  }

  /**
   * Generate a cache key for an LLM classification.
   */
  getLLMCacheKey(finding) {
    const data = `${finding.file}:${finding.line}:${finding.rule}:${finding.matched || ''}`;
    return crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);
  }

  /**
   * Load cached LLM classifications. Returns {} if none or expired.
   */
  loadLLMClassifications() {
    const LLM_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
    try {
      if (!fs.existsSync(this.llmCachePath)) return {};
      const raw = JSON.parse(fs.readFileSync(this.llmCachePath, 'utf-8'));
      const now = Date.now();
      const valid = {};
      for (const [key, entry] of Object.entries(raw)) {
        if (now - new Date(entry.cachedAt).getTime() < LLM_CACHE_TTL) {
          valid[key] = entry;
        }
      }
      return valid;
    } catch {
      return {};
    }
  }

  /**
   * Save LLM classifications to cache.
   */
  saveLLMClassifications(classifications) {
    try {
      if (!fs.existsSync(this.cacheDir)) {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      }
      const existing = this.loadLLMClassifications();
      const merged = { ...existing, ...classifications };
      fs.writeFileSync(this.llmCachePath, JSON.stringify(merged, null, 2));
    } catch {
      // Silent
    }
  }
}

export default CacheManager;
