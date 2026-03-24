/**
 * Threat Intelligence Feed
 * =========================
 *
 * Loads and queries ship-safe's threat intelligence database.
 * Ships with a seed file, supports offline updates.
 *
 * Data includes:
 *   - Known malicious skill hashes (ClawHavoc IOCs)
 *   - Compromised MCP server names/versions
 *   - Malicious config file signatures
 *   - Known vulnerable configurations
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SEED_PATH = path.resolve(__dirname, '..', 'data', 'threat-intel.json');
const LOCAL_CACHE = path.join(os.homedir(), '.ship-safe', 'threat-intel.json');
const DEFAULT_FEED_URL = 'https://raw.githubusercontent.com/asamassekou10/ship-safe/main/cli/data/threat-intel.json';

let _cache = null;

export class ThreatIntel {
  /**
   * Load threat intel data — prefers local cache if newer, falls back to seed.
   */
  static load() {
    if (_cache) return _cache;

    let data = null;

    // Try local cache first
    try {
      if (fs.existsSync(LOCAL_CACHE)) {
        data = JSON.parse(fs.readFileSync(LOCAL_CACHE, 'utf-8'));
      }
    } catch { /* skip */ }

    // Fall back to seed
    if (!data) {
      try {
        data = JSON.parse(fs.readFileSync(SEED_PATH, 'utf-8'));
      } catch {
        data = { version: '0.0.0', maliciousSkillHashes: [], compromisedMcpServers: [], maliciousConfigSignatures: [], knownVulnerableConfigs: [] };
      }
    }

    _cache = data;
    return data;
  }

  /**
   * Check a SHA-256 hash against known malicious skill hashes.
   * @returns {object|null} matching entry or null
   */
  static lookupHash(sha256) {
    const data = ThreatIntel.load();
    return data.maliciousSkillHashes.find(h => h.sha256 === sha256) || null;
  }

  /**
   * Check if an MCP server name/version is known compromised.
   * @returns {object|null} matching advisory or null
   */
  static lookupMcpServer(name, version = '*') {
    const data = ThreatIntel.load();
    return data.compromisedMcpServers.find(s => {
      if (s.name !== name) return false;
      if (s.versions.includes('*')) return true;
      return s.versions.some(v => {
        if (v.startsWith('<')) {
          return version < v.slice(1);
        }
        return v === version;
      });
    }) || null;
  }

  /**
   * Scan content for known malicious config signatures.
   * @returns {object[]} matching signatures
   */
  static matchSignatures(content) {
    const data = ThreatIntel.load();
    const matches = [];
    for (const sig of data.maliciousConfigSignatures) {
      try {
        const re = new RegExp(sig.pattern, 'gi');
        if (re.test(content)) {
          matches.push(sig);
        }
      } catch { /* skip bad patterns */ }
    }
    return matches;
  }

  /**
   * Compute SHA-256 hash of content.
   */
  static hash(content) {
    return createHash('sha256').update(content).digest('hex');
  }

  /**
   * Update local threat intel cache from remote feed.
   * @returns {{ updated: boolean, oldVersion: string, newVersion: string }}
   */
  static async update(feedUrl = DEFAULT_FEED_URL) {
    const current = ThreatIntel.load();
    const oldVersion = current.version;

    try {
      const response = await fetch(feedUrl);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const remote = await response.json();

      // Only update if remote is newer
      if (remote.version <= oldVersion) {
        return { updated: false, oldVersion, newVersion: oldVersion, message: 'Already up to date' };
      }

      // Write to local cache
      const cacheDir = path.dirname(LOCAL_CACHE);
      if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(LOCAL_CACHE, JSON.stringify(remote, null, 2));

      // Invalidate in-memory cache
      _cache = remote;

      return {
        updated: true,
        oldVersion,
        newVersion: remote.version,
        stats: {
          hashes: remote.maliciousSkillHashes?.length || 0,
          servers: remote.compromisedMcpServers?.length || 0,
          signatures: remote.maliciousConfigSignatures?.length || 0,
        },
      };
    } catch (err) {
      return { updated: false, oldVersion, newVersion: oldVersion, error: err.message };
    }
  }

  /**
   * Get summary stats of loaded intel data.
   */
  static stats() {
    const data = ThreatIntel.load();
    return {
      version: data.version,
      updated: data.updated,
      hashes: data.maliciousSkillHashes?.length || 0,
      servers: data.compromisedMcpServers?.length || 0,
      signatures: data.maliciousConfigSignatures?.length || 0,
      configs: data.knownVulnerableConfigs?.length || 0,
    };
  }
}
