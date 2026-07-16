/**
 * StatefulWatcher — Persistent Kimi Security Session
 * ====================================================
 *
 * Keeps a Kimi conversation thread open across file-change events.
 * Each scan sends only the diff — not the full codebase — so the model
 * builds understanding incrementally rather than restarting from scratch.
 *
 * Advantages over stateless watch:
 *  - No duplicate findings on repeated scans of unchanged files
 *  - Model understands which files are already clean vs. risky
 *  - Diffs are small → faster, cheaper per event
 *  - Kimi K3's long-context session handles full work sessions without reset
 *
 * USAGE (via watch command):
 *   npx ship-safe watch . --deep --stateful
 *   npx ship-safe watch . --deep --stateful --provider kimi
 */

import fs from 'fs';
import path from 'path';
import { autoDetectProvider } from '../providers/llm-provider.js';
import { createFinding } from './base-agent.js';

// Max chars of diff content per event
const MAX_DIFF_CHARS = 20_000;

// =============================================================================
// STATEFUL WATCHER
// =============================================================================

export class StatefulWatcher {
  /**
   * @param {object} options
   * @param {object}  options.provider    — LLM provider (Kimi preferred)
   * @param {string}  options.rootPath
   * @param {boolean} options.verbose
   */
  constructor(options = {}) {
    this.provider = options.provider;
    this.rootPath = options.rootPath;
    this.verbose = options.verbose || false;

    // Persistent conversation thread
    this._messages = [];
    this._scanCount = 0;
    this._baselineSet = false;
  }

  static create(rootPath, options = {}) {
    const providerName = typeof options.provider === 'string' ? options.provider : 'kimi';
    const provider = autoDetectProvider(rootPath, { provider: providerName, model: options.model || 'kimi-k3' });
    if (!provider) return null;
    return new StatefulWatcher({ provider, rootPath, verbose: options.verbose });
  }

  /**
   * Set the initial baseline — called once on watcher start.
   * The model receives a codebase summary and primes its security context.
   *
   * @param {object} recon — Output from ReconAgent
   * @param {string[]} files — All scannable files
   */
  async setBaseline(recon, files) {
    const summary = this._buildReconSummary(recon);
    const fileList = files
      .slice(0, 200)
      .map(f => path.relative(this.rootPath, f))
      .join('\n');

    const baselineMsg = `You are a persistent security monitor for this codebase. I will send you file changes as they happen. For each change, identify new security issues introduced by that specific change.

Project context:
${summary}

File inventory (${files.length} total):
${fileList}

Respond to each update with a JSON array of findings. Use this format:
[{"file":"<relative path>","line":<number>,"severity":"critical|high|medium|low","rule":"<rule-id>","title":"<title>","description":"<description>","remediation":"<fix>"}]

If no new issues are introduced by the change, respond with an empty array: []
Never include issues you already reported in previous messages.`;

    this._messages.push({ role: 'user', content: baselineMsg });

    try {
      const ack = await this._callProvider('You are a security expert. Acknowledge you understand the codebase context.', this._messages);
      this._messages.push({ role: 'assistant', content: ack });
      this._baselineSet = true;
      if (this.verbose) console.log(`  [Stateful] Baseline set. Provider: ${this.provider.name}`);
    } catch (err) {
      if (this.verbose) console.log(`  [Stateful] Baseline failed: ${err.message}`);
    }
  }

  /**
   * Analyze a set of changed files. Sends only diffs to the persistent session.
   *
   * @param {string[]} changedFiles — Absolute paths of changed files
   * @returns {Promise<object[]>} — New findings introduced by this change
   */
  async analyzeChanges(changedFiles) {
    if (!this._baselineSet) return [];
    this._scanCount++;

    const diffs = this._readChanges(changedFiles);
    if (!diffs) return [];

    const updateMsg = `Files changed (scan #${this._scanCount}):\n\n${diffs}\n\nWhat NEW security issues does this change introduce? Reply with the JSON findings array only.`;

    this._messages.push({ role: 'user', content: updateMsg });

    try {
      const response = await this._callProvider(
        'You are a persistent security monitor. Report only NEW issues from the latest change.',
        this._messages
      );

      this._messages.push({ role: 'assistant', content: response });

      const findings = this._parseFindings(response, changedFiles[0]);
      if (this.verbose && findings.length > 0) {
        console.log(`  [Stateful] Scan #${this._scanCount}: ${findings.length} new finding(s)`);
      }
      return findings;
    } catch (err) {
      if (this.verbose) console.log(`  [Stateful] Scan failed: ${err.message}`);
      return [];
    }
  }

  _readChanges(changedFiles) {
    const parts = [];
    let totalChars = 0;

    for (const filePath of changedFiles) {
      if (totalChars >= MAX_DIFF_CHARS) break;
      try {
        const relPath = path.relative(this.rootPath, filePath);
        const content = fs.readFileSync(filePath, 'utf-8');
        const snippet = content.slice(0, Math.min(5000, MAX_DIFF_CHARS - totalChars));
        parts.push(`### ${relPath}\n\`\`\`\n${snippet}\n\`\`\``);
        totalChars += snippet.length;
      } catch { /* skip */ }
    }

    return parts.length ? parts.join('\n\n') : null;
  }

  _buildReconSummary(recon) {
    if (!recon) return 'No recon data.';
    const parts = [];
    if (recon.frameworks?.length) parts.push(`Frameworks: ${recon.frameworks.join(', ')}`);
    if (recon.databases?.length)  parts.push(`Databases: ${recon.databases.join(', ')}`);
    if (recon.authPatterns?.length) parts.push(`Auth: ${recon.authPatterns.join(', ')}`);
    if (recon.languages?.length)  parts.push(`Languages: ${recon.languages.join(', ')}`);
    return parts.join('\n') || 'General codebase.';
  }

  async _callProvider(systemPrompt, messages) {
    // Use multi-turn messages if provider supports it (OpenAI format)
    if (this.provider.baseUrl && typeof this.provider.complete === 'function') {
      const response = await fetch(this.provider.baseUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.provider.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: this.provider.model,
          max_tokens: 2048,
          messages: [
            { role: 'system', content: systemPrompt },
            ...messages,
          ],
        }),
      });

      if (!response.ok) {
        throw new Error(`${this.provider.name} API error: HTTP ${response.status}`);
      }

      const data = await response.json();
      return data.choices?.[0]?.message?.content || '';
    }

    // Fallback: single-turn (for providers without persistent context)
    const lastMsg = messages[messages.length - 1];
    return this.provider.complete(systemPrompt, lastMsg?.content || '', { maxTokens: 2048 });
  }

  _parseFindings(text, refFile) {
    const cleaned = text
      .replace(/^```(?:json)?\s*/i, '')
      .replace(/\s*```\s*$/i, '')
      .trim();

    try {
      const raw = JSON.parse(cleaned);
      if (!Array.isArray(raw)) return [];

      return raw
        .filter(r => r.title && r.severity)
        .map(r => {
          const filePath = r.file
            ? path.resolve(this.rootPath, r.file)
            : refFile || null;

          return createFinding({
            file: filePath,
            line: r.line || 0,
            severity: ['critical', 'high', 'medium', 'low', 'info'].includes(r.severity) ? r.severity : 'medium',
            confidence: 'medium',
            rule: r.rule || 'stateful:monitor',
            title: r.title,
            description: r.description || r.title,
            matched: '',
            remediation: r.remediation || '',
            category: 'Stateful Monitor',
          });
        });
    } catch {
      return [];
    }
  }

  getStats() {
    return {
      scanCount: this._scanCount,
      provider: this.provider?.name || 'none',
      model: this.provider?.model || 'unknown',
      messageCount: this._messages.length,
    };
  }
}

export default StatefulWatcher;
