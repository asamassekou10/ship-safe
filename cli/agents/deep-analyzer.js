/**
 * DeepAnalyzer — LLM-Powered Taint Analysis
 * ============================================
 *
 * Takes critical/high findings nominated by regex scan and sends them
 * to an LLM for deeper analysis: taint reachability, sanitization
 * verification, and exploitability assessment.
 *
 * Supports:
 *   - Anthropic API (ANTHROPIC_API_KEY)
 *   - OpenAI API (OPENAI_API_KEY)
 *   - Google Gemini (GOOGLE_API_KEY)
 *   - Ollama local models (--local flag)
 *
 * USAGE:
 *   const analyzer = new DeepAnalyzer({ provider, budgetCents: 50 });
 *   const enrichedFindings = await analyzer.analyze(findings, context);
 */

import fs from 'fs';
import path from 'path';
import { createProvider, autoDetectProvider } from '../providers/llm-provider.js';

// =============================================================================
// CONSTANTS
// =============================================================================

/** Max file content to send per finding (tokens are expensive) */
const MAX_FILE_CHARS = 4000;

/** Max findings to analyze per run (cost control) */
const MAX_FINDINGS = 30;

/** Approximate cost per 1K input tokens (Haiku pricing) */
const COST_PER_1K_INPUT = 0.08;  // cents
const COST_PER_1K_OUTPUT = 0.4;  // cents

/** Estimated tokens per finding analysis */
const EST_INPUT_TOKENS_PER_FINDING = 1500;
const EST_OUTPUT_TOKENS_PER_FINDING = 300;

// =============================================================================
// SYSTEM PROMPT
// =============================================================================

const SYSTEM_PROMPT = `You are a security code auditor performing taint analysis. For each finding, determine:

1. **Tainted**: Is the flagged value controllable by an external user (via HTTP request, file upload, CLI args, env vars, database read, etc.)?
2. **Sanitized**: Is there sanitization, validation, or encoding between the source and sink that neutralizes the risk?
3. **Exploitability**: Rate as "confirmed", "likely", "unlikely", or "false_positive".
4. **Reasoning**: One sentence explaining your verdict.

Respond with a JSON array ONLY. No markdown, no explanation outside JSON.

[{
  "findingId": "<id>",
  "tainted": true|false,
  "sanitized": true|false,
  "exploitability": "confirmed"|"likely"|"unlikely"|"false_positive",
  "reasoning": "<one sentence>"
}]

Rules:
- If the value is a hardcoded string literal with no user input path, it is NOT tainted.
- If there is a validation library (zod, joi, yup, ajv) or sanitization function between input and sink, mark sanitized=true.
- If the code is in a test file, example, or documentation, mark as false_positive.
- If you cannot determine taint flow from the provided context, mark exploitability as "unlikely" rather than guessing.
- Be conservative: only mark "confirmed" when there is a clear, unsanitized path from user input to dangerous sink.`;

// =============================================================================
// DEEP ANALYZER
// =============================================================================

export class DeepAnalyzer {
  /**
   * @param {object} options
   * @param {object} options.provider    — LLM provider instance (from createProvider)
   * @param {number} options.budgetCents — Max spend in cents (default: 50)
   * @param {boolean} options.verbose    — Log analysis progress
   */
  constructor(options = {}) {
    this.provider = options.provider || null;
    this.budgetCents = options.budgetCents ?? 50;
    this.verbose = options.verbose || false;
    this.spentCents = 0;
    this.analyzedCount = 0;
  }

  /**
   * Create a DeepAnalyzer with auto-detected provider.
   * Returns null if no provider is available.
   */
  static create(rootPath, options = {}) {
    // --local flag: use Ollama
    if (options.local) {
      const provider = createProvider('ollama', null, {
        model: options.model || 'llama3.2',
        baseUrl: options.ollamaUrl || 'http://localhost:11434/api/chat',
      });
      return new DeepAnalyzer({ provider, ...options });
    }

    // Auto-detect from env
    const provider = autoDetectProvider(rootPath);
    if (!provider) return null;

    return new DeepAnalyzer({ provider, ...options });
  }

  /**
   * Analyze findings with LLM-powered taint analysis.
   * Only processes critical/high findings to optimize cost.
   *
   * @param {object[]} findings — All findings from agents
   * @param {object}   context  — { rootPath, recon }
   * @returns {Promise<object[]>} — Findings with deepAnalysis attached
   */
  async analyze(findings, context = {}) {
    if (!this.provider) return findings;

    // Filter to critical/high only
    const candidates = findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    );

    if (candidates.length === 0) return findings;

    // Cap at MAX_FINDINGS
    const toAnalyze = candidates.slice(0, MAX_FINDINGS);

    // Check budget before starting
    const estimatedCost = this._estimateCost(toAnalyze.length);
    if (estimatedCost > this.budgetCents) {
      const affordable = Math.floor(
        this.budgetCents / (estimatedCost / toAnalyze.length)
      );
      toAnalyze.length = Math.max(1, affordable);
    }

    // Batch findings (5 per request to balance cost vs. context)
    const batchSize = 5;
    const results = new Map();

    for (let i = 0; i < toAnalyze.length; i += batchSize) {
      // Budget check before each batch
      if (this.spentCents >= this.budgetCents) {
        if (this.verbose) {
          console.log(`  Deep analysis: budget exhausted (${this.spentCents}c / ${this.budgetCents}c)`);
        }
        break;
      }

      const batch = toAnalyze.slice(i, i + batchSize);
      const prompt = this._buildPrompt(batch, context);

      try {
        const response = await this.provider.complete(
          SYSTEM_PROMPT,
          prompt,
          { maxTokens: 1500 }
        );

        // Track cost
        const inputTokens = Math.ceil(prompt.length / 4);
        const outputTokens = Math.ceil(response.length / 4);
        this.spentCents += (inputTokens / 1000) * COST_PER_1K_INPUT
                         + (outputTokens / 1000) * COST_PER_1K_OUTPUT;

        // Parse response
        const analyses = this._parseResponse(response);
        for (const analysis of analyses) {
          results.set(analysis.findingId, analysis);
        }

        this.analyzedCount += batch.length;
      } catch (err) {
        if (this.verbose) {
          console.log(`  Deep analysis batch failed: ${err.message}`);
        }
        // Continue with remaining batches
      }
    }

    // Attach deep analysis to findings
    for (const finding of findings) {
      const id = this._findingId(finding);
      const analysis = results.get(id);

      if (analysis) {
        finding.deepAnalysis = {
          tainted: analysis.tainted,
          sanitized: analysis.sanitized,
          exploitability: analysis.exploitability,
          reasoning: analysis.reasoning,
        };

        // Adjust confidence based on deep analysis
        if (analysis.exploitability === 'false_positive') {
          finding.confidence = 'low';
        } else if (analysis.exploitability === 'unlikely') {
          if (finding.confidence === 'high') finding.confidence = 'medium';
        } else if (analysis.exploitability === 'confirmed') {
          finding.confidence = 'high';
        }
      }
    }

    return findings;
  }

  /**
   * Build the analysis prompt for a batch of findings.
   */
  _buildPrompt(findings, context) {
    const items = findings.map(f => {
      const id = this._findingId(f);
      const fileContent = this._getFileContext(f);

      return {
        findingId: id,
        rule: f.rule,
        severity: f.severity,
        title: f.title,
        description: f.description,
        file: f.file ? path.basename(f.file) : 'unknown',
        line: f.line,
        matched: (f.matched || '').slice(0, 200),
        codeContext: fileContent,
      };
    });

    // Add project context if available
    let projectContext = '';
    if (context.recon) {
      const r = context.recon;
      const parts = [];
      if (r.frameworks?.length) parts.push(`Frameworks: ${r.frameworks.join(', ')}`);
      if (r.databases?.length) parts.push(`Databases: ${r.databases.join(', ')}`);
      if (r.authPatterns?.length) parts.push(`Auth: ${r.authPatterns.join(', ')}`);
      if (parts.length) projectContext = `\nProject context:\n${parts.join('\n')}\n`;
    }

    return `Analyze these ${items.length} security findings for taint reachability and exploitability.
${projectContext}
Findings:
${JSON.stringify(items, null, 2)}`;
  }

  /**
   * Get file content around the finding for LLM context.
   */
  _getFileContext(finding) {
    if (!finding.file) return '';

    try {
      const content = fs.readFileSync(finding.file, 'utf-8');
      const lines = content.split('\n');
      const lineNum = finding.line || 1;

      // Get a window of ~40 lines around the finding
      const start = Math.max(0, lineNum - 21);
      const end = Math.min(lines.length, lineNum + 20);
      let context = lines.slice(start, end)
        .map((l, i) => `${start + i + 1}: ${l}`)
        .join('\n');

      // Truncate if too long
      if (context.length > MAX_FILE_CHARS) {
        context = context.slice(0, MAX_FILE_CHARS) + '\n... (truncated)';
      }

      return context;
    } catch {
      return '';
    }
  }

  /**
   * Generate a stable ID for a finding.
   */
  _findingId(finding) {
    const file = finding.file ? path.basename(finding.file) : 'unknown';
    return `${file}:${finding.line}:${finding.rule}`;
  }

  /**
   * Parse LLM response into analysis objects.
   */
  _parseResponse(text) {
    const cleaned = text
      .replace(/^```(?:json)?\s*/i, '')
      .replace(/\s*```\s*$/i, '')
      .trim();

    try {
      const parsed = JSON.parse(cleaned);
      if (!Array.isArray(parsed)) return [];

      // Validate each entry
      return parsed.filter(item =>
        item.findingId &&
        typeof item.tainted === 'boolean' &&
        typeof item.sanitized === 'boolean' &&
        ['confirmed', 'likely', 'unlikely', 'false_positive'].includes(item.exploitability)
      );
    } catch {
      return [];
    }
  }

  /**
   * Estimate cost for analyzing N findings (in cents).
   */
  _estimateCost(count) {
    const inputCost = (count * EST_INPUT_TOKENS_PER_FINDING / 1000) * COST_PER_1K_INPUT;
    const outputCost = (count * EST_OUTPUT_TOKENS_PER_FINDING / 1000) * COST_PER_1K_OUTPUT;
    return inputCost + outputCost;
  }

  /**
   * Get analysis stats.
   */
  getStats() {
    return {
      analyzedCount: this.analyzedCount,
      spentCents: Math.round(this.spentCents * 100) / 100,
      budgetCents: this.budgetCents,
      provider: this.provider?.name || 'none',
    };
  }
}

export default DeepAnalyzer;
