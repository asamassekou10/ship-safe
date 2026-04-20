/**
 * DeepAnalyzer — Multi-Tier LLM-Powered Taint Analysis
 * ======================================================
 *
 * Hermes-inspired three-tier analysis pipeline:
 *
 *   Tier 1  (Haiku / cheap model)  — Fast triage of all critical+high findings.
 *           Labels each finding: "skip" | "review" | "escalate".
 *           Skips obvious false-positives early and cheaply.
 *
 *   Tier 2  (Sonnet / mid model)   — Deep taint analysis of "review" findings.
 *           Full file context, sanitization checking, exploitability rating.
 *
 *   Tier 3  (Opus / frontier model) — Full exploit-chain reasoning for "escalate"
 *           findings (confirmed critical severity with untrusted input path).
 *           Returns attack vector, business impact, and exact fix.
 *
 * When only one provider/model is configured (non-Anthropic), the pipeline falls
 * back gracefully to a single-tier analysis identical to the previous behavior.
 *
 * Structured output:
 *   When the provider is AnthropicProvider, all LLM calls use the tool-use API
 *   (tool_choice: forced) which guarantees JSON matching the schema — no regex
 *   cleanup, no silent dropped findings.
 *
 * Supports:
 *   - Anthropic API (ANTHROPIC_API_KEY) — full multi-tier + structured output
 *   - OpenAI API (OPENAI_API_KEY)       — single-tier, text parsing
 *   - Google Gemini (GOOGLE_API_KEY)    — single-tier, text parsing
 *   - Ollama / Gemma4 (--local)         — large context, schema-enforced output
 *
 * USAGE:
 *   const analyzer = new DeepAnalyzer({ provider, budgetCents: 50 });
 *   const enrichedFindings = await analyzer.analyze(findings, context);
 */

import fs from 'fs';
import path from 'path';
import { createProvider, autoDetectProvider } from '../providers/llm-provider.js';

// Lazy-import ScanPlaybook to avoid circular dep; only used when rootPath is known
let _ScanPlaybook = null;
async function getScanPlaybook() {
  if (!_ScanPlaybook) {
    const mod = await import('../utils/scan-playbook.js');
    _ScanPlaybook = mod.ScanPlaybook;
  }
  return _ScanPlaybook;
}

// =============================================================================
// CONSTANTS
// =============================================================================

/** Max file content per finding for standard providers */
const MAX_FILE_CHARS_DEFAULT = 4000;

/** Max file content per finding for large-context providers (Gemma 4 128K–256K) */
const MAX_FILE_CHARS_LARGE_CTX = 80000;

/** Max findings to analyze per run (cost control) */
const MAX_FINDINGS = 30;

// Approximate cost per 1K tokens (Haiku pricing used as baseline)
const COST_PER_1K_INPUT  = 0.08;  // cents
const COST_PER_1K_OUTPUT = 0.4;   // cents

const EST_INPUT_TOKENS_PER_FINDING  = 1500;
const EST_OUTPUT_TOKENS_PER_FINDING = 300;

// Multi-tier Anthropic model IDs
const TIER1_MODEL = 'claude-haiku-4-5-20251001';   // fast triage
const TIER2_MODEL = 'claude-sonnet-4-6';           // deep analysis
const TIER3_MODEL = 'claude-opus-4-6';             // exploit chain

// =============================================================================
// JSON SCHEMAS — used with Anthropic tool-use for guaranteed output
// =============================================================================

/** Tier 1: quick triage schema */
const TRIAGE_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          findingId:  { type: 'string' },
          tier:       { type: 'string', enum: ['skip', 'review', 'escalate'] },
          reason:     { type: 'string' },
        },
        required: ['findingId', 'tier', 'reason'],
        additionalProperties: false,
      },
    },
  },
  required: ['results'],
};

/** Tier 2: deep analysis schema */
const DEEP_ANALYSIS_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          findingId:      { type: 'string' },
          tainted:        { type: 'boolean' },
          sanitized:      { type: 'boolean' },
          exploitability: { type: 'string', enum: ['confirmed', 'likely', 'unlikely', 'false_positive'] },
          reasoning:      { type: 'string' },
        },
        required: ['findingId', 'tainted', 'sanitized', 'exploitability', 'reasoning'],
        additionalProperties: false,
      },
    },
  },
  required: ['results'],
};

/** Tier 3: exploit-chain schema */
const EXPLOIT_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          findingId:      { type: 'string' },
          tainted:        { type: 'boolean' },
          sanitized:      { type: 'boolean' },
          exploitability: { type: 'string', enum: ['confirmed', 'likely', 'unlikely', 'false_positive'] },
          reasoning:      { type: 'string' },
          attackVector:   { type: 'string' },
          businessImpact: { type: 'string' },
          fix:            { type: 'string' },
        },
        required: ['findingId', 'tainted', 'sanitized', 'exploitability', 'reasoning', 'attackVector', 'businessImpact', 'fix'],
        additionalProperties: false,
      },
    },
  },
  required: ['results'],
};

// =============================================================================
// SYSTEM PROMPTS
// =============================================================================

const TRIAGE_SYSTEM = `You are a fast security triage assistant. For each finding, quickly decide:
- "skip"     — Obvious false positive (hardcoded literal, test file, sanitized value, documentation).
- "review"   — Needs deeper analysis. Possibly tainted user input reaching a dangerous sink.
- "escalate" — Clear, unsanitized path from user-controlled input to a critical sink (SQL query, shell exec, file write, deserialization). Escalate only when confident.

Be conservative: prefer "review" over "escalate" when unsure.`;

const DEEP_SYSTEM = `You are a security code auditor performing taint analysis. For each finding, determine:

1. Tainted: Is the flagged value controllable by an external user (HTTP request, file upload, CLI args, env vars, DB read)?
2. Sanitized: Is there sanitization, validation, or encoding between source and sink that neutralizes the risk?
3. Exploitability: "confirmed" | "likely" | "unlikely" | "false_positive"
4. Reasoning: One concise sentence explaining your verdict.

Rules:
- Hardcoded string literals with no user input path → NOT tainted.
- Validation library (zod, joi, yup, ajv) or sanitize function between input and sink → sanitized=true.
- Test/example/documentation file → false_positive.
- Cannot determine taint flow from provided context → "unlikely".
- Only "confirmed" when there is a clear, unsanitized path from user input to dangerous sink.`;

const EXPLOIT_SYSTEM = `You are an expert security researcher performing full exploit-chain analysis. For each confirmed critical finding:

1. Trace the complete attack vector from attacker-controlled input to dangerous sink.
2. Assess the real-world business impact (data breach, account takeover, RCE, etc.).
3. Write a precise, actionable fix (code change, library call, or config update).
4. Rate exploitability as "confirmed" only if the path is fully unsanitized; otherwise "likely".

Be specific. Code references, line numbers, and exact fix suggestions are expected.`;

// Fallback system prompt for non-tiered (single provider) analysis
const SINGLE_TIER_SYSTEM = `You are a security code auditor performing taint analysis. For each finding, determine:

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
   * @param {object}  options.provider    — LLM provider instance (from createProvider)
   * @param {number}  options.budgetCents — Max spend in cents (default: 50)
   * @param {boolean} options.verbose     — Log analysis progress
   */
  constructor(options = {}) {
    this.provider = options.provider || null;
    this.budgetCents = options.budgetCents ?? 50;
    this.verbose = options.verbose || false;
    this.spentCents = 0;
    this.analyzedCount = 0;
    this._tier2Count = 0;
    this._tier3Count = 0;
    this._skippedCount = 0;

    // Large-context mode for local models (Gemma 4, etc.)
    const ctxWindow = this.provider?.contextWindow ?? 0;
    this.largeContext = ctxWindow >= 65536;
    this.maxFileChars = this.largeContext ? MAX_FILE_CHARS_LARGE_CTX : MAX_FILE_CHARS_DEFAULT;
    this.batchSize = this.largeContext ? 15 : 5;

    // Whether we can use multi-tier structured output routing
    this._isAnthropic = this.provider?.name === 'Anthropic';
    this._supportsTools = this._isAnthropic || this.provider?.supportsStructuredOutput === true;
  }

  /**
   * Create a DeepAnalyzer with auto-detected provider.
   * Returns null if no provider is available.
   */
  static create(rootPath, options = {}) {
    if (options.local) {
      const provider = createProvider('gemma4', null, {
        model:   options.model,
        baseUrl: options.ollamaUrl,
      });
      return new DeepAnalyzer({ provider, ...options });
    }

    const provider = autoDetectProvider(rootPath, {
      provider: options.provider,
      baseUrl:  options.baseUrl,
      model:    options.model,
    });
    if (!provider) return null;

    return new DeepAnalyzer({ provider, ...options });
  }

  /**
   * Analyze findings with LLM-powered taint analysis.
   * Uses multi-tier pipeline when Anthropic is detected; single-tier otherwise.
   *
   * @param {object[]} findings — All findings from agents
   * @param {object}   context  — { rootPath, recon }
   * @returns {Promise<object[]>} — Findings with deepAnalysis attached
   */
  async analyze(findings, context = {}) {
    if (!this.provider) return findings;

    // Load playbook context once — injected into all LLM calls for this run
    if (context.rootPath) {
      try {
        const PlaybookClass = await getScanPlaybook();
        const playbook = new PlaybookClass(context.rootPath);
        this._playbookContext = playbook.getPromptContext();
      } catch { this._playbookContext = ''; }
    }

    // Only analyze critical/high findings
    const candidates = findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    );
    if (candidates.length === 0) return findings;

    // Cap at MAX_FINDINGS with budget scaling
    const toAnalyze = candidates.slice(0, MAX_FINDINGS);
    const estimatedCost = this._estimateCost(toAnalyze.length);
    if (estimatedCost > this.budgetCents) {
      const affordable = Math.floor(this.budgetCents / (estimatedCost / toAnalyze.length));
      toAnalyze.length = Math.max(1, affordable);
    }

    const results = this._supportsTools
      ? await this._analyzeTiered(toAnalyze, context)
      : await this._analyzeSingleTier(toAnalyze, context);

    // Attach deep analysis to findings
    for (const finding of findings) {
      const id = this._findingId(finding);
      const analysis = results.get(id);
      if (analysis) {
        finding.deepAnalysis = {
          tainted:        analysis.tainted,
          sanitized:      analysis.sanitized,
          exploitability: analysis.exploitability,
          reasoning:      analysis.reasoning,
          ...(analysis.attackVector   ? { attackVector:   analysis.attackVector }   : {}),
          ...(analysis.businessImpact ? { businessImpact: analysis.businessImpact } : {}),
          ...(analysis.fix            ? { fix:            analysis.fix }            : {}),
        };

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

  // ===========================================================================
  // MULTI-TIER PIPELINE (Anthropic only)
  // ===========================================================================

  async _analyzeTiered(findings, context) {
    const results = new Map();

    // Model selection: Anthropic uses tier-specific models; others use provider's default
    const tier1Model = this._isAnthropic ? TIER1_MODEL : null;
    const tier2Model = this._isAnthropic ? TIER2_MODEL : null;
    const tier3Model = this._isAnthropic ? TIER3_MODEL : null;
    const providerLabel = this._isAnthropic ? 'Haiku' : this.provider.name;

    // ── Tier 1: Haiku triage ────────────────────────────────────────────────
    if (this.verbose) console.log(`  [Tier 1] Triaging ${findings.length} findings with ${providerLabel}...`);

    const triageMap = await this._runTriage(findings, context, tier1Model);

    const toReview   = findings.filter(f => triageMap.get(this._findingId(f)) === 'review');
    const toEscalate = findings.filter(f => triageMap.get(this._findingId(f)) === 'escalate');
    const skipped    = findings.length - toReview.length - toEscalate.length;

    this._skippedCount += skipped;

    if (this.verbose) {
      console.log(`  [Tier 1] Results: ${toEscalate.length} escalate, ${toReview.length} review, ${skipped} skip`);
    }

    // ── Tier 2: Sonnet deep analysis ────────────────────────────────────────
    if (toReview.length > 0 && this.spentCents < this.budgetCents) {
      const tier2Label = this._isAnthropic ? 'Sonnet' : this.provider.name;
      if (this.verbose) console.log(`  [Tier 2] Deep-analyzing ${toReview.length} findings with ${tier2Label}...`);
      const tier2Results = await this._runDeepAnalysis(toReview, context, tier2Model);
      for (const [id, analysis] of tier2Results) results.set(id, analysis);
      this._tier2Count += toReview.length;
    }

    // ── Tier 3: Opus exploit chain ──────────────────────────────────────────
    if (toEscalate.length > 0 && this.spentCents < this.budgetCents) {
      const tier3Label = this._isAnthropic ? 'Opus' : this.provider.name;
      if (this.verbose) console.log(`  [Tier 3] Running exploit-chain analysis on ${toEscalate.length} findings with ${tier3Label}...`);
      const tier3Results = await this._runExploitChain(toEscalate, context, tier3Model);
      for (const [id, analysis] of tier3Results) results.set(id, analysis);
      this._tier3Count += toEscalate.length;
    }

    this.analyzedCount += findings.length - skipped;
    return results;
  }

  /** Tier 1: quick triage — returns Map<findingId, 'skip'|'review'|'escalate'> */
  async _runTriage(findings, context, model = null) {
    const triageMap = new Map();
    // Default everything to 'review' so nothing is silently dropped on error
    for (const f of findings) triageMap.set(this._findingId(f), 'review');

    const batchSize = 10; // Haiku can handle larger batches
    for (let i = 0; i < findings.length; i += batchSize) {
      if (this.spentCents >= this.budgetCents) break;
      const batch = findings.slice(i, i + batchSize);
      // Tier 1 is about cheap, fast signal — no file context, metadata only.
      // File context is fetched only in Tier 2+ where it's worth the token cost.
      const items = batch.map(f => ({
        findingId: this._findingId(f),
        rule: f.rule,
        severity: f.severity,
        title: f.title,
        file: f.file ? path.basename(f.file) : 'unknown',
        line: f.line,
        matched: (f.matched || '').slice(0, 200),
        description: (f.description || '').slice(0, 120),
      }));

      const prompt = `Triage these ${items.length} security findings. For each, decide: "skip" (obvious false-positive), "review" (needs deeper analysis), or "escalate" (confirmed critical, clear user-input-to-dangerous-sink path).\n\nFindings:\n${JSON.stringify(items, null, 2)}`;

      try {
        const result = await this.provider.completeWithTools(
          TRIAGE_SYSTEM,
          prompt,
          'triage_findings',
          TRIAGE_SCHEMA,
          { maxTokens: 1024, ...(model ? { model } : {}) }
        );

        this._trackCost(prompt.length, JSON.stringify(result || '').length);

        for (const item of (result?.results ?? [])) {
          if (triageMap.has(item.findingId)) {
            triageMap.set(item.findingId, item.tier);
          }
        }
      } catch (err) {
        if (this.verbose) console.log(`  [Tier 1] Batch failed: ${err.message}`);
      }
    }

    return triageMap;
  }

  /** Tier 2: deep taint analysis — returns Map<findingId, analysis> */
  async _runDeepAnalysis(findings, context, model = null) {
    const results = new Map();

    for (let i = 0; i < findings.length; i += this.batchSize) {
      if (this.spentCents >= this.budgetCents) break;
      const batch = findings.slice(i, i + this.batchSize);
      const items = batch.map(f => ({
        findingId: this._findingId(f),
        rule: f.rule,
        severity: f.severity,
        title: f.title,
        description: f.description,
        file: f.file ? path.basename(f.file) : 'unknown',
        line: f.line,
        matched: (f.matched || '').slice(0, 200),
        codeContext: this._getFileContext(f),
      }));

      let projectContext = this._buildProjectContext(context);
      const prompt = `Analyze these ${items.length} security findings for taint reachability and exploitability.${projectContext}\n\nFindings:\n${JSON.stringify(items, null, 2)}`;

      try {
        const result = await this.provider.completeWithTools(
          DEEP_SYSTEM,
          prompt,
          'report_analysis',
          DEEP_ANALYSIS_SCHEMA,
          { maxTokens: 1500, ...(model ? { model } : {}) }
        );

        this._trackCost(prompt.length, JSON.stringify(result || '').length);

        for (const item of (result?.results ?? [])) {
          results.set(item.findingId, item);
        }
      } catch (err) {
        if (this.verbose) console.log(`  [Tier 2] Batch failed: ${err.message}`);
        // Fallback: try plain text completion + parse
        try {
          const fallbackResult = await this._runSingleTierBatch(batch, context, model);
          for (const [id, analysis] of fallbackResult) results.set(id, analysis);
        } catch { /* ignore */ }
      }
    }

    return results;
  }

  /** Tier 3: exploit-chain analysis — returns Map<findingId, analysis> */
  async _runExploitChain(findings, context, model = null) {
    const results = new Map();

    // Single findings per call for maximum depth
    for (const finding of findings) {
      if (this.spentCents >= this.budgetCents) break;

      const item = {
        findingId: this._findingId(finding),
        rule: finding.rule,
        severity: finding.severity,
        title: finding.title,
        description: finding.description,
        file: finding.file ? path.basename(finding.file) : 'unknown',
        line: finding.line,
        matched: (finding.matched || '').slice(0, 400),
        codeContext: this._getFileContext(finding), // Full context window
      };

      const prompt = `Perform full exploit-chain analysis on this security finding.\n\nFinding:\n${JSON.stringify(item, null, 2)}`;

      try {
        const result = await this.provider.completeWithTools(
          EXPLOIT_SYSTEM,
          prompt,
          'report_exploit_chain',
          EXPLOIT_SCHEMA,
          { maxTokens: 2048, ...(model ? { model } : {}) }
        );

        this._trackCost(prompt.length, JSON.stringify(result || '').length);

        for (const analysis of (result?.results ?? [])) {
          results.set(analysis.findingId, analysis);
        }
      } catch (err) {
        if (this.verbose) console.log(`  [Tier 3] Failed for ${item.findingId}: ${err.message}`);
        // Fallback to Tier 2 analysis on error
        try {
          const fallback = await this._runDeepAnalysis([finding], context, this._isAnthropic ? TIER2_MODEL : null);
          for (const [id, analysis] of fallback) results.set(id, analysis);
        } catch { /* ignore */ }
      }
    }

    return results;
  }

  // ===========================================================================
  // SINGLE-TIER PIPELINE (non-Anthropic providers)
  // ===========================================================================

  async _analyzeSingleTier(findings, context) {
    const results = new Map();

    for (let i = 0; i < findings.length; i += this.batchSize) {
      if (this.spentCents >= this.budgetCents) {
        if (this.verbose) console.log(`  Deep analysis: budget exhausted (${this.spentCents}c / ${this.budgetCents}c)`);
        break;
      }

      const batch = findings.slice(i, i + this.batchSize);
      try {
        const batchResults = await this._runSingleTierBatch(batch, context);
        for (const [id, analysis] of batchResults) results.set(id, analysis);
        this.analyzedCount += batch.length;
      } catch (err) {
        if (this.verbose) console.log(`  Deep analysis batch failed: ${err.message}`);
        // Continue with remaining batches
      }
    }

    return results;
  }

  async _runSingleTierBatch(batch, context, model = null) {
    const results = new Map();
    const prompt = this._buildSingleTierPrompt(batch, context);

    const response = await this.provider.complete(
      SINGLE_TIER_SYSTEM,
      prompt,
      { maxTokens: 1500, ...(model ? { model } : {}) }
    );

    this._trackCost(prompt.length, response.length);

    const analyses = this._parseTextResponse(response);
    for (const analysis of analyses) {
      results.set(analysis.findingId, analysis);
    }
    return results;
  }

  _buildSingleTierPrompt(findings, context) {
    const items = findings.map(f => ({
      findingId: this._findingId(f),
      rule: f.rule,
      severity: f.severity,
      title: f.title,
      description: f.description,
      file: f.file ? path.basename(f.file) : 'unknown',
      line: f.line,
      matched: (f.matched || '').slice(0, 200),
      codeContext: this._getFileContext(f),
    }));

    const projectContext = this._buildProjectContext(context);
    return `Analyze these ${items.length} security findings for taint reachability and exploitability.${projectContext}\n\nFindings:\n${JSON.stringify(items, null, 2)}`;
  }

  // ===========================================================================
  // HELPERS
  // ===========================================================================

  _buildProjectContext(context) {
    const parts = [];

    // Playbook context (accumulated across scans — richer than single-run recon)
    if (context.rootPath) {
      try {
        // Use cached playbook context if available (set by analyze())
        if (this._playbookContext) {
          parts.push(`Repo playbook:\n${this._playbookContext}`);
        }
      } catch { /* ignore */ }
    }

    // Single-run recon context
    if (context.recon) {
      const r = context.recon;
      const reconParts = [];
      if (r.frameworks?.length) reconParts.push(`Frameworks: ${r.frameworks.join(', ')}`);
      if (r.databases?.length)  reconParts.push(`Databases: ${r.databases.join(', ')}`);
      if (r.authPatterns?.length) reconParts.push(`Auth: ${r.authPatterns.join(', ')}`);
      if (reconParts.length) parts.push(reconParts.join('\n'));
    }

    return parts.length ? `\n\nProject context:\n${parts.join('\n\n')}` : '';
  }

  /**
   * Get file content around the finding for LLM context.
   * @param {object} finding
   * @param {number} windowLines — Lines before/after (default: 20 = 40 line window)
   */
  _getFileContext(finding, windowLines = 20) {
    if (!finding.file) return '';

    try {
      const content = fs.readFileSync(finding.file, 'utf-8');
      const lines = content.split('\n');
      const lineNum = finding.line || 1;

      let context;
      if (this.largeContext) {
        context = lines.map((l, i) => `${i + 1}: ${l}`).join('\n');
      } else {
        const start = Math.max(0, lineNum - windowLines - 1);
        const end   = Math.min(lines.length, lineNum + windowLines);
        context = lines.slice(start, end)
          .map((l, i) => `${start + i + 1}: ${l}`)
          .join('\n');
      }

      if (context.length > this.maxFileChars) {
        context = context.slice(0, this.maxFileChars) + '\n... (truncated)';
      }

      return context;
    } catch {
      return '';
    }
  }

  _findingId(finding) {
    const file = finding.file ? path.basename(finding.file) : 'unknown';
    return `${file}:${finding.line}:${finding.rule}`;
  }

  _trackCost(promptChars, responseChars) {
    const inputTokens  = Math.ceil(promptChars / 4);
    const outputTokens = Math.ceil(responseChars / 4);
    this.spentCents += (inputTokens  / 1000) * COST_PER_1K_INPUT
                     + (outputTokens / 1000) * COST_PER_1K_OUTPUT;
  }

  _parseTextResponse(text) {
    const cleaned = text
      .replace(/^```(?:json)?\s*/i, '')
      .replace(/\s*```\s*$/i, '')
      .trim();

    try {
      const parsed = JSON.parse(cleaned);
      if (!Array.isArray(parsed)) return [];
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

  _estimateCost(count) {
    const inputCost  = (count * EST_INPUT_TOKENS_PER_FINDING  / 1000) * COST_PER_1K_INPUT;
    const outputCost = (count * EST_OUTPUT_TOKENS_PER_FINDING / 1000) * COST_PER_1K_OUTPUT;
    return inputCost + outputCost;
  }

  getStats() {
    return {
      analyzedCount: this.analyzedCount,
      skippedCount:  this._skippedCount,
      tier2Count:    this._tier2Count,
      tier3Count:    this._tier3Count,
      spentCents:    Math.round(this.spentCents * 100) / 100,
      budgetCents:   this.budgetCents,
      provider:      this.provider?.name || 'none',
      multiTier:     this._supportsTools,
      isAnthropic:   this._isAnthropic,
    };
  }
}

export default DeepAnalyzer;
