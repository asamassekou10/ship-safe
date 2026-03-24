/**
 * Enhanced Scoring Engine
 * ========================
 *
 * Risk-based scoring with 8 categories, EPSS integration,
 * KEV flagging, and historical trend tracking.
 *
 * Score = 100 - sum(category deductions)
 * Each category has a weight and max deduction cap.
 */

import fs from 'fs';
import path from 'path';
import { getComplianceSummary } from '../utils/compliance-map.js';

// =============================================================================
// SCORING CONFIGURATION
// =============================================================================

// Weights aligned with OWASP Top 10 2025:
//   A01 Broken Access Control (auth: 15), A02 Security Misconfiguration (config: 8),
//   A03 Software Supply Chain Failures (supply-chain: 12, deps: 13),
//   A05 Injection (injection: 15), A07 Auth Failures (secrets: 15),
//   A10 Mishandling of Exceptional Conditions (→ injection category)
//   + API Security (10), AI/LLM Security (12) — weights sum to 100
const CATEGORIES = {
  secrets:       { weight: 15, label: 'Secrets',                deductions: { critical: 25, high: 15, medium: 5 } },
  injection:     { weight: 15, label: 'Code Vulnerabilities',   deductions: { critical: 20, high: 10, medium: 3 } },
  deps:          { weight: 13, label: 'Dependencies',           deductions: { critical: 20, high: 10, medium: 5, moderate: 5 } },
  auth:          { weight: 15, label: 'Auth & Access Control',  deductions: { critical: 20, high: 10, medium: 3 } },
  config:        { weight: 8,  label: 'Configuration',          deductions: { critical: 15, high: 8,  medium: 3 } },
  'supply-chain':{ weight: 12, label: 'Supply Chain',           deductions: { critical: 15, high: 8,  medium: 3 } },
  api:           { weight: 10, label: 'API Security',           deductions: { critical: 15, high: 8,  medium: 3 } },
  llm:           { weight: 12, label: 'AI/LLM Security',       deductions: { critical: 15, high: 8,  medium: 3 } },
};

// Fallback categories for findings that don't match a known category
const FALLBACK_CATEGORY_MAP = {
  'secret': 'secrets',
  'vulnerability': 'injection',
  'ssrf': 'injection',        // OWASP 2025: SSRF merged into A01 Broken Access Control
  'history': 'secrets',
  'cicd': 'config',
  'mobile': 'injection',
  'privacy': 'config',
  'mcp': 'llm',
  'agentic': 'llm',
  'rag': 'llm',
  'vibe': 'injection',        // Vibe coding findings → Code Vulnerabilities
  'exception': 'injection',   // OWASP A10:2025 — Mishandling of Exceptional Conditions
  'agent-config': 'llm',      // Agent config security → AI/LLM category
  'recon': null,               // skip recon findings
};

const GRADES = [
  { min: 90, letter: 'A', label: 'Ship it!',                    color: 'green' },
  { min: 75, letter: 'B', label: 'Minor issues to review',       color: 'cyan' },
  { min: 60, letter: 'C', label: 'Fix before shipping',          color: 'yellow' },
  { min: 40, letter: 'D', label: 'Significant security risks',   color: 'red' },
  { min: 0,  letter: 'F', label: 'Not safe to ship',             color: 'red' },
];

// =============================================================================
// SCORING ENGINE
// =============================================================================

export class ScoringEngine {
  /**
   * Compute the security score from agent findings + dependency vulnerabilities.
   *
   * @param {object[]} findings   — Array of finding objects from agents
   * @param {object[]} depVulns   — Array of dependency CVE objects
   * @returns {object}            — { score, grade, categories, breakdown }
   */
  compute(findings = [], depVulns = []) {
    const categoryResults = {};

    // Initialize all categories
    for (const [key, config] of Object.entries(CATEGORIES)) {
      categoryResults[key] = {
        label: config.label,
        weight: config.weight,
        counts: { critical: 0, high: 0, medium: 0, low: 0 },
        deduction: 0,
        maxDeduction: config.weight, // Cap at category weight
        findings: [],
      };
    }

    // ── Classify findings into categories ─────────────────────────────────────
    for (const finding of findings) {
      const cat = this.resolveCategory(finding.category);
      if (!cat || !categoryResults[cat]) continue;

      const sev = finding.severity || 'medium';
      categoryResults[cat].counts[sev] = (categoryResults[cat].counts[sev] || 0) + 1;
      categoryResults[cat].findings.push(finding);
    }

    // ── Add dependency vulnerabilities ────────────────────────────────────────
    for (const vuln of depVulns) {
      const sev = vuln.severity || 'medium';
      categoryResults.deps.counts[sev] = (categoryResults.deps.counts[sev] || 0) + 1;
    }

    // ── Compute deductions per category (confidence-weighted) ─────────────────
    const CONFIDENCE_MULTIPLIER = { high: 1.0, medium: 0.6, low: 0.3 };

    for (const [key, config] of Object.entries(CATEGORIES)) {
      const result = categoryResults[key];
      let deduction = 0;

      // Count-based deductions for deps (no per-finding confidence)
      for (const [sev, pts] of Object.entries(config.deductions)) {
        if (key === 'deps') {
          deduction += (result.counts[sev] || 0) * pts;
        }
      }

      // Per-finding confidence-weighted deductions for agent findings
      if (key !== 'deps') {
        for (const finding of result.findings) {
          const sev = finding.severity || 'medium';
          const pts = config.deductions[sev] || 0;
          const confidence = finding.confidence || 'high';
          const multiplier = CONFIDENCE_MULTIPLIER[confidence] || 1.0;
          deduction += pts * multiplier;
        }
      }

      result.deduction = Math.min(deduction, result.maxDeduction);
    }

    // ── Compute total score ───────────────────────────────────────────────────
    const totalDeduction = Object.values(categoryResults).reduce(
      (sum, r) => sum + r.deduction, 0
    );
    const score = Math.max(0, 100 - totalDeduction);
    const grade = GRADES.find(g => score >= g.min);

    // ── Compliance mapping ─────────────────────────────────────────────────
    let compliance;
    try {
      compliance = getComplianceSummary(findings);
    } catch {
      compliance = null;
    }

    return {
      score,
      grade,
      categories: categoryResults,
      totalFindings: findings.length,
      totalDepVulns: depVulns.length,
      compliance,
    };
  }

  /**
   * Map a finding category to a scoring category.
   */
  resolveCategory(findingCategory) {
    if (CATEGORIES[findingCategory]) return findingCategory;
    if (FALLBACK_CATEGORY_MAP[findingCategory] !== undefined) {
      return FALLBACK_CATEGORY_MAP[findingCategory];
    }
    return 'injection'; // default fallback
  }

  /**
   * Save score to history file for trend tracking.
   */
  saveToHistory(rootPath, scoreResult, suppressions = null) {
    const historyDir = path.join(rootPath, '.ship-safe');
    const historyFile = path.join(historyDir, 'history.json');

    try {
      if (!fs.existsSync(historyDir)) {
        fs.mkdirSync(historyDir, { recursive: true });
      }

      let history = [];
      if (fs.existsSync(historyFile)) {
        try {
          history = JSON.parse(fs.readFileSync(historyFile, 'utf-8'));
        } catch { history = []; }
      }

      const entry = {
        timestamp: new Date().toISOString(),
        score: scoreResult.score,
        grade: scoreResult.grade.letter,
        totalFindings: scoreResult.totalFindings,
        totalDepVulns: scoreResult.totalDepVulns,
        categoryScores: Object.fromEntries(
          Object.entries(scoreResult.categories).map(([k, v]) => [k, {
            deduction: v.deduction,
            counts: v.counts,
          }])
        ),
      };
      if (suppressions) entry.suppressions = suppressions;
      history.push(entry);

      // Keep last 100 entries
      if (history.length > 100) history = history.slice(-100);

      fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
    } catch {
      // Don't fail if history save fails
    }
  }

  /**
   * Load score history for trend display.
   */
  loadHistory(rootPath) {
    const historyFile = path.join(rootPath, '.ship-safe', 'history.json');
    try {
      if (fs.existsSync(historyFile)) {
        return JSON.parse(fs.readFileSync(historyFile, 'utf-8'));
      }
    } catch { /* ignore */ }
    return [];
  }

  /**
   * Get trend summary comparing current to last scan.
   */
  getTrend(rootPath, currentScore) {
    const history = this.loadHistory(rootPath);
    if (history.length < 2) return null;

    const previous = history[history.length - 2];
    const diff = currentScore - previous.score;

    return {
      previousScore: previous.score,
      currentScore,
      diff,
      direction: diff > 0 ? 'improved' : diff < 0 ? 'regressed' : 'unchanged',
      previousDate: previous.timestamp,
    };
  }
}

export { GRADES, CATEGORIES };
export default ScoringEngine;
