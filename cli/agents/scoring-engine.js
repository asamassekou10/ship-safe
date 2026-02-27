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

// =============================================================================
// SCORING CONFIGURATION
// =============================================================================

const CATEGORIES = {
  secrets:       { weight: 15, label: 'Secrets',                deductions: { critical: 25, high: 15, medium: 5 } },
  injection:     { weight: 15, label: 'Code Vulnerabilities',   deductions: { critical: 20, high: 10, medium: 3 } },
  deps:          { weight: 15, label: 'Dependencies',           deductions: { critical: 20, high: 10, medium: 5, moderate: 5 } },
  auth:          { weight: 15, label: 'Auth & Access Control',  deductions: { critical: 20, high: 10, medium: 3 } },
  config:        { weight: 10, label: 'Configuration',          deductions: { critical: 15, high: 8,  medium: 3 } },
  'supply-chain':{ weight: 10, label: 'Supply Chain',           deductions: { critical: 15, high: 8,  medium: 3 } },
  api:           { weight: 10, label: 'API Security',           deductions: { critical: 15, high: 8,  medium: 3 } },
  llm:           { weight: 10, label: 'AI/LLM Security',       deductions: { critical: 15, high: 8,  medium: 3 } },
};

// Fallback categories for findings that don't match a known category
const FALLBACK_CATEGORY_MAP = {
  'secret': 'secrets',
  'vulnerability': 'injection',
  'ssrf': 'injection',
  'history': 'secrets',
  'cicd': 'config',
  'mobile': 'injection',
  'recon': null, // skip recon findings
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

    // ── Compute deductions per category ───────────────────────────────────────
    for (const [key, config] of Object.entries(CATEGORIES)) {
      const result = categoryResults[key];
      let deduction = 0;

      for (const [sev, pts] of Object.entries(config.deductions)) {
        deduction += (result.counts[sev] || 0) * pts;
      }

      result.deduction = Math.min(deduction, result.maxDeduction);
    }

    // ── Compute total score ───────────────────────────────────────────────────
    const totalDeduction = Object.values(categoryResults).reduce(
      (sum, r) => sum + r.deduction, 0
    );
    const score = Math.max(0, 100 - totalDeduction);
    const grade = GRADES.find(g => score >= g.min);

    return {
      score,
      grade,
      categories: categoryResults,
      totalFindings: findings.length,
      totalDepVulns: depVulns.length,
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
  saveToHistory(rootPath, scoreResult) {
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

      history.push({
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
      });

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
