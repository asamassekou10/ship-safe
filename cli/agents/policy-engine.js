/**
 * Policy-as-Code Engine
 * ======================
 *
 * Enforces security policies defined in .ship-safe.policy.json.
 * Teams can define minimum scores, required scans, severity thresholds,
 * and custom rule overrides.
 *
 * USAGE:
 *   const policy = PolicyEngine.load(rootPath);
 *   const violations = policy.evaluate(scoreResult, findings);
 */

import fs from 'fs';
import path from 'path';

const DEFAULT_POLICY = {
  minimumScore: 0,
  failOn: null,           // 'critical' | 'high' | 'medium' — fail if any finding at this level
  requiredScans: [],      // ['secrets', 'deps', 'injection', 'auth']
  ignoreRules: [],        // ['GENERIC_API_KEY', 'API_NO_VALIDATION']
  customSeverityOverrides: {}, // { 'CORS_WILDCARD': 'critical' }
  maxAge: {
    criticalCVE: null,    // '7d' — max time before critical CVEs must be fixed
    highCVE: null,
    mediumCVE: null,
  },
};

export class PolicyEngine {
  constructor(policy = {}) {
    this.policy = { ...DEFAULT_POLICY, ...policy };
  }

  /**
   * Load policy from .ship-safe.policy.json in the project root.
   */
  static load(rootPath) {
    const policyPath = path.join(rootPath, '.ship-safe.policy.json');

    if (!fs.existsSync(policyPath)) {
      return new PolicyEngine();
    }

    try {
      const content = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
      return new PolicyEngine(content);
    } catch (err) {
      console.warn(`Warning: Could not parse .ship-safe.policy.json: ${err.message}`);
      return new PolicyEngine();
    }
  }

  /**
   * Evaluate findings against the policy.
   * Returns array of violations (empty = pass).
   */
  evaluate(scoreResult, findings = []) {
    const violations = [];

    // ── Minimum score check ───────────────────────────────────────────────────
    if (this.policy.minimumScore > 0 && scoreResult.score < this.policy.minimumScore) {
      violations.push({
        type: 'minimum_score',
        message: `Score ${scoreResult.score} is below minimum ${this.policy.minimumScore}`,
        severity: 'critical',
      });
    }

    // ── Fail-on severity check ────────────────────────────────────────────────
    if (this.policy.failOn) {
      const sevOrder = ['critical', 'high', 'medium', 'low'];
      const threshold = sevOrder.indexOf(this.policy.failOn);

      for (const finding of findings) {
        const findingSev = sevOrder.indexOf(finding.severity);
        if (findingSev >= 0 && findingSev <= threshold) {
          violations.push({
            type: 'severity_threshold',
            message: `${finding.severity} finding: ${finding.title} in ${finding.file}:${finding.line}`,
            severity: finding.severity,
            finding,
          });
        }
      }
    }

    return violations;
  }

  /**
   * Check if a finding's rule should be ignored by policy.
   */
  isIgnored(finding) {
    return this.policy.ignoreRules.includes(finding.rule);
  }

  /**
   * Apply severity overrides from policy.
   */
  applySeverityOverrides(findings) {
    return findings.map(f => {
      if (this.policy.customSeverityOverrides[f.rule]) {
        return { ...f, severity: this.policy.customSeverityOverrides[f.rule] };
      }
      return f;
    });
  }

  /**
   * Filter findings by policy ignores and apply overrides.
   */
  applyPolicy(findings) {
    let filtered = findings.filter(f => !this.isIgnored(f));
    filtered = this.applySeverityOverrides(filtered);
    return filtered;
  }

  /**
   * Check if policy passes (no violations).
   */
  passes(scoreResult, findings) {
    return this.evaluate(scoreResult, findings).length === 0;
  }

  /**
   * Generate a default policy template.
   */
  static generateTemplate(rootPath) {
    const template = {
      minimumScore: 70,
      failOn: 'critical',
      requiredScans: ['secrets', 'injection', 'deps', 'auth'],
      ignoreRules: [],
      customSeverityOverrides: {},
      maxAge: {
        criticalCVE: '7d',
        highCVE: '30d',
        mediumCVE: '90d',
      },
    };

    const policyPath = path.join(rootPath, '.ship-safe.policy.json');
    fs.writeFileSync(policyPath, JSON.stringify(template, null, 2));
    return policyPath;
  }
}

export default PolicyEngine;
