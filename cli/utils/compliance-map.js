/**
 * Compliance Mapping Utility
 * ===========================
 *
 * Maps CWE/OWASP findings to compliance frameworks:
 *   - SOC 2 Type II (Trust Service Criteria)
 *   - ISO 27001:2022 (Annex A controls)
 *   - NIST AI Risk Management Framework (AI RMF 1.0)
 */

// =============================================================================
// CWE → COMPLIANCE CONTROL MAPPING
// =============================================================================

const CWE_MAP = {
  'CWE-74':  { soc2: ['CC6.1', 'CC7.1'], iso27001: ['A.8.28'], nistAiRmf: ['MAP 1.5', 'MEASURE 2.6'] },
  'CWE-78':  { soc2: ['CC6.1', 'CC7.1'], iso27001: ['A.8.28'], nistAiRmf: ['MAP 1.5'] },
  'CWE-79':  { soc2: ['CC6.1'], iso27001: ['A.8.28'], nistAiRmf: [] },
  'CWE-89':  { soc2: ['CC6.1'], iso27001: ['A.8.28'], nistAiRmf: [] },
  'CWE-94':  { soc2: ['CC6.1', 'CC7.1'], iso27001: ['A.8.28', 'A.8.9'], nistAiRmf: ['MAP 1.5'] },
  'CWE-116': { soc2: ['CC6.1'], iso27001: ['A.8.28'], nistAiRmf: ['MEASURE 2.6'] },
  'CWE-200': { soc2: ['CC6.5', 'CC6.1'], iso27001: ['A.8.11', 'A.5.33'], nistAiRmf: ['GOVERN 1.7', 'MAP 5.1'] },
  'CWE-250': { soc2: ['CC6.3'], iso27001: ['A.8.2'], nistAiRmf: ['GOVERN 1.4'] },
  'CWE-269': { soc2: ['CC6.3', 'CC6.1'], iso27001: ['A.8.2', 'A.5.15'], nistAiRmf: ['GOVERN 1.4'] },
  'CWE-287': { soc2: ['CC6.1', 'CC6.2'], iso27001: ['A.8.5'], nistAiRmf: [] },
  'CWE-306': { soc2: ['CC6.1', 'CC6.2'], iso27001: ['A.8.5'], nistAiRmf: ['GOVERN 1.4'] },
  'CWE-311': { soc2: ['CC6.7'], iso27001: ['A.8.24'], nistAiRmf: [] },
  'CWE-312': { soc2: ['CC6.7', 'CC6.1'], iso27001: ['A.8.24', 'A.5.33'], nistAiRmf: ['MAP 5.1'] },
  'CWE-326': { soc2: ['CC6.7'], iso27001: ['A.8.24'], nistAiRmf: [] },
  'CWE-327': { soc2: ['CC6.7'], iso27001: ['A.8.24'], nistAiRmf: [] },
  'CWE-502': { soc2: ['CC6.1'], iso27001: ['A.8.28'], nistAiRmf: [] },
  'CWE-522': { soc2: ['CC6.1', 'CC6.7'], iso27001: ['A.8.5', 'A.8.24'], nistAiRmf: [] },
  'CWE-611': { soc2: ['CC6.1'], iso27001: ['A.8.28'], nistAiRmf: [] },
  'CWE-668': { soc2: ['CC6.1', 'CC6.6'], iso27001: ['A.8.9', 'A.8.20'], nistAiRmf: ['GOVERN 1.4'] },
  'CWE-798': { soc2: ['CC6.1', 'CC6.7'], iso27001: ['A.5.33', 'A.8.24'], nistAiRmf: [] },
  'CWE-918': { soc2: ['CC6.1', 'CC6.6'], iso27001: ['A.8.20', 'A.8.28'], nistAiRmf: [] },
};

// OWASP Agentic → NIST AI RMF mapping (agent-specific)
const AGENTIC_MAP = {
  'ASI01': { soc2: ['CC6.1', 'CC7.2'], iso27001: ['A.8.28', 'A.8.9'], nistAiRmf: ['MAP 1.5', 'MEASURE 2.6', 'MANAGE 2.2'] },
  'ASI02': { soc2: ['CC6.1', 'CC6.3'], iso27001: ['A.8.2', 'A.8.9'], nistAiRmf: ['MAP 1.5', 'GOVERN 1.4', 'MANAGE 2.2'] },
  'ASI03': { soc2: ['CC6.3'], iso27001: ['A.8.2', 'A.5.15'], nistAiRmf: ['GOVERN 1.4', 'MAP 3.4'] },
  'ASI04': { soc2: ['CC6.6', 'CC7.1'], iso27001: ['A.5.19', 'A.5.21'], nistAiRmf: ['MAP 1.5', 'GOVERN 6.1'] },
  'ASI05': { soc2: ['CC6.1', 'CC7.1'], iso27001: ['A.8.28', 'A.8.9'], nistAiRmf: ['MAP 1.5'] },
  'ASI06': { soc2: ['CC6.1'], iso27001: ['A.8.11'], nistAiRmf: ['MEASURE 2.6', 'MANAGE 2.2'] },
  'ASI07': { soc2: ['CC6.1', 'CC6.7'], iso27001: ['A.8.20', 'A.8.24'], nistAiRmf: ['MAP 1.5'] },
  'ASI08': { soc2: ['CC7.4', 'CC7.5'], iso27001: ['A.5.30'], nistAiRmf: ['MANAGE 4.1'] },
  'ASI09': { soc2: ['CC6.2'], iso27001: ['A.8.5', 'A.5.15'], nistAiRmf: ['GOVERN 1.7'] },
  'ASI10': { soc2: ['CC7.2', 'CC7.4'], iso27001: ['A.8.9', 'A.5.30'], nistAiRmf: ['MANAGE 2.2', 'MANAGE 4.1'] },
};

// =============================================================================
// PUBLIC API
// =============================================================================

/**
 * Map a single finding to compliance controls.
 * @param {object} finding - A finding with `cwe` and `owasp` fields.
 * @returns {{ soc2: string[], iso27001: string[], nistAiRmf: string[] }}
 */
export function mapFindingToCompliance(finding) {
  const result = { soc2: new Set(), iso27001: new Set(), nistAiRmf: new Set() };

  // Map from CWE
  const cwe = finding.cwe || finding.CWE;
  if (cwe && CWE_MAP[cwe]) {
    const m = CWE_MAP[cwe];
    m.soc2.forEach(c => result.soc2.add(c));
    m.iso27001.forEach(c => result.iso27001.add(c));
    m.nistAiRmf.forEach(c => result.nistAiRmf.add(c));
  }

  // Map from OWASP Agentic
  const owasp = finding.owasp || finding.OWASP;
  if (owasp && AGENTIC_MAP[owasp]) {
    const m = AGENTIC_MAP[owasp];
    m.soc2.forEach(c => result.soc2.add(c));
    m.iso27001.forEach(c => result.iso27001.add(c));
    m.nistAiRmf.forEach(c => result.nistAiRmf.add(c));
  }

  return {
    soc2: [...result.soc2].sort(),
    iso27001: [...result.iso27001].sort(),
    nistAiRmf: [...result.nistAiRmf].sort(),
  };
}

/**
 * Aggregate compliance mappings across all findings.
 * @param {object[]} findings - Array of findings.
 * @returns {{ soc2: object, iso27001: object, nistAiRmf: object, summary: object }}
 */
export function getComplianceSummary(findings) {
  const soc2 = {};
  const iso27001 = {};
  const nistAiRmf = {};

  for (const f of findings) {
    const mapped = mapFindingToCompliance(f);

    for (const ctrl of mapped.soc2) {
      soc2[ctrl] = (soc2[ctrl] || 0) + 1;
    }
    for (const ctrl of mapped.iso27001) {
      iso27001[ctrl] = (iso27001[ctrl] || 0) + 1;
    }
    for (const ctrl of mapped.nistAiRmf) {
      nistAiRmf[ctrl] = (nistAiRmf[ctrl] || 0) + 1;
    }
  }

  return {
    soc2,
    iso27001,
    nistAiRmf,
    summary: {
      soc2Controls: Object.keys(soc2).length,
      iso27001Controls: Object.keys(iso27001).length,
      nistAiRmfControls: Object.keys(nistAiRmf).length,
      totalFindings: findings.length,
    },
  };
}
