/**
 * Verdict benchmark — does the investigation layer conclude correctly?
 * =====================================================================
 *
 * `benchmarks/run.mjs` measures whether a rule fires on a vulnerable fixture
 * and stays quiet on its safe twin. That is the sensor layer, and it is at
 * 12/12. It says nothing about the passes that run afterwards, because before
 * the evidence schema there was nothing uniform to read: the verifier wrote
 * `finding.verified`, the analyzer wrote `finding.deepAnalysis`, and both
 * quietly moved `confidence`.
 *
 * Now every pass records a claim and the finding resolves to one verdict, so
 * the question becomes measurable: of the findings we know are real, how many
 * does investigation actually settle — and does it ever settle one the wrong
 * way?
 *
 * Two of the four metrics are absolute failures rather than ratchets:
 *
 *   falseRefutations — a finding labelled a true positive that investigation
 *       marked 'refuted'. This is the only error class that loses a real
 *       vulnerability silently, so its budget is zero and always will be.
 *
 *   unlabeled — a finding on a safe control that verdicts.json does not
 *       describe. New noise must be looked at and written down, not absorbed
 *       into a number that drifts upward unnoticed.
 *
 * The other two ratchet. `settledRate` is the fraction of true positives that
 * reach 'confirmed' or 'likely' — the number the data-flow and reproduction
 * passes exist to raise. `noiseStanding` is off-target findings on safe
 * controls that investigation failed to refute — the number they exist to
 * lower. Neither can be gamed alone: refuting everything trips
 * falseRefutations, and detecting nothing trips the detection corpus, which
 * still runs alongside this one.
 *
 * Deterministic by default so it can gate CI without an API key. `--llm` adds
 * the DeepAnalyzer pass for local comparison; its result is reported but never
 * gated, because a benchmark whose number depends on a model's mood is not a
 * regression test.
 *
 *   node benchmarks/verdicts.mjs             # gate (deterministic)
 *   node benchmarks/verdicts.mjs --write     # refresh results/verdicts.json
 *   node benchmarks/verdicts.mjs --llm       # include the LLM pass, ungated
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import * as agents from '../cli/agents/index.js';
import { VerifierAgent } from '../cli/agents/verifier-agent.js';
import { DataflowInvestigator } from '../cli/agents/dataflow-investigator.js';
import { DeepAnalyzer } from '../cli/agents/deep-analyzer.js';
import packageJson from '../package.json' with { type: 'json' };

const here = path.dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(fs.readFileSync(path.join(here, 'corpus.json'), 'utf8'));
const truth = JSON.parse(fs.readFileSync(path.join(here, 'verdicts.json'), 'utf8'));

const write = process.argv.includes('--write');
const useLlm = process.argv.includes('--llm');

/** Verdicts that count as investigation having settled the question. */
const SETTLED = new Set(['confirmed', 'likely']);

async function scan(agentName, relativeFile) {
  const Agent = agents[agentName];
  if (!Agent) throw new Error(`Unknown agent export: ${agentName}`);

  const rootPath = path.join(here, 'corpus', path.dirname(relativeFile));
  const file = path.join(here, 'corpus', relativeFile);

  const findings = await new Agent().analyze({
    rootPath,
    files: [file],
    recon: { files: [file] },
    options: { quiet: true, noAi: true },
    sharedFindings: [],
  });

  // Environment-scope findings describe the machine running the benchmark —
  // the operator's own MCP config, for instance. Letting them in would make
  // the corpus score differ per laptop.
  return findings.filter((finding) => finding.scope !== 'environment');
}

async function investigate(findings, rootPath, files = null) {
  // Same order as the orchestrator: heuristic first, then the trace that
  // outranks it, then optionally the model. The file list matters: without it
  // the tracer cannot find a caller, and every interprocedural case abstains.
  const investigated = new DataflowInvestigator()
    .investigate(new VerifierAgent().verify(findings), { rootPath, files });
  if (!useLlm) return investigated;

  const analyzer = DeepAnalyzer.create(rootPath, { quiet: true });
  if (!analyzer) {
    process.stderr.write('--llm requested but no provider is configured; skipping the LLM pass\n');
    return investigated;
  }
  return analyzer.analyze(investigated, { rootPath });
}

const verdictOf = (finding) => finding.evidence?.verdict || 'unknown';

/** Every file beside a fixture, so a trace can find the caller of its sink. */
function siblingFiles(dir) {
  try {
    return fs.readdirSync(dir)
      .filter((name) => /\.[cm]?[jt]sx?$/.test(name))
      .map((name) => path.join(dir, name));
  } catch { return []; }
}

const scenarios = [];
const flow = [];
const falseRefutations = [];
const unlabeled = [];
let truePositives = 0;
let settled = 0;
let noiseStanding = 0;
let noiseRefuted = 0;

for (const scenario of corpus.scenarios) {
  const label = truth.labels[scenario.id];
  if (!label) throw new Error(`verdicts.json has no label for scenario: ${scenario.id}`);

  const vulnRoot = path.join(here, 'corpus', path.dirname(scenario.vulnerable));
  const safeRoot = path.join(here, 'corpus', path.dirname(scenario.safe));

  const vulnFindings = await investigate(await scan(scenario.agent, scenario.vulnerable), vulnRoot);
  const safeFindings = await investigate(await scan(scenario.agent, scenario.safe), safeRoot);

  // ── The true positive: the target rule on the vulnerable fixture ──────────
  const target = vulnFindings.find((finding) => finding.rule === scenario.expectedRule);
  let targetVerdict = null;

  if (label.targetIsTruePositive && target) {
    truePositives += 1;
    targetVerdict = verdictOf(target);
    if (SETTLED.has(targetVerdict)) settled += 1;
    if (targetVerdict === 'refuted') {
      falseRefutations.push({
        scenario: scenario.id,
        rule: scenario.expectedRule,
        rationale: target.evidence?.claims?.at(-1)?.rationale || null,
      });
    }
  }

  // ── The noise: off-target findings on the safe control ────────────────────
  const noiseLabels = new Map((label.safeControlNoise || []).map((n) => [n.rule, n]));
  const offTarget = safeFindings.filter((finding) => finding.rule !== scenario.expectedRule);
  const noise = [];

  for (const finding of offTarget) {
    if (!noiseLabels.has(finding.rule)) {
      unlabeled.push({ scenario: scenario.id, rule: finding.rule, file: scenario.safe });
      continue;
    }
    const verdict = verdictOf(finding);
    if (verdict === 'refuted') noiseRefuted += 1;
    else noiseStanding += 1;
    noise.push({ rule: finding.rule, verdict });
  }

  scenarios.push({
    id: scenario.id,
    agent: scenario.agent,
    expectedRule: scenario.expectedRule,
    detected: Boolean(target),
    targetVerdict,
    // Which pass decided, so a change in the number can be traced to a pass
    // rather than guessed at.
    decidedBy: target?.evidence?.decidedBy || null,
    claimSources: target ? (target.evidence?.claims || []).map((c) => c.source) : [],
    safeControlNoise: noise,
  });
}

// ── Flow scenarios ─────────────────────────────────────────────────────────
// Same two metrics, different fixtures: these have a value to follow, so they
// are where a tracing pass can show what a pattern-matching pass cannot.
for (const scenario of truth.flowScenarios || []) {
  const record = { id: scenario.id, expectedRule: scenario.expectedRule, tainted: null, guarded: null };

  if (scenario.tainted) {
    const root = path.join(here, 'corpus', path.dirname(scenario.tainted));
    const findings = await investigate(await scan(scenario.agent, scenario.tainted), root, siblingFiles(root));
    const target = findings.find((f) => f.rule === scenario.expectedRule);

    if (!target) {
      unlabeled.push({ scenario: scenario.id, rule: scenario.expectedRule, file: scenario.tainted, note: 'expected rule did not fire' });
    } else {
      truePositives += 1;
      record.tainted = verdictOf(target);
      if (SETTLED.has(record.tainted)) settled += 1;
      if (record.tainted === 'refuted') {
        falseRefutations.push({
          scenario: scenario.id,
          rule: scenario.expectedRule,
          rationale: target.evidence?.claims?.at(-1)?.rationale || null,
        });
      }
    }
  }

  // The guarded twin is a known false positive: the rule fires, and the value
  // reaching the sink is not the caller's. Refuting it is the correct outcome.
  const guardedRoot = path.join(here, 'corpus', path.dirname(scenario.guarded));
  const guardedFindings = await investigate(await scan(scenario.agent, scenario.guarded), guardedRoot, siblingFiles(guardedRoot));
  const guardedTarget = guardedFindings.find((f) => f.rule === scenario.expectedRule);

  if (guardedTarget) {
    record.guarded = verdictOf(guardedTarget);
    if (record.guarded === 'refuted') noiseRefuted += 1;
    else noiseStanding += 1;
  }

  flow.push(record);
}

const settledRate = truePositives ? settled / truePositives : 0;

const result = {
  schemaVersion: 1,
  corpusVersion: corpus.version,
  truthVersion: truth.version,
  shipSafeVersion: packageJson.version,
  mode: useLlm ? 'deterministic+llm' : 'deterministic',
  methodology:
    'Verdicts resolved from the evidence claims attached by each investigation pass, over the paired synthetic corpus. Measures conclusion quality, not detection: benchmarks/run.mjs measures detection and must pass alongside this.',
  limitations: [
    'Twelve synthetic scenarios. A settled rate here is not a settled rate on production code.',
    'Safe-control noise labels are first-party judgements about first-party fixtures.',
    'The --llm mode is not deterministic and is never gated.',
  ],
  metrics: {
    truePositives,
    settled,
    settledRate,
    falseRefutations: falseRefutations.length,
    noiseStanding,
    noiseRefuted,
    unlabeled: unlabeled.length,
  },
  flow,
  falseRefutationDetail: falseRefutations,
  unlabeledDetail: unlabeled,
  scenarios,
};

if (write) {
  fs.mkdirSync(path.join(here, 'results'), { recursive: true });
  fs.writeFileSync(path.join(here, 'results', 'verdicts.json'), `${JSON.stringify(result, null, 2)}\n`);
  process.stderr.write('wrote benchmarks/results/verdicts.json\n');
}

console.log(JSON.stringify(result, null, 2));

// ── Gate ───────────────────────────────────────────────────────────────────
// --llm runs are informational: the ratchets describe the deterministic
// pipeline, and holding a model's output to them would fail on nothing worse
// than a different sampling.
if (!useLlm) {
  const { gate } = truth;
  const failures = [];

  if (falseRefutations.length > gate.maxFalseRefutations) {
    failures.push(`${falseRefutations.length} true positive(s) marked refuted — a real vulnerability would be dropped silently`);
  }
  if (unlabeled.length > 0) {
    failures.push(`${unlabeled.length} unlabeled finding(s) on safe controls — review them and record them in verdicts.json`);
  }
  if (settledRate < gate.minSettledRate) {
    failures.push(`settled rate ${settledRate.toFixed(3)} is below the recorded ${gate.minSettledRate}`);
  }
  if (noiseStanding > gate.maxNoiseStanding) {
    failures.push(`${noiseStanding} unrefuted noise finding(s) exceeds the recorded ${gate.maxNoiseStanding}`);
  }

  for (const failure of failures) process.stderr.write(`verdict gate: ${failure}\n`);
  if (failures.length > 0) process.exitCode = 1;
}
