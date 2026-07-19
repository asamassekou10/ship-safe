import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import * as agents from '../cli/agents/index.js';
import packageJson from '../package.json' with { type: 'json' };

const here = path.dirname(fileURLToPath(import.meta.url));
const corpus = JSON.parse(fs.readFileSync(path.join(here, 'corpus.json'), 'utf8'));

async function scan(agentName, relativeFile) {
  const Agent = agents[agentName];
  if (!Agent) throw new Error(`Unknown agent export: ${agentName}`);

  const rootPath = path.join(here, 'corpus', path.dirname(relativeFile));
  const file = path.join(here, 'corpus', relativeFile);
  const instance = new Agent();
  return instance.analyze({
    rootPath,
    files: [file],
    recon: { files: [file] },
    options: { quiet: true, noAi: true },
    sharedFindings: [],
  });
}

const scenarios = [];
for (const scenario of corpus.scenarios) {
  const vulnerableFindings = await scan(scenario.agent, scenario.vulnerable);
  const safeFindings = await scan(scenario.agent, scenario.safe);
  const detected = vulnerableFindings.some((finding) => finding.rule === scenario.expectedRule);
  const cleanControlPassed = !safeFindings.some((finding) => finding.rule === scenario.expectedRule);

  scenarios.push({
    id: scenario.id,
    category: scenario.category,
    agent: scenario.agent,
    expectedRule: scenario.expectedRule,
    detected,
    cleanControlPassed,
    vulnerableFindingRules: [...new Set(vulnerableFindings.map((finding) => finding.rule))].sort(),
    safeFindingRules: [...new Set(safeFindings.map((finding) => finding.rule))].sort(),
  });
}

const detectedCount = scenarios.filter((scenario) => scenario.detected).length;
const cleanControlCount = scenarios.filter((scenario) => scenario.cleanControlPassed).length;
const result = {
  schemaVersion: 1,
  corpusVersion: corpus.version,
  shipSafeVersion: packageJson.version,
  methodology: 'First-party paired synthetic scenarios; one vulnerable and one safe control per target rule.',
  limitations: [
    'This corpus measures deterministic scenario detection, not prevalence or performance on arbitrary production repositories.',
    'Target-rule clean-control pass rate is not a real-world precision estimate.',
    'The evaluation is maintained by the Ship Safe project and is not independent validation.',
  ],
  metrics: {
    scenarios: scenarios.length,
    detected: detectedCount,
    scenarioRecall: detectedCount / scenarios.length,
    targetRuleCleanControls: scenarios.length,
    targetRuleCleanControlsPassed: cleanControlCount,
    targetRuleCleanControlPassRate: cleanControlCount / scenarios.length,
  },
  scenarios,
};

if (process.argv.includes('--write')) {
  const serialized = `${JSON.stringify(result, null, 2)}\n`;
  fs.mkdirSync(path.join(here, 'results'), { recursive: true });
  fs.writeFileSync(path.join(here, 'results', 'latest.json'), serialized);
  fs.writeFileSync(path.join(here, '..', 'webapp', 'data', 'benchmark-results.json'), serialized);
  const publicResults = path.join(here, '..', 'webapp', 'public', 'benchmarks');
  fs.mkdirSync(publicResults, { recursive: true });
  fs.writeFileSync(path.join(publicResults, 'latest.json'), serialized);
}

console.log(JSON.stringify(result, null, 2));

if (detectedCount !== scenarios.length || cleanControlCount !== scenarios.length) {
  process.exitCode = 1;
}
