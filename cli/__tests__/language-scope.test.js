/**
 * Language-scoped rules
 * =====================
 *
 * Most rules are shaped by one language's syntax, but agents scan several.
 * 9.6.4 fixed an Express upload rule that matched the substring `path.join(`
 * inside Python's `os.path.join(self.root_path, filename)` and reported
 * critical on Flask's own config loader. The regex was patched; the reason it
 * could happen was that nothing let a rule say which language it described.
 *
 * A pattern may now declare `langs`. These tests cover the mechanism and the
 * two directions that matter: a scoped rule stays off the wrong language, and
 * files with no language of their own are never silently skipped.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { BaseAgent, languageOf } from '../agents/base-agent.js';

function tmpFile(content, ext) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-lang-'));
  const file = path.join(dir, `t${ext}`);
  fs.writeFileSync(file, content);
  return { dir, file };
}
const cleanup = (dir) => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ } };

const agent = new BaseAgent('T', 'test', 'injection');

const JS_ONLY = [{
  rule: 'TEST_JS_ONLY', title: 'js only', severity: 'high',
  langs: ['js'], regex: /needle/g,
}];
const UNSCOPED = [{
  rule: 'TEST_UNSCOPED', title: 'unscoped', severity: 'high',
  regex: /needle/g,
}];

const runOn = (patterns, ext) => {
  const { dir, file } = tmpFile('const x = "needle";\n', ext);
  try { return agent.scanFileWithPatterns(file, patterns).length; }
  finally { cleanup(dir); }
};

describe('languageOf', () => {
  it('maps the TypeScript family onto js', () => {
    for (const ext of ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']) {
      assert.equal(languageOf(`a${ext}`), 'js', ext);
    }
  });

  it('has no opinion about files that carry no language', () => {
    for (const ext of ['.json', '.yml', '.md', '.txt', '']) {
      assert.equal(languageOf(`a${ext}`), null, ext);
    }
  });
});

describe('langs scoping', () => {
  it('runs a scoped rule on its own language', () => {
    assert.equal(runOn(JS_ONLY, '.js'), 1);
  });

  it('does not run a js rule against Python or Ruby', () => {
    assert.equal(runOn(JS_ONLY, '.py'), 0);
    assert.equal(runOn(JS_ONLY, '.rb'), 0);
  });

  it('still runs a scoped rule on config files with no language', () => {
    // A JS-scoped rule must not stop matching a .json config. Skipping those
    // would be a detection loss dressed up as precision.
    assert.equal(runOn(JS_ONLY, '.json'), 1);
  });

  it('does not run ordinary code rules on Markdown without an explicit opt-in', () => {
    assert.equal(runOn(JS_ONLY, '.md'), 0);
  });

  it('leaves unscoped rules running everywhere', () => {
    for (const ext of ['.js', '.py', '.rb', '.go', '.json']) {
      assert.equal(runOn(UNSCOPED, ext), 1, ext);
    }
  });
});

describe('SSRFProber scoping', async () => {
  const { SSRFProber } = await import('../agents/ssrf-prober.js');

  const hits = async (code, ext) => {
    const { dir, file } = tmpFile(code, ext);
    try {
      const f = await new SSRFProber().analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      return f.map(x => x.rule);
    } finally { cleanup(dir); }
  };

  it('still catches the JS shapes it was written for', async () => {
    assert.ok((await hits('fetch(req.query.url)', '.js')).includes('SSRF_USER_URL_FETCH'));
    assert.ok((await hits('axios.get(req.body.url)', '.js')).includes('SSRF_USER_URL_AXIOS'));
  });

  it('still catches the Python shape', async () => {
    assert.ok((await hits('requests.get(request.args["u"])', '.py')).includes('SSRF_PYTHON_REQUESTS'));
  });

  it('does not apply the Python rule to JavaScript', async () => {
    assert.ok(!(await hits('requests.get(request.args)', '.js')).includes('SSRF_PYTHON_REQUESTS'));
  });
});

describe('APIFuzzer scoping', async () => {
  const { APIFuzzer } = await import('../agents/api-fuzzer.js');

  const hits = async (code, ext) => {
    const { dir, file } = tmpFile(code, ext);
    try {
      const f = await new APIFuzzer().analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      return f.map(x => x.rule);
    } finally { cleanup(dir); }
  };

  it('still catches Express upload and route shapes in JavaScript', async () => {
    const findings = await hits(
      'router.post("/upload", (req, res) => { const body = { ...req.body }; path.join(dir, req.file.originalname); });',
      '.js'
    );

    assert.ok(findings.includes('API_NO_AUTH_CHECK'));
    assert.ok(findings.includes('API_SPREAD_BODY'));
    assert.ok(findings.includes('API_PATH_IN_FILENAME'));
  });

  it('does not apply Express upload and route rules to Python', async () => {
    const findings = await hits(
      'router.post("/upload", (req, res) => { const body = { ...req.body }; path.join(dir, req.file.originalname); })',
      '.py'
    );

    assert.ok(!findings.includes('API_NO_AUTH_CHECK'));
    assert.ok(!findings.includes('API_SPREAD_BODY'));
    assert.ok(!findings.includes('API_PATH_IN_FILENAME'));
  });

  it('still catches the debug-endpoint shape on JS', async () => {
    assert.ok((await hits('app.get("/debug/info", handler);', '.js')).includes('API_DEBUG_ENDPOINT'));
  });

  it('does not apply the Express route rule to Ruby', async () => {
    assert.ok(!(await hits('app.get("/debug/info", handler);', '.rb')).includes('API_DEBUG_ENDPOINT'));
  });
});

describe('LLMRedTeam scoping', async () => {
  const { LLMRedTeam } = await import('../agents/llm-redteam.js');

  const hits = async (code, ext) => {
    const { dir, file } = tmpFile(code, ext);
    try {
      const f = await new LLMRedTeam().analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
      return f.map(x => x.rule);
    } finally { cleanup(dir); }
  };

  it('still catches the JS token-limit shape', async () => {
    assert.ok((await hits("openai.chat.create({ model: 'gpt-4' })", '.js')).includes('LLM_NO_TOKEN_LIMIT'));
  });

  it('does not apply the JS token-limit rule to Python', async () => {
    assert.ok(!(await hits("openai.chat.create({ model: 'gpt-4' })", '.py')).includes('LLM_NO_TOKEN_LIMIT'));
  });

  it('still catches the Python unverified-model shape', async () => {
    assert.ok((await hits('AutoModel.from_pretrained("org/model")', '.py')).includes('LLM_UNVERIFIED_MODEL'));
  });

  it('does not apply the Python model rule to JavaScript', async () => {
    assert.ok(!(await hits('AutoModel.from_pretrained("org/model")', '.js')).includes('LLM_UNVERIFIED_MODEL'));
  });

  it('keeps the cross-language output-filter rule on JavaScript', async () => {
    assert.ok((await hits('console.log(response.content);', '.js')).includes('LLM_NO_OUTPUT_FILTER'));
  });

  it('keeps the cross-language output-filter rule on Python', async () => {
    assert.ok((await hits('print(response.content)', '.py')).includes('LLM_NO_OUTPUT_FILTER'));
  });
});
