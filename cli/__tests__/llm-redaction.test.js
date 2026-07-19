import test from 'node:test';
import assert from 'node:assert/strict';
import { redactForLLM } from '../utils/llm-redaction.js';

test('redactForLLM masks common provider credentials', () => {
  const input = [
    'OPENAI_API_KEY=sk-example12345678901234567890',
    'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
    'github_token: ghp_abcdefghijklmnopqrstuvwxyz123456',
    'const password = "correct-horse-battery-staple";',
  ].join('\n');

  const result = redactForLLM(input);

  assert.doesNotMatch(result, /sk-example/);
  assert.doesNotMatch(result, /abcdefghijklmnopqrstuvwxyz123456/);
  assert.doesNotMatch(result, /correct-horse/);
  assert.match(result, /OPENAI_API_KEY=\[REDACTED\]/);
  assert.match(result, /Authorization: Bearer \[REDACTED\]/);
});

test('redactForLLM removes private key material while preserving context', () => {
  const input = [
    'const signingKey = `',
    '-----BEGIN PRIVATE KEY-----',
    'super-secret-key-material',
    '-----END PRIVATE KEY-----',
    '`;',
    'verifySignature(payload);',
  ].join('\n');

  const result = redactForLLM(input);

  assert.doesNotMatch(result, /super-secret-key-material/);
  assert.match(result, /\[REDACTED PRIVATE KEY\]/);
  assert.match(result, /verifySignature\(payload\)/);
});

test('redactForLLM leaves ordinary source code readable', () => {
  const input = 'const result = await scan(repository);\nreturn result.findings;';
  assert.equal(redactForLLM(input), input);
});
