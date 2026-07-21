import assert from 'node:assert/strict';
import test from 'node:test';
import { AGENT_SECRET_MASK } from './agent-secrets.ts';
import { maskLLMSettings, readLLMSettings, secureLLMSettings } from './llm-credentials.ts';

process.env.AGENT_SECRETS_KEY = 'test-only-llm-settings-key';

test('encrypts LLM API keys without changing preferences', () => {
  const stored = secureLLMSettings({
    provider: 'kimi',
    model: 'kimi-k3',
    think: true,
    swarm: false,
    apiKeys: { KIMI_API_KEY: 'sk-private' },
  });

  assert.equal(JSON.stringify(stored).includes('sk-private'), false);
  assert.deepEqual(readLLMSettings(stored), {
    provider: 'kimi',
    model: 'kimi-k3',
    think: true,
    swarm: false,
    apiKeys: { KIMI_API_KEY: 'sk-private' },
  });
});

test('returns masked credentials to the browser', () => {
  const stored = secureLLMSettings({ provider: 'openai', apiKeys: { OPENAI_API_KEY: 'sk-private' } });
  assert.deepEqual(maskLLMSettings(stored)?.apiKeys, { OPENAI_API_KEY: AGENT_SECRET_MASK });
});

test('preserves masked keys and removes cleared keys', () => {
  const stored = secureLLMSettings({
    provider: 'auto',
    apiKeys: { OPENAI_API_KEY: 'keep-me', KIMI_API_KEY: 'remove-me' },
  });
  const updated = secureLLMSettings({
    provider: 'openai',
    apiKeys: { OPENAI_API_KEY: AGENT_SECRET_MASK, KIMI_API_KEY: '' },
  }, stored);

  assert.deepEqual(readLLMSettings(updated).apiKeys, { OPENAI_API_KEY: 'keep-me' });
});

test('reads legacy plaintext settings', () => {
  assert.deepEqual(readLLMSettings({
    provider: 'anthropic',
    model: 'claude',
    apiKeys: { ANTHROPIC_API_KEY: 'legacy-key' },
  }).apiKeys, { ANTHROPIC_API_KEY: 'legacy-key' });
});
