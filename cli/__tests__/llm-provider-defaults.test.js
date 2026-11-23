import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProvider } from '../providers/llm-provider.js';

// Google shut gemini-2.0-flash down on the Gemini API on 2026-06-01, so a
// Gemini provider created without a model must not fall back to it.
test('Gemini provider defaults to a served model', () => {
  for (const name of ['gemini', 'google']) {
    const provider = createProvider(name, 'test-key');
    assert.notEqual(provider.model, 'gemini-2.0-flash', name);
  }
});

test('Gemini provider keeps an explicit model', () => {
  assert.equal(createProvider('gemini', 'test-key', { model: 'gemini-3.6-flash' }).model, 'gemini-3.6-flash');
});
