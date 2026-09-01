import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { assertSafeRemoteUrl } from '../utils/remote-fetch.js';

describe('remote fetch guard', () => {
  test('rejects literal private destinations', async () => {
    await assert.rejects(
      () => assertSafeRemoteUrl('https://169.254.169.254/latest/meta-data'),
      /private or loopback/
    );
    await assert.rejects(
      () => assertSafeRemoteUrl('https://127.0.0.1:8080/tools'),
      /private or loopback/
    );
  });

  test('requires explicit opt-in for local development endpoints', async () => {
    await assert.rejects(
      () => assertSafeRemoteUrl('http://localhost:3000/skill'),
      /require https|private or loopback/
    );
    await assert.doesNotReject(
      () => assertSafeRemoteUrl('http://localhost:3000/skill', { allowLoopback: true })
    );
  });

  test('local opt-in does not allow non-loopback private destinations', async () => {
    await assert.rejects(
      () => assertSafeRemoteUrl('http://169.254.169.254/latest/meta-data', { allowLoopback: true }),
      /private or loopback/
    );
    await assert.rejects(
      () => assertSafeRemoteUrl('https://10.0.0.8/internal', { allowLoopback: true }),
      /private or loopback/
    );
  });

  test('rejects embedded credentials and public HTTP', async () => {
    await assert.rejects(
      () => assertSafeRemoteUrl('https://user:password@example.com/skill'),
      /embedded credentials/
    );
    await assert.rejects(
      () => assertSafeRemoteUrl('http://example.com/skill'),
      /require https/
    );
  });
});
