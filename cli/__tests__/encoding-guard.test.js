/**
 * Ship Safe — encoding guard
 * ===========================
 *
 * Regression guard against UTF-8 mojibake (double/triple-encoded punctuation)
 * in tracked text files. This class of corruption was introduced once by an
 * in-place `perl -i -pe` edit that inserted a wide character (an em-dash)
 * without a UTF-8 I/O layer, which re-encoded every pre-existing multibyte
 * character in the file. It renders as garbled, double-encoded text.
 *
 * If this test fails: do NOT edit text content with `perl -i`/`sed` using
 * non-ASCII characters. Use the editor's UTF-8-safe write path (or Node with
 * explicit 'utf8'), and repair the file with the double-decode fix.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import fs from 'node:fs';

// Byte signatures of double-encoded UTF-8 punctuation/emoji. These do not occur
// in correctly-encoded UTF-8 text.
const SIGNATURES = [
  Buffer.from([0xc3, 0x83, 0xc2]), // Ã‚… (em/en-dash, quotes double-encoded)
  Buffer.from([0xc3, 0x82, 0xc2]), // Â…
  Buffer.from([0xc3, 0xa2, 0xc2]), // â… (e2-lead char double-encoded)
];

const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|icns|woff2?|ttf|eot|otf|mp3|mp4|mov|webm|pdf|zip|gz|tar|wasm|node)$/i;

function trackedTextFiles() {
  return execSync('git ls-files', { maxBuffer: 1 << 26 })
    .toString().trim().split('\n')
    .filter((f) => f && !BINARY_EXT.test(f));
}

describe('encoding guard', () => {
  it('has no mojibake (double-encoded UTF-8) in tracked text files', () => {
    const offenders = [];
    for (const file of trackedTextFiles()) {
      let buf;
      try { buf = fs.readFileSync(file); } catch { continue; }
      if (buf.length > 5_000_000) continue;
      let count = 0;
      for (const sig of SIGNATURES) {
        let i = 0;
        while ((i = buf.indexOf(sig, i)) !== -1) { count++; i += sig.length; }
      }
      if (count > 0) offenders.push(`${file} (${count})`);
    }
    assert.deepEqual(
      offenders, [],
      `Mojibake found in:\n  ${offenders.join('\n  ')}\nRepair with a double-decode fix; do not edit non-ASCII text via perl -i/sed.`,
    );
  });
});
