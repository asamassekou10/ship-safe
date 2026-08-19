/**
 * Helpers for detecting invisible Unicode Tag payloads.
 *
 * Unicode Tags are invisible in most editors but U+E0020 through U+E007E
 * encode printable ASCII by subtracting U+E0000. The only common benign use
 * is the three RGI subdivision flags, which are explicitly allowlisted.
 */

export const TAG_BLOCK_START = 0xE0000;
export const TAG_BLOCK_END = 0xE007F;
export const TAG_PAYLOAD_START = 0xE0020;
export const TAG_PAYLOAD_END = 0xE007E;

const FLAG_BASE = String.fromCodePoint(0x1F3F4);
const CANCEL_TAG = String.fromCodePoint(0xE007F);
const RGI_SUBDIVISIONS = ['gbeng', 'gbsct', 'gbwls'];

const ALLOWED_FLAG_TAG_SEQUENCES = new Set(
  RGI_SUBDIVISIONS.map(code => (
    FLAG_BASE
    + [...code].map(char => String.fromCodePoint(TAG_BLOCK_START + char.codePointAt(0))).join('')
    + CANCEL_TAG
  )),
);

const TAG_CHAR_RE = /[\u{E0000}-\u{E007F}]/u;

export function stripAllowedEmojiFlagTags(line) {
  let result = line;
  for (const sequence of ALLOWED_FLAG_TAG_SEQUENCES) {
    result = result.split(sequence).join('');
  }
  return result;
}

export function containsUnicodeTag(line) {
  return TAG_CHAR_RE.test(line);
}

export function firstNonAllowedUnicodeTagIndex(line) {
  let index = 0;

  while (index < line.length) {
    const allowedSequence = [...ALLOWED_FLAG_TAG_SEQUENCES]
      .find(sequence => line.startsWith(sequence, index));
    if (allowedSequence) {
      index += allowedSequence.length;
      continue;
    }

    const codePoint = line.codePointAt(index);
    if (codePoint >= TAG_BLOCK_START && codePoint <= TAG_BLOCK_END) return index;
    index += codePoint > 0xFFFF ? 2 : 1;
  }

  return -1;
}

export function decodeUnicodeTagPayload(line, maxLength = 120) {
  let decoded = '';
  for (const char of line) {
    const codePoint = char.codePointAt(0);
    if (codePoint < TAG_PAYLOAD_START || codePoint > TAG_PAYLOAD_END) continue;
    decoded += String.fromCodePoint(codePoint - TAG_BLOCK_START);
    if (decoded.length >= maxLength) return `${decoded.slice(0, maxLength - 3)}...`;
  }
  return decoded;
}

export function describeUnicodeTagPayload(line) {
  const sanitized = stripAllowedEmojiFlagTags(line);
  if (!containsUnicodeTag(sanitized)) return null;

  const decoded = decodeUnicodeTagPayload(sanitized);
  return decoded ? `hidden text: ${JSON.stringify(decoded)}` : 'Unicode Tag characters (U+E0000-U+E007F)';
}
