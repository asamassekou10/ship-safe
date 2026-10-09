import { firstNonAllowedUnicodeTagIndex } from './unicode-tags.js';

// Shared instruction detectors for agent configs and decoded A2A descriptions.
export const AGENT_INSTRUCTION_PATTERNS = {
  PROMPT_OVERRIDE: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:all\s+)?(?:above|prior|previous)|you\s+are\s+now\s+(?:a|an)\s|new\s+(?:instructions|role|persona)\s*:|override\s+(?:system|previous|all)\s+(?:instructions|prompt|rules)|forget\s+(?:everything|all\s+(?:previous|prior)))/gi,
  ROLE_HIJACK: /(?:act\s+as\s+(?:a\s+)?(?:hacker|attacker|malicious|evil|unfiltered)|pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|new|unrestricted)|your\s+(?:new|real|true|actual)\s+(?:role|purpose|goal|identity)\s+is)/gi,
  HIDDEN_INSTRUCTION: /<!--[\s\S]{0,500}?(?:ignore|override|execute|fetch|curl|wget|send\s+to|exfiltrate|upload)[\s\S]{0,500}?-->/gi,
  // eslint-disable-next-line no-misleading-character-class
  ZERO_WIDTH: /[\u200B\u200C\u200D\uFEFF\u2060]{4,}/g,
};

export function hasHiddenAgentInstruction(text) {
  return firstNonAllowedUnicodeTagIndex(text) !== -1
    || Object.values(AGENT_INSTRUCTION_PATTERNS).some(pattern => new RegExp(pattern.source, pattern.flags).test(text));
}
