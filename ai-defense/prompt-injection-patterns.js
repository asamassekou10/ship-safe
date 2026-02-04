/**
 * Prompt Injection Detection Patterns
 * ====================================
 *
 * Use these patterns to detect common prompt injection attempts.
 *
 * WHY THIS MATTERS:
 * - Prompt injection is the #1 LLM vulnerability (OWASP LLM01)
 * - Attackers can override your system instructions
 * - Can lead to data leakage, unauthorized actions, or abuse
 *
 * HOW TO USE:
 *   import { containsInjectionAttempt, sanitizeUserInput } from './prompt-injection-patterns';
 *
 *   if (containsInjectionAttempt(userInput)) {
 *     return "I can't process that request.";
 *   }
 *
 * LIMITATIONS:
 * - Pattern matching can't catch all attacks
 * - Sophisticated attacks may bypass these filters
 * - Use as ONE layer of defense, not the only one
 */

// =============================================================================
// INJECTION PATTERNS
// =============================================================================

/**
 * Common prompt injection patterns
 * Each pattern has a regex and severity level
 */
export const INJECTION_PATTERNS = [
  // Direct instruction override
  {
    name: 'Ignore instructions',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?)/i,
    severity: 'high',
  },
  {
    name: 'Disregard instructions',
    pattern: /disregard\s+(all\s+)?(previous|prior|above|system)/i,
    severity: 'high',
  },
  {
    name: 'Forget instructions',
    pattern: /forget\s+(all\s+)?(previous|prior|above|system|everything)/i,
    severity: 'high',
  },
  {
    name: 'Override instructions',
    pattern: /override\s+(all\s+)?(previous|prior|system)/i,
    severity: 'high',
  },

  // System prompt extraction
  {
    name: 'System prompt request',
    pattern: /what\s+(is|are)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/i,
    severity: 'medium',
  },
  {
    name: 'Repeat instructions',
    pattern: /repeat\s+(your|the|all|everything)\s+(system\s+)?(instructions?|prompts?|above)/i,
    severity: 'high',
  },
  {
    name: 'Show prompt',
    pattern: /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)/i,
    severity: 'medium',
  },
  {
    name: 'Print instructions',
    pattern: /print\s+(your|the|all)\s+(system\s+)?(instructions?|prompts?|rules?)/i,
    severity: 'high',
  },

  // Jailbreak attempts
  {
    name: 'DAN mode',
    pattern: /\b(DAN|do\s+anything\s+now)\b/i,
    severity: 'high',
  },
  {
    name: 'Developer mode',
    pattern: /\b(developer|dev)\s+mode/i,
    severity: 'high',
  },
  {
    name: 'Jailbreak',
    pattern: /\bjailbreak\b/i,
    severity: 'high',
  },
  {
    name: 'Unrestricted mode',
    pattern: /(without|no)\s+(restrictions?|limits?|boundaries|filters?)/i,
    severity: 'high',
  },

  // Role manipulation
  {
    name: 'Act as unrestricted',
    pattern: /act\s+(as\s+)?(if\s+)?(you\s+)?(have\s+no|without)\s+(restrictions?|limits?|rules?)/i,
    severity: 'high',
  },
  {
    name: 'Pretend no policies',
    pattern: /pretend\s+(you\s+)?(don'?t\s+have|have\s+no)\s+(content\s+)?(policies|restrictions)/i,
    severity: 'high',
  },
  {
    name: 'New persona',
    pattern: /you\s+are\s+now\s+a\s+different\s+(ai|assistant|character)/i,
    severity: 'medium',
  },

  // Delimiter attacks
  {
    name: 'Fake system tag',
    pattern: /\[?\s*(system|admin|root|sudo)\s*[\]:]?\s*(new\s+)?instruction/i,
    severity: 'high',
  },
  {
    name: 'End instruction block',
    pattern: /<\/?system>|<\/?instruction>|\[end\]|\[\/instruction\]/i,
    severity: 'high',
  },
  {
    name: 'Markdown code block escape',
    pattern: /```\s*(system|instruction|prompt)/i,
    severity: 'medium',
  },

  // Encoding attacks
  {
    name: 'Base64 instruction',
    pattern: /base64|decode\s+this/i,
    severity: 'low',
  },
  {
    name: 'Unicode obfuscation',
    pattern: /[\u200B-\u200D\uFEFF]/,  // Zero-width characters
    severity: 'medium',
  },

  // Information extraction
  {
    name: 'API key request',
    pattern: /(what\s+is|tell\s+me|show|reveal)\s+(your|the)\s+(api|secret)\s*key/i,
    severity: 'high',
  },
  {
    name: 'Credentials request',
    pattern: /(what\s+are|tell\s+me|show|reveal)\s+(your|the)\s+(credentials?|passwords?|secrets?)/i,
    severity: 'high',
  },
  {
    name: 'Internal info request',
    pattern: /tell\s+me\s+about\s+(your|the)\s+(internal|backend|server|database)/i,
    severity: 'medium',
  },

  // Output manipulation
  {
    name: 'Output format override',
    pattern: /respond\s+(only\s+)?(in|with)\s+(json|xml|code)\s+format/i,
    severity: 'low',
  },
  {
    name: 'Ignore safety',
    pattern: /ignore\s+(safety|content|output)\s+(filters?|checks?|validation)/i,
    severity: 'high',
  },
];

// =============================================================================
// DETECTION FUNCTIONS
// =============================================================================

/**
 * Check if input contains potential injection attempts
 * @param input - User input to check
 * @param minSeverity - Minimum severity to flag ('low', 'medium', 'high')
 * @returns Object with detected flag and matched patterns
 */
export function containsInjectionAttempt(input, minSeverity = 'medium') {
  const severityLevels = { low: 0, medium: 1, high: 2 };
  const minLevel = severityLevels[minSeverity] || 1;

  const matches = [];

  for (const { name, pattern, severity } of INJECTION_PATTERNS) {
    if (severityLevels[severity] >= minLevel && pattern.test(input)) {
      matches.push({ name, severity });
    }
  }

  return {
    detected: matches.length > 0,
    matches,
  };
}

/**
 * Sanitize user input by removing or replacing suspicious content
 * Note: This is a basic sanitizer. Sophisticated attacks may bypass it.
 * @param input - User input to sanitize
 * @returns Sanitized input
 */
export function sanitizeUserInput(input) {
  let sanitized = input;

  // Remove zero-width characters (unicode obfuscation)
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF]/g, '');

  // Remove potential delimiter attacks
  sanitized = sanitized.replace(/<\/?system>/gi, '');
  sanitized = sanitized.replace(/<\/?instruction>/gi, '');
  sanitized = sanitized.replace(/\[system\]/gi, '');
  sanitized = sanitized.replace(/\[instruction\]/gi, '');

  // Normalize whitespace
  sanitized = sanitized.replace(/\s+/g, ' ').trim();

  return sanitized;
}

/**
 * Log potential injection attempt for monitoring
 * @param userId - User who attempted injection
 * @param input - The suspicious input
 * @param matches - Matched patterns
 */
export function logInjectionAttempt(userId, input, matches) {
  console.warn('[SECURITY] Potential prompt injection detected', {
    userId,
    inputPreview: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
    patterns: matches.map(m => m.name),
    timestamp: new Date().toISOString(),
  });

  // In production, send to your logging/alerting system
  // await sendToSecurityLog({ userId, input, matches });
}

// =============================================================================
// USAGE EXAMPLE
// =============================================================================

/**
 * Example middleware for AI endpoints
 *
 * async function aiEndpoint(request) {
 *   const { message } = await request.json();
 *
 *   // Check for injection
 *   const { detected, matches } = containsInjectionAttempt(message);
 *
 *   if (detected) {
 *     logInjectionAttempt(userId, message, matches);
 *
 *     // Option 1: Reject the request
 *     return new Response('Invalid request', { status: 400 });
 *
 *     // Option 2: Sanitize and continue (less secure)
 *     // message = sanitizeUserInput(message);
 *   }
 *
 *   // Proceed with AI call
 *   const response = await callAI(message);
 *   return Response.json({ response });
 * }
 */

// Export for CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    INJECTION_PATTERNS,
    containsInjectionAttempt,
    sanitizeUserInput,
    logInjectionAttempt,
  };
}
