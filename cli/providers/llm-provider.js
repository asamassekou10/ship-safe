/**
 * Multi-LLM Provider
 * ===================
 *
 * Abstraction layer for LLM providers.
 * Supports: Anthropic (Claude), OpenAI, Google (Gemini), Ollama (local),
 *           and any OpenAI-compatible endpoint (Groq, Together AI, Mistral API,
 *           LM Studio, Azure OpenAI, AWS Bedrock via proxy, etc.).
 *
 * USAGE:
 *   const provider = createProvider('anthropic', apiKey);
 *   const provider = createProvider('groq', apiKey);
 *   const provider = createProvider('openai', apiKey, { baseUrl: 'https://custom/v1/chat/completions' });
 *   const result = await provider.classify(findings, context);
 */

import fs from 'fs';
import path from 'path';

// =============================================================================
// PROVIDER INTERFACE
// =============================================================================

class BaseLLMProvider {
  constructor(name, apiKey, options = {}) {
    this.name = name;
    this.apiKey = apiKey;
    this.model = options.model || null;
    this.baseUrl = options.baseUrl || null;
  }

  /**
   * Send a prompt to the LLM and get a text response.
   */
  async complete(systemPrompt, userPrompt, options = {}) {
    throw new Error(`${this.name}.complete() not implemented`);
  }

  /**
   * Classify security findings using the LLM.
   */
  async classify(findings, context) {
    const prompt = this.buildClassificationPrompt(findings, context);
    const response = await this.complete(
      'You are a security expert. Respond with JSON only, no markdown.',
      prompt,
      { maxTokens: 4096 }
    );
    return this.parseJSON(response);
  }

  buildClassificationPrompt(findings, context) {
    const items = findings.map(f => ({
      id: `${f.file}:${f.line}`,
      rule: f.rule,
      severity: f.severity,
      title: f.title,
      matched: f.matched?.slice(0, 100),
      description: f.description,
    }));

    return `Classify each finding as REAL or FALSE_POSITIVE. For REAL findings, provide a specific fix.

Respond with JSON array ONLY:
[{"id":"<id>","classification":"REAL"|"FALSE_POSITIVE","reason":"<brief reason>","fix":"<specific fix or null>"}]

Findings:
${JSON.stringify(items, null, 2)}`;
  }

  parseJSON(text) {
    const cleaned = text
      .replace(/^```(?:json)?\s*/i, '')
      .replace(/\s*```\s*$/i, '')
      .trim();
    try {
      return JSON.parse(cleaned);
    } catch {
      return [];
    }
  }
}

// =============================================================================
// ANTHROPIC PROVIDER (Claude)
// =============================================================================

class AnthropicProvider extends BaseLLMProvider {
  constructor(apiKey, options = {}) {
    super('Anthropic', apiKey, options);
    this.model = options.model || 'claude-haiku-4-5-20251001';
    this.baseUrl = options.baseUrl || 'https://api.anthropic.com/v1/messages';
  }

  /** Whether this provider supports guaranteed-JSON tool-use output */
  get supportsStructuredOutput() { return true; }

  async complete(systemPrompt, userPrompt, options = {}) {
    const response = await fetch(this.baseUrl, {
      method: 'POST',
      headers: {
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: options.model || this.model,
        max_tokens: options.maxTokens || 2048,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Anthropic API error: HTTP ${response.status} ${body.slice(0, 200)}`);
    }

    const data = await response.json();
    return data.content?.[0]?.text || '';
  }

  /**
   * Complete with guaranteed-JSON output via Anthropic tool-use API.
   * The LLM is forced to call the named tool, so the response always matches
   * the provided JSON Schema — no regex cleanup needed.
   *
   * @param {string} systemPrompt
   * @param {string} userPrompt
   * @param {string} toolName       — Name of the forced tool call
   * @param {object} inputSchema    — JSON Schema for the tool's input
   * @param {object} options        — { maxTokens, model }
   * @returns {Promise<object|null>} — Parsed tool input object, or null on failure
   */
  async completeWithTools(systemPrompt, userPrompt, toolName, inputSchema, options = {}) {
    const response = await fetch(this.baseUrl, {
      method: 'POST',
      headers: {
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: options.model || this.model,
        max_tokens: options.maxTokens || 2048,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
        tools: [{
          name: toolName,
          description: `Report ${toolName} results`,
          input_schema: inputSchema,
        }],
        tool_choice: { type: 'tool', name: toolName },
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Anthropic API error: HTTP ${response.status} ${body.slice(0, 200)}`);
    }

    const data = await response.json();
    const toolUse = data.content?.find(b => b.type === 'tool_use');
    return toolUse?.input ?? null;
  }
}

// =============================================================================
// OPENAI PROVIDER (GPT-4o, etc.)
// =============================================================================

class OpenAIProvider extends BaseLLMProvider {
  constructor(apiKey, options = {}) {
    super('OpenAI', apiKey, options);
    this.model = options.model || 'gpt-4o-mini';
    this.baseUrl = options.baseUrl || 'https://api.openai.com/v1/chat/completions';
  }

  async complete(systemPrompt, userPrompt, options = {}) {
    const response = await fetch(this.baseUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: options.maxTokens || 2048,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: HTTP ${response.status}`);
    }

    const data = await response.json();
    return data.choices?.[0]?.message?.content || '';
  }
}

// =============================================================================
// GOOGLE PROVIDER (Gemini)
// =============================================================================

class GoogleProvider extends BaseLLMProvider {
  constructor(apiKey, options = {}) {
    super('Google', apiKey, options);
    this.model = options.model || 'gemini-2.0-flash';
  }

  async complete(systemPrompt, userPrompt, options = {}) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': this.apiKey,
      },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: userPrompt }] }],
        generationConfig: { maxOutputTokens: options.maxTokens || 2048 },
      }),
    });

    if (!response.ok) {
      throw new Error(`Google API error: HTTP ${response.status}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  }
}

// =============================================================================
// OLLAMA PROVIDER (Local models)
// =============================================================================

class OllamaProvider extends BaseLLMProvider {
  constructor(apiKey, options = {}) {
    super('Ollama', null, options);
    this.model = options.model || 'gemma4:e4b';
    this.baseUrl = options.baseUrl || 'http://localhost:11434/api/chat';
  }

  async complete(systemPrompt, userPrompt, options = {}) {
    const response = await fetch(this.baseUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        stream: false,
      }),
    });

    if (!response.ok) {
      throw new Error(`Ollama error: HTTP ${response.status}`);
    }

    const data = await response.json();
    return data.message?.content || '';
  }
}

// =============================================================================
// GEMMA 4 PROVIDER
// Uses Ollama's structured output (format: schema) for guaranteed JSON —
// no regex parsing, no silent dropped findings.
// =============================================================================

const CLASSIFY_SCHEMA = {
  type: 'object',
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id:             { type: 'string' },
          classification: { type: 'string', enum: ['REAL', 'FALSE_POSITIVE'] },
          reason:         { type: 'string' },
          fix:            { type: ['string', 'null'] },
        },
        required: ['id', 'classification', 'reason', 'fix'],
      },
    },
  },
  required: ['results'],
};

class GemmaProvider extends OllamaProvider {
  constructor(options = {}) {
    super(null, {
      model:   options.model   || 'gemma4:e4b',
      baseUrl: options.baseUrl || 'http://localhost:11434/api/chat',
    });
    this.name = 'Gemma4';
    // 256K tokens for 27b/31b, 128K for e4b — set conservatively high
    this.contextWindow = options.model?.includes('27b') ? 131072 : 65536;
  }

  /**
   * Classify using Ollama structured output (format: schema).
   * Gemma 4 has trained-in function calling — the schema is enforced at the
   * token level, so the response is always valid JSON matching CLASSIFY_SCHEMA.
   */
  async classify(findings, context) {
    const prompt = this.buildClassificationPrompt(findings, context);

    const response = await fetch(this.baseUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model:  this.model,
        format: CLASSIFY_SCHEMA,
        stream: false,
        options: { num_ctx: this.contextWindow },
        messages: [
          { role: 'system', content: 'You are a security expert. Classify each finding as REAL or FALSE_POSITIVE and suggest a fix.' },
          { role: 'user',   content: prompt },
        ],
      }),
    });

    if (!response.ok) {
      throw new Error(`Gemma4/Ollama error: HTTP ${response.status}`);
    }

    const data = await response.json();
    const text = data.message?.content || '';

    try {
      const parsed = JSON.parse(text);
      return parsed.results ?? [];
    } catch {
      // Fallback: schema enforcement failed (old Ollama version) — try regex parse
      return this.parseJSON(text);
    }
  }
}

// =============================================================================
// OPENAI-COMPATIBLE PROVIDER
// Handles Groq, Together AI, Mistral API, LM Studio, Azure OpenAI, Bedrock
// proxy, and any other endpoint that speaks /v1/chat/completions.
// =============================================================================

// Well-known OpenAI-compatible base URLs and their default models.
const OPENAI_COMPATIBLE_PRESETS = {
  groq:       { baseUrl: 'https://api.groq.com/openai/v1/chat/completions',         model: 'llama-3.3-70b-versatile',    envKey: 'GROQ_API_KEY' },
  together:   { baseUrl: 'https://api.together.xyz/v1/chat/completions',             model: 'meta-llama/Llama-3-70b-chat-hf', envKey: 'TOGETHER_API_KEY' },
  mistral:    { baseUrl: 'https://api.mistral.ai/v1/chat/completions',               model: 'mistral-large-latest',       envKey: 'MISTRAL_API_KEY' },
  cohere:     { baseUrl: 'https://api.cohere.com/compatibility/v1/chat/completions', model: 'command-r-plus',             envKey: 'COHERE_API_KEY' },
  deepseek:   { baseUrl: 'https://api.deepseek.com/v1/chat/completions',             model: 'deepseek-chat',              envKey: 'DEEPSEEK_API_KEY' },
  perplexity: { baseUrl: 'https://api.perplexity.ai/chat/completions',               model: 'llama-3.1-sonar-large-128k-online', envKey: 'PERPLEXITY_API_KEY' },
  lmstudio:   { baseUrl: 'http://localhost:1234/v1/chat/completions',                model: null,                         envKey: null },
  xai:        { baseUrl: 'https://api.x.ai/v1/chat/completions',                    model: 'grok-3-mini',                envKey: 'XAI_API_KEY' },
  // Gemma 4 via Ollama — runs fully local, no API key required
  // e4b: MoE 4B active params, ~8GB RAM;  27b: dense, ~20GB RAM
  gemma4:     { baseUrl: 'http://localhost:11434/v1/chat/completions',               model: 'gemma4:e4b',                 envKey: null },
  'gemma4:27b': { baseUrl: 'http://localhost:11434/v1/chat/completions',             model: 'gemma4:27b',                 envKey: null },
};

class OpenAICompatibleProvider extends OpenAIProvider {
  constructor(name, apiKey, options = {}) {
    super(apiKey, options);
    this.name = name;
  }
}

// =============================================================================
// FACTORY
// =============================================================================

/**
 * Create an LLM provider instance.
 *
 * @param {string} provider — 'anthropic' | 'openai' | 'google' | 'ollama'
 *                            or any preset: 'groq' | 'together' | 'mistral' |
 *                            'cohere' | 'deepseek' | 'perplexity' | 'lmstudio' | 'xai'
 * @param {string} apiKey   — API key (null for Ollama/LM Studio)
 * @param {object} options  — { model, baseUrl }
 *                            baseUrl overrides the default for any provider.
 */
export function createProvider(provider, apiKey, options = {}) {
  const name = provider.toLowerCase();

  // First-class providers
  switch (name) {
    case 'anthropic':
    case 'claude':
      return new AnthropicProvider(apiKey, options);
    case 'openai':
    case 'gpt':
      return new OpenAIProvider(apiKey, options);
    case 'google':
    case 'gemini':
      return new GoogleProvider(apiKey, options);
    case 'ollama':
    case 'local':
      return new OllamaProvider(apiKey, options);
    case 'gemma4':
    case 'gemma':
      // Gemma 4 via Ollama — structured output, no API key needed
      return new GemmaProvider({
        model:   options.model,
        baseUrl: options.baseUrl,
      });
  }

  // OpenAI-compatible presets
  if (OPENAI_COMPATIBLE_PRESETS[name]) {
    const preset = OPENAI_COMPATIBLE_PRESETS[name];
    return new OpenAICompatibleProvider(
      // Capitalise for display: "groq" → "Groq"
      name.charAt(0).toUpperCase() + name.slice(1),
      apiKey,
      {
        baseUrl: options.baseUrl || preset.baseUrl,
        model:   options.model   || preset.model || 'default',
      }
    );
  }

  // Unknown name but caller supplied a baseUrl — treat as generic OpenAI-compatible
  if (options.baseUrl) {
    return new OpenAICompatibleProvider(provider, apiKey, options);
  }

  throw new Error(
    `Unknown LLM provider: "${provider}".\n` +
    `Built-in: anthropic, openai, google, ollama\n` +
    `Presets:  groq, together, mistral, cohere, deepseek, perplexity, lmstudio, xai\n` +
    `Custom:   pass any name with --base-url <url>`
  );
}

/**
 * Auto-detect the best available LLM provider from environment variables.
 *
 * @param {string} rootPath  — Project root (for .env file scan)
 * @param {object} options   — { provider, baseUrl, model } explicit overrides
 */
export function autoDetectProvider(rootPath, options = {}) {
  // Explicit provider name requested
  if (options.provider) {
    const apiKey = resolveApiKey(options.provider, rootPath);
    return createProvider(options.provider, apiKey, {
      model:   options.model,
      baseUrl: options.baseUrl,
    });
  }

  // baseUrl supplied without a provider name → openai-compatible with auto key
  if (options.baseUrl) {
    const apiKey = process.env.OPENAI_API_KEY || resolveApiKey('openai', rootPath) || '';
    return new OpenAICompatibleProvider('custom', apiKey, {
      baseUrl: options.baseUrl,
      model:   options.model || 'default',
    });
  }

  // Standard env-var auto-detection (first match wins)
  const envKeys = {
    ANTHROPIC_API_KEY: 'anthropic',
    OPENAI_API_KEY:    'openai',
    GOOGLE_API_KEY:    'google',
    GEMINI_API_KEY:    'google',
    GROQ_API_KEY:      'groq',
    TOGETHER_API_KEY:  'together',
    MISTRAL_API_KEY:   'mistral',
    DEEPSEEK_API_KEY:  'deepseek',
    XAI_API_KEY:       'xai',
  };

  for (const [envVar, providerName] of Object.entries(envKeys)) {
    if (process.env[envVar]) {
      return createProvider(providerName, process.env[envVar], { model: options.model });
    }
  }

  // Check .env file
  if (rootPath) {
    const envPath = path.join(rootPath, '.env');
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf-8');
        for (const [envVar, providerName] of Object.entries(envKeys)) {
          const match = content.match(new RegExp(`^${envVar}\\s*=\\s*["']?([^"'\\s]+)`, 'm'));
          if (match) return createProvider(providerName, match[1], { model: options.model });
        }
      } catch { /* ignore */ }
    }
  }

  return null;
}

/**
 * Resolve an API key for a given provider name from env or .env file.
 */
function resolveApiKey(providerName, rootPath) {
  const name = providerName.toLowerCase();
  const preset = OPENAI_COMPATIBLE_PRESETS[name];
  const envVar = preset?.envKey || `${name.toUpperCase()}_API_KEY`;

  if (process.env[envVar]) return process.env[envVar];

  if (rootPath) {
    const envPath = path.join(rootPath, '.env');
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf-8');
        const match = content.match(new RegExp(`^${envVar}\\s*=\\s*["']?([^"'\\s]+)`, 'm'));
        if (match) return match[1];
      } catch { /* ignore */ }
    }
  }

  return null;
}

export { OPENAI_COMPATIBLE_PRESETS };
export default { createProvider, autoDetectProvider };
