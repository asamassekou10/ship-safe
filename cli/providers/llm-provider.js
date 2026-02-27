/**
 * Multi-LLM Provider
 * ===================
 *
 * Abstraction layer for LLM providers.
 * Supports: Anthropic (Claude), OpenAI, Google (Gemini), Ollama (local).
 *
 * USAGE:
 *   const provider = createProvider('anthropic', apiKey);
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

  async complete(systemPrompt, userPrompt, options = {}) {
    const response = await fetch(this.baseUrl, {
      method: 'POST',
      headers: {
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: options.maxTokens || 2048,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Anthropic API error ${response.status}: ${body.slice(0, 200)}`);
    }

    const data = await response.json();
    return data.content?.[0]?.text || '';
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
      const body = await response.text();
      throw new Error(`OpenAI API error ${response.status}: ${body.slice(0, 200)}`);
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
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: userPrompt }] }],
        generationConfig: { maxOutputTokens: options.maxTokens || 2048 },
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Google API error ${response.status}: ${body.slice(0, 200)}`);
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
    this.model = options.model || 'llama3.2';
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
      const body = await response.text();
      throw new Error(`Ollama error ${response.status}: ${body.slice(0, 200)}`);
    }

    const data = await response.json();
    return data.message?.content || '';
  }
}

// =============================================================================
// FACTORY
// =============================================================================

/**
 * Create an LLM provider instance.
 *
 * @param {string} provider — 'anthropic' | 'openai' | 'google' | 'ollama'
 * @param {string} apiKey   — API key (null for Ollama)
 * @param {object} options  — { model, baseUrl }
 */
export function createProvider(provider, apiKey, options = {}) {
  switch (provider.toLowerCase()) {
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
    default:
      throw new Error(`Unknown LLM provider: ${provider}. Use: anthropic, openai, google, ollama`);
  }
}

/**
 * Auto-detect the best available LLM provider from environment variables.
 */
export function autoDetectProvider(rootPath) {
  // Check env vars
  const envKeys = {
    ANTHROPIC_API_KEY: 'anthropic',
    OPENAI_API_KEY: 'openai',
    GOOGLE_API_KEY: 'google',
    GEMINI_API_KEY: 'google',
  };

  for (const [envVar, provider] of Object.entries(envKeys)) {
    if (process.env[envVar]) {
      return createProvider(provider, process.env[envVar]);
    }
  }

  // Check .env file
  if (rootPath) {
    const envPath = path.join(rootPath, '.env');
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf-8');
        for (const [envVar, provider] of Object.entries(envKeys)) {
          const match = content.match(new RegExp(`^${envVar}\\s*=\\s*["']?([^"'\\s]+)`, 'm'));
          if (match) return createProvider(provider, match[1]);
        }
      } catch { /* ignore */ }
    }
  }

  return null;
}

export default { createProvider, autoDetectProvider };
