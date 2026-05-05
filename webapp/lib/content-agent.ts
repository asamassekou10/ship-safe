import type { BlogPost } from '@/data/blog';
import { draftWithHermesProvider } from '@/lib/content-intelligence-providers';

export interface ContentAgentSource {
  id: string;
  type: 'rss' | 'reddit' | 'hackernews' | 'web';
  url: string;
  weight?: number;
}

export interface ContentAgentConfig {
  brandName: string;
  productUrl: string;
  audience: string;
  primaryKeywords: string[];
  competitorKeywords: string[];
  painPointKeywords: string[];
  sources: ContentAgentSource[];
  maxItemsPerSource?: number;
  minScore?: number;
  mode?: 'draft' | 'publish';
  hermesAgentId?: string;
}

export interface DiscoveredItem {
  id: string;
  sourceId: string;
  sourceType: ContentAgentSource['type'];
  title: string;
  url: string;
  excerpt: string;
  publishedAt?: string;
  engagement?: number;
}

export interface ScoredItem extends DiscoveredItem {
  score: number;
  reasons: string[];
}

export interface ContentAgentResult {
  status: 'drafted' | 'skipped' | 'published';
  topic?: ScoredItem;
  post?: BlogPost;
  sourceCount: number;
  candidateCount: number;
  selectedCount: number;
  guardrails: string[];
  cms?: {
    attempted: boolean;
    ok?: boolean;
    status?: number;
    error?: string;
  };
}

const DEFAULT_MAX_ITEMS = 8;
const DEFAULT_MIN_SCORE = 24;

export const defaultContentAgentConfig: ContentAgentConfig = {
  brandName: 'Ship Safe',
  productUrl: 'https://www.shipsafecli.com',
  audience: 'developers and founders shipping AI-assisted SaaS products',
  primaryKeywords: [
    'AI agent security',
    'MCP security',
    'LLM security',
    'AI coding',
    'supply chain security',
    'GitHub Actions security',
    'secrets scanning',
    'Vercel security',
    'developer security',
  ],
  competitorKeywords: ['Snyk', 'Semgrep', 'GitGuardian', 'Socket', 'Wiz', 'Aikido'],
  painPointKeywords: [
    'leaked secret',
    'prompt injection',
    'vulnerability',
    'breach',
    'malicious package',
    'compromised token',
    'CI/CD',
    'OAuth scopes',
  ],
  sources: [
    {
      id: 'hn-security',
      type: 'hackernews',
      url: 'https://hn.algolia.com/api/v1/search_by_date?query=AI%20security%20OR%20supply%20chain%20security&tags=story',
      weight: 1.05,
    },
    {
      id: 'google-security-rss',
      type: 'rss',
      url: 'https://blog.google/technology/safety-security/rss/',
      weight: 1,
    },
    {
      id: 'github-blog-security-rss',
      type: 'rss',
      url: 'https://github.blog/security/feed/',
      weight: 1.15,
    },
    {
      id: 'reddit-netsec',
      type: 'reddit',
      url: 'https://www.reddit.com/r/netsec/hot.json?limit=15',
      weight: 0.9,
    },
  ],
  maxItemsPerSource: DEFAULT_MAX_ITEMS,
  minScore: DEFAULT_MIN_SCORE,
};

export async function runContentAgent(config: Partial<ContentAgentConfig> = {}): Promise<ContentAgentResult> {
  const resolved = mergeConfig(config);
  const discovered = await discoverItems(resolved);
  const ranked = scoreItems(discovered, resolved).sort((a, b) => b.score - a.score);
  const scored = ranked.filter((item) => item.score >= (resolved.minScore ?? DEFAULT_MIN_SCORE));

  const selected = pickTopic(scored) ?? ranked[0];

  if (!selected) {
    return {
      status: 'skipped',
      sourceCount: resolved.sources.length,
      candidateCount: discovered.length,
      selectedCount: 0,
      guardrails: ['No candidate cleared the relevance and recency threshold.'],
    };
  }

  const supportingSources = scored
    .filter((item) => item.url !== selected.url)
    .slice(0, 4);
  const selectedCount = Math.max(scored.length, 1);

  const post = await draftBlogPost(selected, supportingSources, resolved);
  const guardrails = validateDraft(post, [selected, ...supportingSources]);

  if (guardrails.some((guardrail) => guardrail.startsWith('BLOCK:'))) {
    return {
      status: 'skipped',
      topic: selected,
      post,
      sourceCount: resolved.sources.length,
      candidateCount: discovered.length,
      selectedCount,
      guardrails,
    };
  }

  const cms = resolved.mode === 'publish' ? await publishToCms(post, [selected, ...supportingSources]) : undefined;

  return {
    status: cms?.ok ? 'published' : 'drafted',
    topic: selected,
    post,
    sourceCount: resolved.sources.length,
    candidateCount: discovered.length,
    selectedCount,
    guardrails,
    cms,
  };
}

function mergeConfig(config: Partial<ContentAgentConfig>): ContentAgentConfig {
  return {
    ...defaultContentAgentConfig,
    ...config,
    primaryKeywords: config.primaryKeywords ?? defaultContentAgentConfig.primaryKeywords,
    competitorKeywords: config.competitorKeywords ?? defaultContentAgentConfig.competitorKeywords,
    painPointKeywords: config.painPointKeywords ?? defaultContentAgentConfig.painPointKeywords,
    sources: config.sources?.length ? config.sources : defaultContentAgentConfig.sources,
  };
}

async function discoverItems(config: ContentAgentConfig): Promise<DiscoveredItem[]> {
  const settled = await Promise.allSettled(
    config.sources.map(async (source) => {
      const res = await fetch(source.url, {
        headers: source.type === 'reddit' ? { 'User-Agent': 'ship-safe-content-agent/0.1' } : undefined,
        next: { revalidate: 1800 },
      });

      if (!res.ok) throw new Error(`${source.id} returned ${res.status}`);

      const text = await res.text();
      const limit = config.maxItemsPerSource ?? DEFAULT_MAX_ITEMS;

      if (source.type === 'rss') return parseRss(text, source).slice(0, limit);
      if (source.type === 'reddit') return parseReddit(text, source).slice(0, limit);
      if (source.type === 'hackernews') return parseHackerNews(text, source).slice(0, limit);
      return parseWebPage(text, source).slice(0, limit);
    }),
  );

  return settled.flatMap((result) => (result.status === 'fulfilled' ? result.value : []));
}

function parseRss(xml: string, source: ContentAgentSource): DiscoveredItem[] {
  const itemBlocks = [...xml.matchAll(/<item\b[\s\S]*?<\/item>/gi)].map((match) => match[0]);
  const entryBlocks = [...xml.matchAll(/<entry\b[\s\S]*?<\/entry>/gi)].map((match) => match[0]);

  return [...itemBlocks, ...entryBlocks].map((block, index) => {
    const title = cleanXml(readTag(block, 'title')) || `Untitled item ${index + 1}`;
    const link = cleanXml(readTag(block, 'link')) || readAtomLink(block) || source.url;
    const excerpt = cleanXml(readTag(block, 'description') || readTag(block, 'summary') || readTag(block, 'content:encoded'));
    const publishedAt = cleanXml(readTag(block, 'pubDate') || readTag(block, 'published') || readTag(block, 'updated'));
    return toItem(source, `${source.id}:${index}`, title, link, excerpt, publishedAt);
  });
}

function parseReddit(jsonText: string, source: ContentAgentSource): DiscoveredItem[] {
  const parsed = safeJson<{
    data?: { children?: Array<{ data?: { id?: string; title?: string; permalink?: string; url?: string; selftext?: string; created_utc?: number; score?: number } }> };
  }>(jsonText);

  return parsed?.data?.children?.map((child, index) => {
    const data = child.data ?? {};
    const permalink = data.permalink ? `https://www.reddit.com${data.permalink}` : data.url ?? source.url;
    return toItem(
      source,
      data.id ?? `${source.id}:${index}`,
      data.title ?? `Reddit discussion ${index + 1}`,
      permalink,
      data.selftext ?? '',
      data.created_utc ? new Date(data.created_utc * 1000).toISOString() : undefined,
      data.score,
    );
  }) ?? [];
}

function parseHackerNews(jsonText: string, source: ContentAgentSource): DiscoveredItem[] {
  const parsed = safeJson<{
    hits?: Array<{ objectID?: string; title?: string; story_title?: string; url?: string; story_url?: string; created_at?: string; points?: number; num_comments?: number }>;
  }>(jsonText);

  return parsed?.hits?.map((hit, index) => {
    const id = hit.objectID ?? `${source.id}:${index}`;
    return toItem(
      source,
      id,
      hit.title ?? hit.story_title ?? `Hacker News item ${index + 1}`,
      hit.url ?? hit.story_url ?? `https://news.ycombinator.com/item?id=${id}`,
      '',
      hit.created_at,
      (hit.points ?? 0) + (hit.num_comments ?? 0),
    );
  }) ?? [];
}

function parseWebPage(html: string, source: ContentAgentSource): DiscoveredItem[] {
  const title = cleanXml(readTag(html, 'title')) || source.id;
  const description = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["'][^>]*>/i)?.[1] ?? '';
  return [toItem(source, source.id, title, source.url, description)];
}

function toItem(
  source: ContentAgentSource,
  id: string,
  title: string,
  url: string,
  excerpt: string,
  publishedAt?: string,
  engagement?: number,
): DiscoveredItem {
  return {
    id,
    sourceId: source.id,
    sourceType: source.type,
    title: title.trim(),
    url: normalizeUrl(url, source.url),
    excerpt: excerpt.trim().slice(0, 700),
    publishedAt: parseDate(publishedAt),
    engagement,
  };
}

function scoreItems(items: DiscoveredItem[], config: ContentAgentConfig): ScoredItem[] {
  const seen = new Set<string>();

  return items
    .filter((item) => {
      const key = `${item.title.toLowerCase()}|${item.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return item.title.length > 8 && isAllowedUrl(item.url);
    })
    .map((item) => {
      const haystack = `${item.title} ${item.excerpt}`.toLowerCase();
      const reasons: string[] = [];
      let score = 0;

      for (const keyword of config.primaryKeywords) {
        const match = keywordMatch(keyword, haystack);
        if (match > 0) {
          score += match === 2 ? 12 : 7;
          reasons.push(match === 2 ? `Matches primary topic: ${keyword}` : `Partially matches primary topic: ${keyword}`);
        }
      }

      for (const keyword of config.painPointKeywords) {
        const match = keywordMatch(keyword, haystack);
        if (match > 0) {
          score += match === 2 ? 9 : 5;
          reasons.push(match === 2 ? `Matches customer pain point: ${keyword}` : `Partially matches customer pain point: ${keyword}`);
        }
      }

      for (const keyword of config.competitorKeywords) {
        if (haystack.includes(keyword.toLowerCase())) {
          score += 5;
          reasons.push(`Mentions adjacent vendor/category: ${keyword}`);
        }
      }

      const ageDays = item.publishedAt ? (Date.now() - new Date(item.publishedAt).getTime()) / 86_400_000 : 7;
      if (ageDays <= 2) {
        score += 14;
        reasons.push('Published in the last 48 hours');
      } else if (ageDays <= 14) {
        score += 8;
        reasons.push('Published in the last two weeks');
      }

      if ((item.engagement ?? 0) > 50) {
        score += 6;
        reasons.push('Has visible discussion or engagement');
      }

      const source = config.sources.find((candidate) => candidate.id === item.sourceId);
      score *= source?.weight ?? 1;

      return { ...item, score: Math.round(score), reasons: reasons.slice(0, 5) };
    });
}

function keywordMatch(keyword: string, haystack: string): 0 | 1 | 2 {
  const normalized = keyword.toLowerCase();
  if (haystack.includes(normalized)) return 2;

  const words = normalized
    .split(/[^a-z0-9]+/)
    .filter((word) => word.length > 2);

  if (words.length < 2) return 0;
  const hits = words.filter((word) => haystack.includes(word)).length;
  return hits >= Math.ceil(words.length / 2) ? 1 : 0;
}

function pickTopic(items: ScoredItem[]): ScoredItem | undefined {
  return items.find((item) => item.reasons.length >= 2) ?? items[0];
}

async function draftBlogPost(topic: ScoredItem, supportingSources: ScoredItem[], config: ContentAgentConfig): Promise<BlogPost> {
  const hermesDraft = (process.env.CONTENT_AGENT_PROVIDER === 'hermes' || config.hermesAgentId)
    ? await draftWithHermesProvider({ topic, supportingSources, config })
    : undefined;
  if (hermesDraft) return hermesDraft;

  const aiDraft = process.env.OPENAI_API_KEY ? await draftWithOpenAI(topic, supportingSources, config) : undefined;
  if (aiDraft) return aiDraft;

  const today = new Date().toISOString().slice(0, 10);
  const title = makeTitle(topic, config);
  const slug = slugify(title);
  const sourceLines = [topic, ...supportingSources].map((source) => `- [${source.title}](${source.url})`).join('\n');
  const keywords = Array.from(new Set([...config.primaryKeywords.slice(0, 5), ...config.painPointKeywords.slice(0, 4)]));

  return {
    slug,
    title,
    description: `A practical Ship Safe analysis of ${topic.title}, why it matters for ${config.audience}, and what teams should check next.`,
    date: today,
    author: `${config.brandName} Content Agent`,
    tags: ['AI security', 'security research', 'developer security'],
    keywords,
    content: `
${topic.title} is worth paying attention to because it sits close to a risk surface many software teams already have: fast-moving AI tooling, third-party integrations, CI automation, and production credentials.

This article is an agent-generated draft. It should be reviewed before publication if the topic involves an active incident, a named vendor, legal claims, or customer impact.

## Why This Matters

For ${config.audience}, the practical question is not only what happened. The better question is what this changes about the way teams should build, deploy, and monitor software.

The signal from the source material is:

- ${topic.reasons.join('\n- ')}

## What Teams Should Check

- Review integrations that can read secrets, deployment metadata, source code, or customer data
- Check whether automation tokens are scoped to the smallest permission set that still works
- Confirm webhook receivers verify signatures before triggering downstream agent workflows
- Audit CI jobs that run AI tools with write permissions
- Rotate credentials when an upstream tool or identity provider may have been involved

## How Ship Safe Helps

${config.brandName} scans codebases and AI-agent configurations for the classes of mistakes that make incidents spread: leaked secrets, unsafe webhook handlers, overbroad permissions, risky MCP/Hermes tool configs, unpinned actions, and agent workflows that cross trust boundaries.

The goal is simple: keep the speed of AI-assisted development without letting invisible integration risk accumulate in the background.

## Sources

${sourceLines}
    `.trim(),
  };
}

async function draftWithOpenAI(topic: ScoredItem, supportingSources: ScoredItem[], config: ContentAgentConfig): Promise<BlogPost | undefined> {
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: process.env.CONTENT_AGENT_MODEL ?? 'gpt-4.1-mini',
      input: [
        {
          role: 'system',
          content: 'You are a careful B2B SaaS security editor. Return only valid JSON. Do not invent citations, quotes, dates, or claims.',
        },
        {
          role: 'user',
          content: JSON.stringify({
            task: 'Draft a concise, source-cited blog post in the provided schema.',
            brand: config.brandName,
            audience: config.audience,
            productUrl: config.productUrl,
            selectedTopic: topic,
            supportingSources,
            requiredSchema: {
              slug: 'kebab-case string',
              title: 'string',
              description: 'string under 180 chars',
              date: new Date().toISOString().slice(0, 10),
              author: `${config.brandName} Content Agent`,
              tags: ['3-5 strings'],
              keywords: ['6-12 SEO strings'],
              content: 'markdown body with a Sources section linking every factual source used',
            },
          }),
        },
      ],
      text: {
        format: {
          type: 'json_object',
        },
      },
    }),
  });

  if (!response.ok) return undefined;
  const parsed = await response.json() as { output_text?: string; output?: Array<{ content?: Array<{ text?: string }> }> };
  const raw = parsed.output_text ?? parsed.output?.flatMap((item) => item.content ?? []).map((content) => content.text ?? '').join('') ?? '';
  const post = safeJson<BlogPost>(raw);
  if (!post) return undefined;
  return {
    ...post,
    slug: slugify(post.slug || post.title),
    date: post.date || new Date().toISOString().slice(0, 10),
    author: post.author || `${config.brandName} Content Agent`,
  };
}

function validateDraft(post: BlogPost, sources: ScoredItem[]): string[] {
  const guardrails: string[] = [];

  if (!post.title || post.title.length < 12) guardrails.push('BLOCK: Draft title is too short.');
  if (!post.description || post.description.length < 50) guardrails.push('BLOCK: Draft description is too thin.');
  if (!post.content.includes('## Sources')) guardrails.push('BLOCK: Draft must include a Sources section.');
  if (!sources.some((source) => post.content.includes(source.url))) guardrails.push('BLOCK: Draft does not cite the selected source URL.');
  if (/\bguarantee[sd]?\b|\bproves?\b|\bconfirmed breach\b/i.test(post.content)) {
    guardrails.push('Review: Draft contains strong certainty language; verify before publishing.');
  }
  if (post.content.length < 1500) guardrails.push('Review: Draft is short; consider expanding before publishing.');

  guardrails.push('No unsupported publication happened inside the agent. Use mode=publish only with a configured CMS webhook.');
  return guardrails;
}

async function publishToCms(post: BlogPost, sources: ScoredItem[]): Promise<ContentAgentResult['cms']> {
  const url = process.env.CONTENT_AGENT_CMS_WEBHOOK_URL;
  if (!url) return { attempted: false, error: 'CONTENT_AGENT_CMS_WEBHOOK_URL is not configured.' };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.CONTENT_AGENT_CMS_TOKEN ? { Authorization: `Bearer ${process.env.CONTENT_AGENT_CMS_TOKEN}` } : {}),
      },
      body: JSON.stringify({ post, sources }),
    });

    return { attempted: true, ok: res.ok, status: res.status };
  } catch (error) {
    return { attempted: true, ok: false, error: error instanceof Error ? error.message : 'Unknown CMS publish error' };
  }
}

function readTag(text: string, tag: string): string {
  return text.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'))?.[1] ?? '';
}

function readAtomLink(text: string): string {
  return text.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*>/i)?.[1] ?? '';
}

function cleanXml(value: string): string {
  return value
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeUrl(url: string, baseUrl: string): string {
  try {
    return new URL(url, baseUrl).toString();
  } catch {
    return baseUrl;
  }
}

function isAllowedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.hostname === 'news.ycombinator.com';
  } catch {
    return false;
  }
}

function parseDate(value?: string): string | undefined {
  if (!value) return undefined;
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return undefined;
  return new Date(timestamp).toISOString();
}

function makeTitle(topic: ScoredItem, config: ContentAgentConfig): string {
  const trimmed = topic.title.replace(/\s+/g, ' ').replace(/[|].*$/, '').trim();
  if (/security|breach|vulnerability|supply chain|AI/i.test(trimmed)) {
    return `What ${trimmed} Means for AI-SaaS Security`;
  }
  return `${trimmed}: A ${config.brandName} Security Brief`;
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/['"]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 90);
}

function safeJson<T>(text: string): T | undefined {
  try {
    return JSON.parse(text) as T;
  } catch {
    return undefined;
  }
}
