import type { ContentDraft } from '@prisma/client';
import type { BlogPost } from '@/data/blog';
import { getGitHubClient } from '@/lib/github';
import { CANONICAL_URL } from './site';

const DEFAULT_POSTS_PATH = 'webapp/data/generated-blog-posts.json';

interface GitHubFile {
  content: string;
  sha: string;
  encoding: string;
}

interface GitRef {
  object: { sha: string };
}

interface GitHubRepo {
  default_branch: string;
}

interface PullRequest {
  html_url: string;
  number: number;
}

export async function publishDraftToGitHubPr(draft: ContentDraft, userId: string) {
  const repo = process.env.CONTENT_AGENT_GITHUB_REPO || process.env.GITHUB_REPOSITORY || 'asamassekou10/ship-safe';
  const postsPath = process.env.CONTENT_AGENT_POSTS_PATH || DEFAULT_POSTS_PATH;
  const [owner, repoName] = repo.split('/');
  if (!owner || !repoName) throw new Error('CONTENT_AGENT_GITHUB_REPO must be owner/repo');

  const client = await getGitHubClient(repo, userId);

  const repoRes = await client.fetch(`/repos/${owner}/${repoName}`);
  if (!repoRes.ok) throw new Error(`GitHub repo lookup failed: ${repoRes.status}`);
  const repoInfo = await repoRes.json() as GitHubRepo;
  const baseBranch = process.env.CONTENT_AGENT_BASE_BRANCH || repoInfo.default_branch || 'main';
  const branch = `codex/content-${draft.slug.slice(0, 44)}-${Date.now().toString(36)}`;

  const refRes = await client.fetch(`/repos/${owner}/${repoName}/git/ref/heads/${encodeURIComponent(baseBranch)}`);
  if (!refRes.ok) throw new Error(`GitHub base ref lookup failed: ${refRes.status}`);
  const baseRef = await refRes.json() as GitRef;

  const createRefRes = await client.fetch(`/repos/${owner}/${repoName}/git/refs`, {
    method: 'POST',
    body: JSON.stringify({
      ref: `refs/heads/${branch}`,
      sha: baseRef.object.sha,
    }),
  });
  if (!createRefRes.ok) {
    const err = await createRefRes.json().catch(() => ({})) as { message?: string };
    throw new Error(err.message || `GitHub branch creation failed: ${createRefRes.status}`);
  }

  const filePath = encodeURIComponent(postsPath).replace(/%2F/g, '/');
  const fileRes = await client.fetch(`/repos/${owner}/${repoName}/contents/${filePath}?ref=${encodeURIComponent(baseBranch)}`);
  if (!fileRes.ok) throw new Error(`GitHub content lookup failed: ${fileRes.status}`);
  const file = await fileRes.json() as GitHubFile;
  if (file.encoding !== 'base64') throw new Error('Unsupported GitHub file encoding');

  const currentJson = Buffer.from(file.content, 'base64').toString('utf8');
  const existingPosts = JSON.parse(currentJson) as BlogPost[];
  const post = draftToBlogPost(draft);
  const nextPosts = [
    post,
    ...existingPosts.filter((existing) => existing.slug !== post.slug),
  ].sort((a, b) => b.date.localeCompare(a.date));

  const nextContent = `${JSON.stringify(nextPosts, null, 2)}\n`;
  const updateRes = await client.fetch(`/repos/${owner}/${repoName}/contents/${filePath}`, {
    method: 'PUT',
    body: JSON.stringify({
      message: `Publish content draft: ${draft.title}`,
      content: Buffer.from(nextContent, 'utf8').toString('base64'),
      sha: file.sha,
      branch,
    }),
  });
  if (!updateRes.ok) {
    const err = await updateRes.json().catch(() => ({})) as { message?: string };
    throw new Error(err.message || `GitHub content update failed: ${updateRes.status}`);
  }

  const appUrl = CANONICAL_URL;
  const prRes = await client.fetch(`/repos/${owner}/${repoName}/pulls`, {
    method: 'POST',
    body: JSON.stringify({
      title: `Publish blog draft: ${draft.title}`,
      head: branch,
      base: baseBranch,
      body: [
        'Publishes an approved Ship Safe content-agent draft.',
        '',
        `Draft slug: \`${draft.slug}\``,
        `Preview after merge: ${appUrl}/blog/${draft.slug}`,
      ].join('\n'),
    }),
  });
  if (!prRes.ok) {
    const err = await prRes.json().catch(() => ({})) as { message?: string };
    throw new Error(err.message || `GitHub PR creation failed: ${prRes.status}`);
  }

  const pr = await prRes.json() as PullRequest;
  return {
    url: pr.html_url,
    number: pr.number,
    branch,
    repo,
  };
}

function draftToBlogPost(draft: ContentDraft): BlogPost {
  return {
    slug: draft.slug,
    title: draft.title,
    description: draft.description,
    date: new Date().toISOString().slice(0, 10),
    author: draft.author,
    tags: asStringArray(draft.tags),
    keywords: asStringArray(draft.keywords),
    content: draft.content,
    ...(draft.coverImage ? { coverImage: draft.coverImage } : {}),
  };
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}
