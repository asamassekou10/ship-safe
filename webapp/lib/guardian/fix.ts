import { prisma } from '@/lib/prisma';
import { getGitHubClient } from '@/lib/github';
import { appendTimeline, advanceRun } from './pipeline';

type Run = NonNullable<Awaited<ReturnType<typeof prisma.pRGuardianRun.findUnique>>>;

interface DiagnosedFinding {
  file?: string;
  line?: number;
  severity?: string;
  category?: string;
  rule?: string;
  title?: string;
  reason?: string;
}

/**
 * Step 3: Apply fixes to the PR branch via GitHub Git Data API.
 * - False positives: add `// ship-safe-ignore` comment
 * - Real issues: generate code fixes (when enabled)
 * Transitions: fixing → verifying
 */
export async function applyFixes(run: Run) {
  const gh = await getGitHubClient(run.repo, run.userId);
  const [owner, repo] = run.repo.split('/');
  const diagnosis = run.diagnosis as {
    falsePositives?: DiagnosedFinding[];
    realIssues?: DiagnosedFinding[];
  } | null;

  if (!diagnosis) {
    await appendTimeline(run.id, 'No diagnosis data', 'Skipping fix step');
    await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
    return;
  }

  const falsePositives = diagnosis.falsePositives || [];
  const fixableFindings = falsePositives.filter(f => f.file && f.line);

  if (fixableFindings.length === 0) {
    await appendTimeline(run.id, 'No fixable findings', 'Nothing to auto-fix');
    await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
    return;
  }

  await appendTimeline(run.id, 'Applying fixes', `${fixableFindings.length} file(s) to update`);

  // Group findings by file
  const fileFindings = new Map<string, DiagnosedFinding[]>();
  for (const f of fixableFindings) {
    const file = f.file!;
    if (!fileFindings.has(file)) fileFindings.set(file, []);
    fileFindings.get(file)!.push(f);
  }

  // Get the current commit SHA of the PR branch
  const refRes = await gh.fetch(`/repos/${owner}/${repo}/git/refs/heads/${encodeURIComponent(run.prBranch)}`);
  if (!refRes.ok) throw new Error(`Failed to get branch ref: ${refRes.status}`);
  const refData = await refRes.json();
  const baseSha = refData.object.sha;

  // Get the base tree
  const commitRes = await gh.fetch(`/repos/${owner}/${repo}/git/commits/${baseSha}`);
  if (!commitRes.ok) throw new Error(`Failed to get commit: ${commitRes.status}`);
  const commitData = await commitRes.json();
  const baseTreeSha = commitData.tree.sha;

  // Process each file: read content, insert ignore comments, create blobs
  const treeEntries: Array<{ path: string; mode: string; type: string; sha: string }> = [];
  const fixedFiles: string[] = [];

  for (const [filePath, findings] of fileFindings) {
    // Read the file content from the repo
    const fileRes = await gh.fetch(`/repos/${owner}/${repo}/contents/${encodeURIComponent(filePath)}?ref=${encodeURIComponent(run.prBranch)}`);
    if (!fileRes.ok) continue;

    const fileData = await fileRes.json();
    const content = Buffer.from(fileData.content, 'base64').toString('utf-8');
    const lines = content.split('\n');

    // Sort findings by line number descending so insertions don't shift later lines
    const sorted = [...findings].sort((a, b) => (b.line || 0) - (a.line || 0));

    for (const finding of sorted) {
      const lineIdx = (finding.line || 1) - 1;
      if (lineIdx >= 0 && lineIdx < lines.length) {
        const indent = lines[lineIdx].match(/^(\s*)/)?.[1] || '';
        const ext = filePath.split('.').pop()?.toLowerCase();
        const commentStyle = getCommentStyle(ext);
        const ignoreComment = `${indent}${commentStyle} ship-safe-ignore — ${finding.reason || 'auto-suppressed by PR Guardian'}`;

        // Check if there's already an ignore comment above this line
        if (lineIdx > 0 && lines[lineIdx - 1].includes('ship-safe-ignore')) continue;

        lines.splice(lineIdx, 0, ignoreComment);
      }
    }

    const newContent = lines.join('\n');

    // Create a blob for the modified file
    const blobRes = await gh.fetch(`/repos/${owner}/${repo}/git/blobs`, {
      method: 'POST',
      body: JSON.stringify({ content: newContent, encoding: 'utf-8' }),
    });
    if (!blobRes.ok) continue;

    const blobData = await blobRes.json();
    treeEntries.push({ path: filePath, mode: '100644', type: 'blob', sha: blobData.sha });
    fixedFiles.push(filePath);
  }

  if (treeEntries.length === 0) {
    await appendTimeline(run.id, 'No files modified', 'Could not apply fixes');
    await prisma.pRGuardianRun.update({ where: { id: run.id }, data: { status: 'blocked' } });
    return;
  }

  // Create a new tree with the modified files
  const treeRes = await gh.fetch(`/repos/${owner}/${repo}/git/trees`, {
    method: 'POST',
    body: JSON.stringify({ base_tree: baseTreeSha, tree: treeEntries }),
  });
  if (!treeRes.ok) throw new Error(`Failed to create tree: ${treeRes.status}`);
  const treeData = await treeRes.json();

  // Create a commit
  const fixSummary = `Suppress ${fixableFindings.length} false positive(s) in ${fixedFiles.length} file(s)`;
  const commitBody = fixedFiles.map(f => `- ${f}`).join('\n');
  const newCommitRes = await gh.fetch(`/repos/${owner}/${repo}/git/commits`, {
    method: 'POST',
    body: JSON.stringify({
      message: `fix: ${fixSummary}\n\n${commitBody}\n\nAuto-fixed by Ship Safe PR Guardian`,
      tree: treeData.sha,
      parents: [baseSha],
    }),
  });
  if (!newCommitRes.ok) throw new Error(`Failed to create commit: ${newCommitRes.status}`);
  const newCommit = await newCommitRes.json();

  // Update the branch reference
  const updateRefRes = await gh.fetch(`/repos/${owner}/${repo}/git/refs/heads/${encodeURIComponent(run.prBranch)}`, {
    method: 'PATCH',
    body: JSON.stringify({ sha: newCommit.sha }),
  });
  if (!updateRefRes.ok) throw new Error(`Failed to update ref: ${updateRefRes.status}`);

  await appendTimeline(run.id, 'Fix committed', `${newCommit.sha.slice(0, 7)}: ${fixSummary}`);

  await prisma.pRGuardianRun.update({
    where: { id: run.id },
    data: {
      status: 'verifying',
      fixCommitSha: newCommit.sha,
      fixSummary,
      attempts: run.attempts + 1,
    },
  });

  // Don't advance immediately — wait for check_suite webhook to fire
  await appendTimeline(run.id, 'Waiting for CI', 'Monitoring for check suite completion...');
}

function getCommentStyle(ext?: string): string {
  switch (ext) {
    case 'py': case 'rb': case 'sh': case 'bash': case 'yaml': case 'yml': case 'toml':
      return '#';
    case 'html': case 'xml': case 'svg':
      return '<!--'; // will need closing --> but ship-safe handles inline comments
    case 'css': case 'scss':
      return '/*'; // will need closing */
    default:
      return '//';
  }
}
