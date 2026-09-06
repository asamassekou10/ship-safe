#!/usr/bin/env node
/**
 * Report Hermes releases newer than the pinned coverage baseline (#205).
 *
 * The baseline in `cli/data/hermes-baseline.json` pins a release tag to a full
 * commit SHA, and every coverage claim in `docs/hermes-coverage-matrix.md` is
 * scoped to that snapshot. Upstream moves; nothing told us.
 *
 * This reports. It does not update anything, and deliberately cannot: the
 * workflow that runs it opens a pull request for a human to review, because a
 * coverage claim that follows upstream automatically is not a coverage claim.
 *
 * Two rules the output has to respect, both from #205:
 *
 *  - It never widens a claim. A surface whose upstream paths changed is
 *    reported as *needing review*, never as still covered.
 *  - A new file in a security-relevant path with no rule against it is
 *    reported as UNCOVERED rather than passed over in silence.
 *
 * Usage:
 *   node scripts/hermes-baseline-drift.mjs            # query GitHub
 *   node scripts/hermes-baseline-drift.mjs --json     # machine-readable
 *
 * Exit codes: 0 no drift, 1 drift found (the workflow reads this), 2 error.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const BASELINE = path.join(ROOT, "cli/data/hermes-baseline.json");

const API = "https://api.github.com/repos";

/** Read the pinned baseline. */
export function readBaseline(baselinePath = BASELINE) {
  return JSON.parse(fs.readFileSync(baselinePath, "utf8"));
}

/**
 * Paths this project claims to have rules against, flattened from the
 * baseline's surfaces. These are what a diff is filtered to: a change outside
 * them is upstream's business, not a coverage question.
 */
export function securityRelevantPaths(baseline) {
  return baseline.surfaces.flatMap((surface) =>
    surface.upstreamPaths.map((pattern) => ({ surface: surface.id, pattern })),
  );
}

/**
 * Does a changed file fall inside one of the baseline's upstream paths?
 *
 * The patterns are shell-style globs with `**`. Rather than pull in a matcher,
 * they are compiled to anchored regexes: `**` crosses separators, `*` does
 * not, everything else is literal. Keeping this explicit matters because a
 * matcher that is too permissive silently widens what we claim to watch.
 */
export function matchesPattern(filePath, pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const source = escaped
    .split("**")
    .map((part) => part.split("*").map((p) => p).join("[^/]*"))
    .join(".*");
  return new RegExp(`^${source}$`).test(filePath);
}

/** Surfaces touched by a list of changed file paths. */
export function surfacesTouched(baseline, changedPaths) {
  const patterns = securityRelevantPaths(baseline);
  const touched = new Map();
  for (const file of changedPaths) {
    for (const { surface, pattern } of patterns) {
      if (matchesPattern(file, pattern)) {
        if (!touched.has(surface)) touched.set(surface, []);
        touched.get(surface).push(file);
      }
    }
  }
  return touched;
}

/**
 * Files inside a watched surface directory that no declared path names.
 *
 * A `**` pattern covers a whole tree, so this is about a *new top-level
 * area* upstream added: if it is security-relevant and nothing matches it,
 * #205 requires it be flagged as uncovered rather than assumed fine.
 */
export function unmatchedSecurityFiles(baseline, changedPaths) {
  const patterns = securityRelevantPaths(baseline);
  const watchedRoots = new Set(
    patterns.map(({ pattern }) => pattern.split("/")[0]).filter((p) => !p.includes("*")),
  );
  return changedPaths.filter((file) => {
    const root = file.split("/")[0];
    if (!watchedRoots.has(root)) return false;
    return !patterns.some(({ pattern }) => matchesPattern(file, pattern));
  });
}

async function gh(url, token) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "ship-safe-baseline-drift",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`GitHub API ${response.status} for ${url}`);
  }
  return response.json();
}

/** Releases published after the pinned tag, newest first. */
export async function newerReleases(baseline, { token, fetchJson = gh } = {}) {
  const releases = await fetchJson(`${API}/${baseline.project}/releases?per_page=100`, token);
  const pinnedIndex = releases.findIndex((release) => release.tag_name === baseline.tag);
  // An unknown pinned tag means the baseline points at something that is no
  // longer published. That is drift too, and the loudest kind, so it is
  // reported rather than treated as "nothing newer".
  if (pinnedIndex === -1) return { unknownPinnedTag: true, releases: [] };
  return { unknownPinnedTag: false, releases: releases.slice(0, pinnedIndex) };
}

/** Files changed between the pinned commit and a newer one. */
export async function changedFiles(baseline, headSha, { token, fetchJson = gh } = {}) {
  const comparison = await fetchJson(
    `${API}/${baseline.project}/compare/${baseline.commit}...${headSha}`,
    token,
  );
  return (comparison.files ?? []).map((file) => file.filename);
}

/** Render the report a reviewer reads in the pull request body. */
export function renderReport(baseline, result) {
  const lines = [];
  lines.push(`## Hermes baseline drift`);
  lines.push("");
  lines.push(
    `Pinned: **${baseline.release}** (\`${baseline.tag}\`, \`${baseline.commit.slice(0, 12)}\`)`,
  );
  lines.push("");

  if (result.unknownPinnedTag) {
    lines.push(
      `> The pinned tag \`${baseline.tag}\` is not among the published releases. ` +
        `The baseline points at something upstream no longer lists.`,
    );
    return lines.join("\n");
  }

  if (result.releases.length === 0) {
    lines.push("No releases newer than the pinned tag. Nothing to review.");
    return lines.join("\n");
  }

  lines.push(`${result.releases.length} newer release(s):`);
  lines.push("");
  lines.push("| release | tag | commit | published |");
  lines.push("| --- | --- | --- | --- |");
  for (const release of result.releases) {
    lines.push(
      `| ${release.name ?? release.tag_name} | \`${release.tag_name}\` | ` +
        `\`${(release.sha ?? "").slice(0, 12)}\` | ${release.published_at ?? ""} |`,
    );
  }
  lines.push("");

  const touched = result.touched ?? new Map();
  if (touched.size > 0) {
    lines.push("### Surfaces with upstream changes");
    lines.push("");
    lines.push(
      "Each of these needs its detector re-checked against the new snapshot. " +
        "**No status may move to covered without that.**",
    );
    lines.push("");
    for (const [surface, files] of touched) {
      lines.push(`- **${surface}** — ${files.length} file(s) changed`);
      for (const file of files.slice(0, 10)) lines.push(`  - \`${file}\``);
      if (files.length > 10) lines.push(`  - ...and ${files.length - 10} more`);
    }
    lines.push("");
  } else {
    lines.push("No files changed inside the baseline's declared upstream paths.");
    lines.push("");
  }

  if ((result.unmatched ?? []).length > 0) {
    lines.push("### UNCOVERED: new areas no rule names");
    lines.push("");
    lines.push(
      "These sit under a watched directory but match no declared path. " +
        "Treat as **uncovered** until a rule exists.",
    );
    lines.push("");
    for (const file of result.unmatched.slice(0, 20)) lines.push(`- \`${file}\``);
    lines.push("");
  }

  lines.push("### What this pull request does not do");
  lines.push("");
  lines.push(
    "Nothing is updated. The baseline JSON, the coverage matrix and every status " +
      "are untouched. Moving the pin is a reviewed change that follows the procedure " +
      "in `docs/hermes-coverage-matrix.md`, including re-checking the known-CVE record.",
  );
  return lines.join("\n");
}

export async function run({ token = process.env.GITHUB_TOKEN, fetchJson = gh } = {}) {
  const baseline = readBaseline();
  const { unknownPinnedTag, releases } = await newerReleases(baseline, { token, fetchJson });

  const result = { unknownPinnedTag, releases, touched: new Map(), unmatched: [] };
  if (!unknownPinnedTag && releases.length > 0) {
    const newest = releases[0];
    const sha = newest.sha ?? newest.target_commitish;
    const files = await changedFiles(baseline, sha, { token, fetchJson });
    result.touched = surfacesTouched(baseline, files);
    result.unmatched = unmatchedSecurityFiles(baseline, files);
  }
  return { baseline, result };
}

// `process.argv[1]` is a platform path; import.meta.url is a file URL. Compare
// them as resolved URLs so this works on Windows as well as on the CI runner.
const invokedDirectly =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  run()
    .then(({ baseline, result }) => {
      const report = renderReport(baseline, result);
      if (process.argv.includes("--json")) {
        process.stdout.write(
          JSON.stringify(
            {
              pinned: { release: baseline.release, tag: baseline.tag, commit: baseline.commit },
              unknownPinnedTag: result.unknownPinnedTag,
              newerReleases: result.releases.map((r) => r.tag_name),
              surfacesTouched: [...result.touched.keys()],
              unmatched: result.unmatched,
            },
            null,
            2,
          ) + "\n",
        );
      } else {
        process.stdout.write(report + "\n");
      }
      const drifted = result.unknownPinnedTag || result.releases.length > 0;
      process.exit(drifted ? 1 : 0);
    })
    .catch((error) => {
      process.stderr.write(`${error.message}\n`);
      process.exit(2);
    });
}
