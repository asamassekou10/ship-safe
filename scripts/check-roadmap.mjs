#!/usr/bin/env node
//
// The roadmap's "Just shipped" heading must name the version in package.json.
//
// It drifted three releases — the file said "Just shipped — 9.7.0" and "Now —
// 10.0" while 10.0.0 was on npm and the 10.0 milestone was closed. That is worse
// than an out-of-date file: ROADMAP.md is what a contributor opens to decide what
// to work on, so it was pointing people at a milestone with no open issues and
// calling it the current work.
//
//     node scripts/check-roadmap.mjs
//
// Runs in CI and as part of the release. A heading a human has to remember to
// update is one that will be wrong.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export function validateRoadmap(version, changelog, roadmap) {
  const changelogHead = changelog.match(
    /^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - (Unreleased|[0-9]{4}-[0-9]{2}-[0-9]{2})/m,
  );
  if (!changelogHead) return 'CHANGELOG.md must start with a versioned release heading.';
  if (changelogHead[1] !== version) {
    return `CHANGELOG.md starts at ${changelogHead[1]}, but package.json is ${version}.`;
  }

  if (changelogHead[2] === 'Unreleased') {
    const now = roadmap.match(/^## Now\s*[—-]\s*([0-9]+\.[0-9]+)(?:\.[0-9]+)?/m);
    const candidateLine = version.split('.').slice(0, 2).join('.');
    if (!now) return `Unreleased ${version} needs a matching "## Now — ${candidateLine}" roadmap heading.`;
    if (now[1] !== candidateLine) {
      return `ROADMAP.md "Now" is ${now[1]}, but the unreleased package is ${version}.`;
    }
    return null;
  }

  const shipped = roadmap.match(
    /^## Just shipped\s*[—-]\s*([0-9]+\.[0-9]+\.[0-9]+)/m,
  );
  if (!shipped) return 'ROADMAP.md needs a "## Just shipped — <version>" heading.';
  if (shipped[1] !== version) {
    return `ROADMAP.md "Just shipped" is ${shipped[1]}, but package.json is ${version}.`;
  }
  return null;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const changelog = readFileSync(join(root, "CHANGELOG.md"), "utf8");
  const roadmap = readFileSync(join(root, "ROADMAP.md"), "utf8");
  const issue = validateRoadmap(version, changelog, roadmap);
  if (issue) {
    console.error(`check-roadmap: ${issue}`);
    process.exit(1);
  }

  const state = /^## \[[0-9]+\.[0-9]+\.[0-9]+\] - Unreleased/m.test(changelog)
    ? 'unreleased candidate in Now'
    : 'shipped version in Just shipped';
  console.log(`check-roadmap: ROADMAP.md tracks ${version} (${state})`);
}
