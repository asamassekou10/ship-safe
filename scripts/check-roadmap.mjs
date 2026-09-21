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
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const roadmap = readFileSync(join(root, "ROADMAP.md"), "utf8");

const heading = roadmap.match(/^## Just shipped\s*[—-]\s*([0-9]+\.[0-9]+\.[0-9]+)/m);

if (!heading) {
  console.error('check-roadmap: no "## Just shipped — <version>" heading in ROADMAP.md.');
  console.error(`  package.json is ${version}. Add the heading so the file states what shipped.`);
  process.exit(1);
}

if (heading[1] !== version) {
  console.error("check-roadmap: ROADMAP.md is behind the package.");
  console.error(`  ROADMAP "Just shipped": ${heading[1]}`);
  console.error(`  package.json:           ${version}`);
  console.error("");
  console.error("  Update the Just shipped and Now sections, then re-run. Contributors");
  console.error("  choose work from this file, so a stale one sends them at closed issues.");
  process.exit(1);
}

console.log(`check-roadmap: ROADMAP.md states ${heading[1]}, matching package.json`);
