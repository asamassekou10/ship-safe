# Releasing Ship Safe

Ship Safe publishes the npm package from GitHub Releases. Maintainers do not run
`npm publish` from a laptop for normal releases.

## Release Path

1. Merge the release-ready changes into `main`.
2. Confirm `package.json` has the version you want to publish.
3. Confirm `CHANGELOG.md` includes user-facing notes for that version.
4. Create and publish a GitHub Release, usually with a matching tag such as
   `v9.6.1`.
5. The `Publish to npm` workflow runs automatically on the `release.published`
   event.
6. If the workflow succeeds, npm receives the package with provenance.

The workflow lives in `.github/workflows/publish.yml`.

## What The Workflow Checks

The publish job runs in the `npm-publish` environment and uses Node.js 20. It:

- installs dependencies with `npm ci --ignore-scripts`
- runs `npm test`
- scans the repo with `node cli/bin/ship-safe.js scan .`
- runs `npm pack --dry-run`
- rejects package contents that include sensitive file names or extensions such
  as `.env`, `.pem`, `.p12`, `.pfx`, `.key`, `.keystore`, `.jks`, or
  `credentials.json`
- publishes with `npm publish --provenance --access public`

CI also runs on pull requests and pushes to `main` through
`.github/workflows/ci.yml`. That workflow tests Node.js 18, 20, and 22, runs the
deterministic benchmark corpus, scans Ship Safe itself, checks key CLI commands,
audits high-severity vulnerabilities, and verifies a locally packed global
install.

## Maintainer Checklist

Before publishing a release:

- `npm test`
- `npm audit --audit-level=high`
- `npm pack --dry-run`
- `node cli/bin/ship-safe.js scan .`
- Confirm the changelog matches the version.
- Confirm the GitHub Release notes explain the user-facing impact.
- Confirm no private cloud files, credentials, customer data, screenshots with
  secrets, or local environment files were added.

If local `npm pack --dry-run` fails because of cache permissions, use a temporary
cache rather than changing package files:

```bash
npm_config_cache=/private/tmp/ship-safe-npm-cache npm pack --dry-run
```

## Contributor Guidance

Contributors usually should not change release automation unless an issue asks
for it. During release prep, avoid unrelated edits to:

- `package.json` version
- `package-lock.json`
- `.github/workflows/publish.yml`
- `.github/workflows/ci.yml`
- generated release assets

Docs, tests, fixtures, detectors, and CI examples are welcome when they are
scoped to the issue or PR.

## Failed Publish

If the GitHub Release exists but npm did not publish:

1. Open the failed `Publish to npm` workflow run.
2. Fix the failing check in a normal PR.
3. Merge the fix to `main`.
4. Re-run the failed workflow only if the tag still points at the intended
   release commit. Otherwise create a new patch release.

Do not force-push release tags unless the release was never consumed and the
maintainer team explicitly agrees.
