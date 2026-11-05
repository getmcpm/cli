---
name: mcpm-release
description: Prepare, publish and verify getmcpm/cli releases, including required synchronization of getmcpm/guard-playground and getmcpm/mcp-guardbench. Use for mcpm release, tag, publish and release-closeout requests.
---

# mcpm release

Read the repo [AGENTS.md](../../../AGENTS.md),
[CONTRIBUTING.md](../../../CONTRIBUTING.md) and
[maintainer context](../../../docs/MAINTAINER-WORKFLOW.md) first. Run commands
from the relevant repository root; use its current scripts and frozen toolchain.
The canonical source of this workflow is this repo file, not a same-name global
skill. Do not modify global skills/config as part of a release.

A getmcpm release includes checking and updating its companion repositories.
Publishing the CLI alone is not a fully synchronized release. Audit companions
before tagging; finalize their updates after the published artifact is available.

## Scope and authorization

- Include companion inspection, scoped synchronization changes, validation and
  reviewable PRs in the release workflow. Respect explicit repository exclusions.
- Use existing authorization without asking again. A CLI release instruction
  does not by itself authorize merging or deploying other repositories. Complete
  the concrete companion changes and checks before requesting any missing final
  approval; report pending merges/deployments honestly.
- This skill is not authorization to publish, merge unrelated PRs, deploy a site
  or contact contributors. Follow the user's requested builder/reviewer workflow.
- Preserve dirty worktrees and active branches; use isolated release checkouts.
  Read each repository's instructions and current release/update scripts.

## Before the tag: inspect the whole release surface

Check live default branches, the latest published CLI and open PRs. Do not rely
on a past release's pins, score table or prior assertion that companions are synced.

| Repository | Required audit |
| --- | --- |
| [getmcpm/cli](https://github.com/getmcpm/cli) | Intended merged scope, release source, CI, changelog, docs and public mcpm skill |
| [getmcpm/guard-playground](https://github.com/getmcpm/guard-playground) | CLI dependency/lock, `engine.lock.json`, generated browser engine/metadata, corpus pin, pending updates and deployment state |
| [getmcpm/mcp-guardbench](https://github.com/getmcpm/mcp-guardbench) | Adapter compatibility, pinned published-version results, README scoreboard, corpus commit and pending fixes |

Use `gh repo list getmcpm` to identify any new relevant companions and
`gh search prs --owner getmcpm --state open` to find overlapping work. Review
existing companion PRs before creating duplicates. An old repin/score PR may need
superseding with the target version rather than merging unchanged. Keep useful
adapter/test fixes distinct from obsolete version updates. Triage relevant incoming
PRs; do not blindly merge the dependency backlog or discard pnpm overrides.

For stable releases, default to aligning the playground engine/dependency and a
fresh guardbench score with the target published CLI. An intentional fixed baseline
or prerelease exception must be explicit and documented, not inferred from an
unchanged detector or a green `@latest` CI run.

## Prepare and publish the CLI

- Determine semver from the actual changes and repository policy. Merge only
  authorized PRs, matching their reviewed heads, after required checks pass.
  This repository uses squash merges.
- Keep `package.json`'s tracked placeholder version unless the repository changes
  its policy. The publish workflow injects the tag version. Stamp a new changelog
  section without folding older published sections into Unreleased.
- Use the repository's pinned toolchain and frozen locks. Before the tag, run
  typecheck/build, source tests, coverage and its negative-threshold probe, and
  packed release dogfood; select protocol/native checks for the changed surface
  using the [development workflow](../mcpm-development/SKILL.md). Preserve all
  nine dependency overrides and fixed reference/native baselines.
- Verify required CI/security checks for the exact branch/PR head, then the
  intended release source or a proven identical tree. A green earlier head is
  insufficient. Distinguish pending optional checks and runner queues from
  failures; record source SHA, reviewed head/tree and check identities.
- Push an annotated version tag only when authorized. Verify its remote peeled
  SHA, then monitor `.github/workflows/publish.yml` through all jobs, including
  official registry listing. Use the configured OIDC workflow; do not invent
  credentials or manually repeat a successful npm publication.
- npm metadata, tarballs and attestations can propagate at different times.
  Retry bounded read-only checks; a transient 404 does not justify republishing.
  If only the registry listing failed after npm succeeded, inspect the workflow's
  listing-only recovery for the already-published version.

## Verify the bytes users receive

Download the actual npm tarball and compare its integrity with the exact-version
registry record. Authenticate SLSA subject, source commit, workflow/tag SAN and
GitHub Actions issuer using the existing trusted-root verifier. Check the release
SBOM signature and rejection of altered bytes when assets are present. Workflow
success or an attestation's existence is not cryptographic verification; missing
best-effort assets must remain explicit limitations.

Clean-install the downloaded archive with disposable client state and run the
repository's release smoke and modern/legacy direct/guarded protocol sandbox.
Bind receipts to archive/runtime hashes, dependency lock, harness, public skill
and actual isolation. Keep expected unsupported cases and exclusions visible.
Use native-client checks where needed for the changed behavior; record exact
versions and separate configured, observed-loaded and enforced evidence. Do not
transfer old native results to a new archive or claim universal compatibility.
Do not assume a native client's inspection command is non-executing: a pinned
Claude Code `mcp get` reference previously launched a harmless server sentinel.

## Required companion updates after publication

### guard-playground

1. Inspect its current README, package scripts and engine lock. Align the CLI
   dependency and dependency lock, engine source tag/commit, generated engine and
   version metadata with the target release. Verify source identity against the
   released CLI; do not substitute an arbitrary local checkout.
2. Run its supported engine build, corpus sync/check and tests (currently
   `build:engine`, `sync:corpus`, `check:engine`, `test`). Follow the repository's
   CLI comparison setup and bind any local reference to the intended release.
   Preserve the declared corpus commit unless deliberately updating the corpus.
3. Validate browser/CLI verdict parity. The browser demo is a stateless detector
   surface, not proof of stdio relay, runtime guard or OS confinement behavior.
   Open/update the scoped PR. Verify Pages deployment separately if authorized;
   a merged pin is not proof that the public site serves the new engine.

### mcp-guardbench

1. Score the **exact published CLI version**, through its public command, against
   the declared corpus commit using the existing runner/adapter. Weekly CI using
   `@latest` is not a reproducible versioned result. Never score an unpublished
   local build and label it as the released package.
2. Resolve adapter incompatibilities with evidence and tests. Do not change the
   corpus or expected verdicts to improve the score. Preserve historical results.
3. Commit the new versioned result artifacts and update the README scoreboard
   with measured metrics/coverage, not copied previous numbers. Record CLI version,
   corpus commit and invocation; validate the run and open/update its PR.

## Documentation and completion gate

Update relevant CLI/companion docs, release proof and the mcpm Obsidian release,
status/backlog notes when that vault is available. Keep candidate, published,
merged and deployed checkpoints distinct. Do not mark a broader backlog item
closed merely because one slice shipped.

Before the final reply, record a per-repository matrix: target/source or pin,
changes or justified baseline exception, PR and merge state, validation evidence,
and publication/deployment state. Companion PRs still open mean synchronization
is **pending**, even if the CLI release succeeded. If authorization or an external
failure prevents completion, finish unaffected work and identify the exact pending
action; never silently omit a companion or claim the entire release is synced.

Report the CLI release link, actual artifact verification, companion outcomes,
incoming relevant PRs and any material unchecked limits concisely.
