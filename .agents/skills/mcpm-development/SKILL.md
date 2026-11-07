---
name: mcpm-development
description: Implement and validate scoped getmcpm/cli contributor changes, including regressions, requested model review and documentation. Use for work on this repository; use mcpm-release for release closeout and the public mcpm skill for CLI usage.
---

# mcpm development

Read [AGENTS.md](../../../AGENTS.md),
[CONTRIBUTING.md](../../../CONTRIBUTING.md) and the relevant
[maintainer references](../../../docs/MAINTAINER-WORKFLOW.md). Work from the repo
root. Honor existing authorization and complete the requested scope; this skill
does not grant merge, tag, publication, deployment or unrelated changes.

## Build the smallest complete change

1. Check branch/base and dirty state. Read the touched implementation and callers,
   contracts, fixtures and scripts; identify what the user-visible change reaches.
   Preserve unrelated work; isolate conflicting work in a fresh checkout.
2. For a bug, add a failing regression through the shared/public path before
   fixing the root cause. For new behavior, test its outcome and failure/coverage
   boundary. Keep changes surgical; reuse existing helpers. Pure docs changes
   need link/content/frontmatter checks rather than invented runtime tests.
3. Use a supported Node and pnpm 10 with `pnpm install --frozen-lockfile` when
   dependencies are needed. Preserve the tracked placeholder version, overrides
   and pinned baselines. Run focused tests, then the applicable checks below.

## Select checks for the surface

| Changed surface | Appropriate verification |
| --- | --- |
| Docs/instructions/skills only | Check current commands/claims, links/import targets, skill frontmatter and distribution boundaries. For loading claims, use an isolated read-only host smoke and name its limits. |
| Runtime/CLI/config/stack | Regression and affected caller tests; `pnpm run typecheck`, `pnpm run build`, `pnpm test`. Check built public commands with synthetic homes and preserve unrelated config/secret/disabled/wrapper state. |
| Dependencies/package/build | Above plus `pnpm dogfood:release` (packs, clean-installs and smokes the binary). Preserve engines and all nine overrides; source tests alone cannot prove packaged dependency loading. |
| Coverage gates | `pnpm run test:coverage` and `bash scripts/probe-coverage-thresholds.sh`; a startup crash is not proof the negative threshold gate worked. |
| MCP/serve/relay/Skills/wire outputs | Relevant regressions plus `pnpm run build`, then a fresh `pnpm pack --pack-destination <temporary-directory>` and `bash scripts/dogfood-protocol.sh <fresh-evidence-directory> <candidate.tgz>`; read the protocol/serve/Skills/doctor docs for the affected modern/legacy direct/guarded paths. Run applicable harness self-checks. |
| Native client configuration/launch/consent | Follow the named native/Cursor/Gemini doc and explicit candidate mode. For native tooling, run its self-checks (`node --test scripts/native-client/self-check.mjs` and doctor checks when relevant). Real native proof needs pinned clients and disposable profiles/VMs. |
| macOS confinement | `pnpm dogfood:confine` on macOS plus relevant regression tests; state other platform/backend limitations. |

Choose based on what changed, not a ritual full matrix for every edit. Source
runtime changes keep the suite/typecheck green; broaden testing when new findings
warrant it. The default protocol harness is a fixed published reference, so pass
the changed archive explicitly for candidate proof. Verify artifact/runtime/lock/
harness hashes and the actual isolation boundary. Do not infer native loading,
consent, provider/model behavior or universal conformance from SDK/source checks.
Native inspection commands may execute servers: do not invoke `mcp get` or another
client merely to fill unknowns in a read-only audit.

For [retained Skills fixtures](../../../docs/RETAINED-SKILLS-DECISION.md), consume
the expected/observed verification status and declared-set coverage together.
A harness pass on an expected mismatch/incomplete case is not clean skill
verification; catalog/directory scope and native loading remain separate.

For the [native inline-hook experiment](../../../docs/NATIVE-PLUGIN-LIFECYCLE.md),
run the existing native self-check entry point and the explicit offline native
command. Consume executed command markers plus complete raw lifecycle evidence;
settings, hook listings and declared bundle versions alone do not prove loading.
Keep text-skill activation unknown and real host profiles outside the fixture.

## Requested review and fix loop

Follow the user's model split: when requested, Sol builds and Astra reviews the
final diff independently. Supply the exact base/head (or uncommitted diff), scope
and evidence. Reviewers re-derive findings from current files, reproduce before
fixing and report out-of-scope observations. Use separate writable checkouts for
mutation testing; never restore/reset a shared dirty tree.

Fix confirmed findings, run the checks affected by those fixes, then have the
requested reviewer inspect the final result. If the requested model/tool is
unavailable, say so; do not label self-review or another model as Astra review.
Do not infer approval, merge or publication from a clean local review.

## Documentation and handoff

Update only relevant docs/contracts, Unreleased changelog entries and the public
[mcpm usage skill](../../../skills/mcpm/SKILL.md) when its consumer workflow
changes. Increment its descriptive version when its instructions change; keep it
self-contained. Update current backlog/release/status and the maintainer's mcpm
Obsidian notes when relevant, available and within the user's authorized scope;
absence of a private vault must not block an otherwise reviewable OSS change.

Prepare a focused PR with problem, resulting behavior, exact validation and
material limits. Verify remote state before saying a PR is open/merged or CI
passed. Report what was built, what was reviewed/fixed, evidence and unchecked
limits; leave merge/tag/deploy to their actual authorization. For an authorized
release, continue with the repo [release skill](../mcpm-release/SKILL.md).
