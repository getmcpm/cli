# mcpm contributor instructions

mcpm is the open-source, CLI-first MCP security guard and package manager:
npm `@getmcpm/cli`, command `mcpm`. Trust assessment, supply-chain evidence and
runtime protection are the product. Keep changes small, deterministic and scoped.

## Start here

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup and checks, and
  [docs/MAINTAINER-WORKFLOW.md](docs/MAINTAINER-WORKFLOW.md) for current context,
  task skills and historical decisions. Read detailed references only as needed.
- [docs/BACKLOG.md](docs/BACKLOG.md) is the selected active queue. Its #IDs are
  project backlog IDs, not GitHub issues. Research and historical roadmaps are
  context, not authorization or commitments to build the whole queue.
- Follow the user's scope and builder/reviewer choices. Use existing authorization
  and finish authorized work autonomously; ask only for missing material scope or
  permission. Review-only requests stay read-only. A build or PR does not imply
  authorization to merge, tag, publish, deploy or contact other people.
- Preserve dirty worktrees, unrelated files and local history. Use isolated
  checkouts when needed; never reset or restore another contributor's work.

## Product and implementation invariants

- Local-first, OSS-first, no telemetry, hosted backend, proprietary lock-in or
  additional model/subscription requirement on the default path. Calling agents
  handle natural language; mcpm supplies deterministic evidence. Jev/Clef is
  deferred, not a dependency. Avoid new runtime dependencies; justify any needed.
- One TypeScript/ESM package, Commander CLI, Zod boundary schemas, tsup build,
  Vitest tests. Reuse existing helpers and immutable data patterns; return new
  objects rather than mutate shared data. Consume official Registry API v0.1 at
  `registry.modelcontextprotocol.io`; tolerate upstream errors/resets honestly.
- Local state lives in `~/.mcpm/`; registry reads are live, with no registry cache.
  Do not introduce infrastructure for speculative future roadmap features.
- Validate registry/config/tool input before use. Preserve security/trust gates,
  strict MCP inputs, native restrictions and explicit coverage gaps. Never lower
  thresholds, allow unguarded/fresh launches or re-lock drift merely to finish.
- Config writes use backup-before-write and atomic write-then-rename. Preserve
  unrelated entries/bytes, credentials, custom arguments, disabled state and
  guard/confinement wrappers. Respect client-specific adapters (including VS Code
  JSONC and Cursor/Gemini parked definitions); unreadable is not absent/healthy.
- Keep values out of secret findings/reports/logs. Use disposable state for tests;
  do not read real client configuration or touch a real keychain for a fixture.
- The external scanner is opt-in via an already-installed executable named by
  `MCPM_EXTERNAL_SCANNER`; never fetch one automatically or bypass runner/shell
  refusal. Native safety floors exclude unverifiable external-scanner credit.
- Guard is a stdio relay; HTTP/SSE does not gain its protection. OS confinement
  is opt-in and macOS-first with documented hybrid/fail-closed conditions; do not
  turn it into a claim of universal sandboxing or general exfiltration prevention.
- Unkeyed integrity sidecars detect corruption, not authenticity against a
  same-user writer. Sigstore authenticates build identity, not code safety.

## Evidence and verification

- Read [docs/CONTRACTS.md](docs/CONTRACTS.md) before changing CLI exit codes,
  config/lock formats or MCP/JSON results. Preserve schema/version semantics;
  unavailable, skipped, unknown and `not_run` never mean passed.
- Metadata/configured state, wrapper recognition, native observed loading and
  actual enforcement are separate evidence. Static recognition cannot authenticate
  a launcher; a native command named inspection can still execute a server
  (Claude Code `mcp get` has done so). Keep read-only work non-executing.
- `mcpm scope` inventories fixed Claude Code sources/instruction metadata only;
  host version, effective selection, loading and enforcement stay unknown. It is
  separate from DoctorModel and the nine served MCP tools.
- Tests first for behavior: reproduce a bug before fixing the shared cause and
  inspect all callers. Exercise the public path and realistic edge cases, not a
  hand-copied implementation. For security predicates, verify the relevant clause
  can fail; failed measurements are failures, never clean results.
- Select checks for the changed surface using the development skill below.
  Source tests, packed artifacts, SDK peers and native clients prove different
  things. Candidate changes need candidate evidence; a fixed published reference
  run does not validate changed code. Keep baseline pins unless updating them is
  part of the task. Bind receipts to source/archive/runtime/lock/harness identity.
- Reproduce review findings before fixing; review the final diff after fixes.
  Report observed out-of-scope problems without silently expanding the patch.
  Never claim an independent/model review that did not happen.

## Toolchain and delivery

- Node.js `^22.22.2 || ^24.15.0 || >=26.0.0`, pnpm 10; use
  `pnpm install --frozen-lockfile`. CI tests Node 22/24/26, with matching typings;
  local `@types/node` is pinned to the Node 22 floor.
- Preserve all nine `pnpm.overrides` when updating dependencies/lockfiles.
  Dependabot lock regeneration can omit them; follow CONTRIBUTING rather than
  dropping the overrides to make installation pass.
- `package.json` intentionally stays at placeholder `0.15.0`; release tags inject
  the published version through `.github/workflows/publish.yml`. Do not manually
  bump the tracked package version as release preparation.
- Update relevant docs and the self-contained public `skills/mcpm/SKILL.md` when
  behavior/workflow changes; its version is descriptive, not CLI semver. Keep
  `CHANGELOG.md` entries under Unreleased until release; retain stamped sections.
- Use conventional commits and focused, reviewable PRs. Workflow changes require
  CODEOWNERS review. Follow [SECURITY.md](SECURITY.md) for vulnerability reports.
  Verify actual remote PR/check/tag/deployment state before reporting completion.

## Maintainer skills

- [.agents/skills/mcpm-development/SKILL.md](.agents/skills/mcpm-development/SKILL.md):
  scoped implementation, regression checks, requested review/fix loop and docs.
- [.agents/skills/mcpm-release/SKILL.md](.agents/skills/mcpm-release/SKILL.md):
  release preparation, exact-artifact proof and companion synchronization.

These are repo maintainer workflows. The distributed public usage skill remains
[skills/mcpm/SKILL.md](skills/mcpm/SKILL.md); do not mix contributor instructions
into it or install/change global skills and permissions as a side effect.
