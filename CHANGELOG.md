# Changelog

All notable changes to this project will be documented in this file.

## [0.24.0] - 2026-07-23

Verify-time Sigstore provenance enforcement (F8 "B3" — the enforcing gate).

### Added

- **`mcpm verify` and `mcpm up --frozen` now re-verify provenance and fail closed.**
  Where the crypto slice (v0.23.0) *reported* provenance, these commands now
  **enforce** it: for every npm server whose lock recorded a cryptographically
  `verified` baseline, the gate re-runs the offline crypto verification against
  npm's **current** published record and blocks on a regression —
  - `signer-changed` — still verifies, but under a different (unforgeable) signer
    identity than the lock recorded (an attestation swap),
  - `regression` — was verified; now the attestation fails to verify or is gone,
  - `unverifiable` — couldn't cryptographically re-verify this run (re-run).

  The gate is **evidence-gated**: only servers with a `verified` baseline are
  checked, so a lock with none — every pre-crypto lock and the overwhelmingly
  unsigned MCP ecosystem — is unaffected. `mcpm verify` reports the provenance
  dimension in its text and `--json` model; `up --frozen` runs the integrity +
  provenance freeze before installing anything.

### Changed

- `mcpm lock` keeps a crypto-`verified` baseline **sticky** across a re-lock whose
  fresh read is transient or no longer verifies (for the same immutable
  coordinate), so a network blip can't silently disarm the verify-time gate; it
  warns loudly on a genuine verification regression or downgrade.
- Honest boundary unchanged: a block means npm's **published record** diverged from
  your lock — not that mcpm inspected the bytes your agent runs at launch.

## [0.23.0] - 2026-07-20

Offline cryptographic verification of npm provenance (F8 crypto slice).

### Added

- **Offline Sigstore verification of npm provenance** — `mcpm lock` and `mcpm why`
  now cryptographically verify a package's SLSA provenance **offline**: the
  attestation's Sigstore bundle is checked against a vendored, authenticity-verified
  trust root (no Rekor/Fulcio network call — the bundle inlines the transparency-log
  entry and certificate chain). A record reads `verified` only when **all** hold:
  the signature + Fulcio chain + SCT + Rekor inclusion verify, the signer's OIDC
  issuer is GitHub Actions, and the attested subject digest binds to **every**
  `sha512` entry of the package's `dist.integrity` (so a valid attestation for a
  *different* tarball cannot pass). The reported build identity is derived from the
  unforgeable signing certificate, not the self-claimed payload.

  Uses three focused `@sigstore` packages (verify / bundle / protobuf-specs; no
  foreign transitive dependencies) and raises the Node floor to `>=22.9.0`.
  **Report-only**, and honest about scope: `verified` means the *build identity* is
  cryptographically attested by the CI's OIDC token — **not** that the code is safe.
  The `mcpm why` Provenance section now renders this verdict.

### Changed

- Removed ~871 lines of dead code and duplication across the repo (two unused
  modules, several unused functions/fields, and behavior-identical consolidations),
  and fixed a bug the cleanup surfaced: `mcpm list` had silently omitted the
  Claude Code and Gemini CLI clients.

### CI

- The release pipeline now **dogfoods the packed artifact before publishing**:
  it packs the tarball, installs it into a clean project, and smoke-runs the real
  `mcpm` binary — failing the release *before* publish if the shipped bytes are
  broken (so a bad `bin`, an unresolved dependency, an engines mismatch, or an
  un-bundled asset can never reach npm).

## [0.22.0] - 2026-07-18

`mcpm lock` gains npm provenance-identity drift detection (F8 · slice 1).

### Added

- **npm provenance-identity drift tripwire** — `mcpm lock` now records each npm
  server's published Sigstore attestation identity (source repo + the immutable
  numeric GitHub repository/owner ids + workflow + commit) into the lockfile and
  WARNs when it drifts across versions: a repo/owner change or a signed→unsigned
  drop — the shape of a hijacked-publish (Postmark) attack, which schema-pinning
  structurally cannot see.

  It is **parse-only and report-only**, with **zero new dependencies**: it parses
  npm's published attestation record (JSON + base64, no cryptographic verification)
  over TLS from a hard-coded host — the same anchor the `dist.integrity` tripwire
  already trusts. It **never blocks the lock** and never changes exit codes.

  **Honesty boundary:** `attested` means an *unverified registry record* — build
  **identity, not safety**. This slice never reports "verified"; cryptographic
  Sigstore verification (which would add dependencies) is a separate, opt-in
  follow-up. It cannot catch a same-repo CI compromise that produces a valid
  attestation with an unchanged identity.

  Drift comparison is tiered on the immutable numeric ids so a legitimate repo
  rename (stable id, changed URL) is not a false positive, and a transient fetch
  failure carries the last known-good baseline forward rather than silently
  disarming the tripwire.

## [0.21.0] - 2026-07-16

`mcpm doctor` now surfaces plaintext secrets pasted into client config (F9 · PR1).

### Added

- **`doctor` plaintext-secret scan** — `mcpm doctor` scans installed servers' `env`
  and `header` values for plaintext secrets and reports them as a read-only advisory,
  so you can move them into the encrypted store (`mcpm secrets` / `--secrets keychain`).
  Two detectors: known-format credential shapes (AWS / GitHub — including fine-grained
  `github_pat_` — / OpenAI / Stripe / Slack / … keys), and a secret-named-key heuristic
  for generic passwords/tokens, gated by a benign corpus to hold the zero-false-positive
  line. Findings report the **key name and a label only — never the value**, and values
  already stored as `mcpm:keychain:` placeholders are skipped. The advisory flows to the
  text output, `--json`, `--report` (a count only — no names), and the MCP `doctor` tool.
  It is **advisory and non-gating**: it never changes `doctor`'s exit code.

  Known false-positive-safe by design: templated references (`Bearer ${input:key}`,
  `%VAR%`), secret-manager URIs (`op://`, `vault://`), and file paths (POSIX + Windows)
  are excluded. Known deferred gaps (documented): the login-shell PATH probe and `--fix`
  mutators (F9 PR2–PR4), inline connection-string credentials, and credential-carrying
  URIs such as `otpauth://…?secret=`.

## [0.20.1] - 2026-07-16

A patch closing the three follow-ups flagged during the v0.20.0 security review
(#131). No API changes.

### Fixed

- **guard/relay — the 64 MB buffer-cap teardown no longer crash-loops the guard.**
  When a wrapped server exceeded the unframed-input cap, the relay called
  `source.destroy(new Error(...))`; the source (`child.stdout`) has no `'error'`
  listener, so that re-emitted as an uncaughtException and crash-looped the guard —
  the same vector the v0.20.0 review fixed at the four `readMessage()` sites but left
  on the buffer-cap branch. It is now a no-arg `destroy()`, matching the
  malformed-frame teardown; the DoS `block` event is still emitted.

### Security

- **registry — free-text response fields are now length-bounded.** The v0.20.0 ReDoS
  fix bounded per-regex cost; these Zod `.max()` ceilings (1 KB identifiers / 8 KB
  URLs / 64 KB free text) bound the input length itself at the untrusted registry
  boundary. Ceilings are deliberately generous — `safeParse` drops the whole page on
  a single over-ceiling field, so they deny only multi-MB DoS payloads and never clip
  legitimate data; `icon.src` is intentionally left uncapped (it may be a large
  `data:` URI and is never scanned or rendered).
- **guard/confine — a drift-guard test locks the secret-dir read-denylist to the
  supported client set.** The denylist is hand-maintained and had silently drifted
  behind two clients before the review caught it; a new test walks every supported
  client's config path and fails the build if one is not covered by a denied segment,
  so the denylist can no longer rot behind a newly-added client adapter.

## [0.20.0] - 2026-07-14

Response-side credential DLP lands (**F10 Detector-A + B**) and a full adversarial
security review hardens the guard, scanner, relay, and confine sandbox. The guard now
warns-and-redacts on credentials egressing in tool responses (including base64-encoded
ones), and six independently-verified findings — from a zero-width-separator signature
bypass to an O(n²) scanner ReDoS — are fixed.

### Added

- **F10 Detector-A — response-side credential DLP** — a 10th catalog signature,
  `credential-egress-in-response` (WARN-tier), flags a high-confidence **structural**
  credential returned in a `tool_response`: PEM private-key blocks, `gh[pousr]_` /
  `github_pat_` (GitHub), `glpat-` (GitLab), `sk-` / `sk-ant-` / `sk-proj-` (OpenAI/
  Anthropic), `[sr]k_(live|test)_` (Stripe), `xox[baprs]-` (Slack), `npm_`, `AIza`
  (Google), and `AKIA…` (AWS, excluding the documented example key). Warn — not block —
  because a secrets-manager/auth tool legitimately returns credentials; the caught
  secret is **redacted** to `‹redacted N-char secret›` so it never reaches the warning
  message or `guard-events.jsonl`.
- **F10 Detector-B — decode-and-rescan** — the guard now decodes base64 / base64url
  runs inside server-returned data (`tool_response`, `resource_content`,
  `prompt_content`) and re-runs the signatures on the decoded text, closing the
  encoding-evasion gap where a server base64-wraps an injection or credential to slip
  past the regex floor. Decoded findings are **WARN-clamped** (strictly additive — a
  decoded match can never block on its own), gated by a printable-ratio "texty" test
  and the anchored-signature set to preserve the zero-false-positive contract.

### Security

Fixes from an adversarially-verified multi-lens review (each finding refute-tested
before it counted):

- **guard/signatures — zero-width-separator bypass of the instruction-injection family
  (HIGH).** `PATTERN_BREAKERS` strips a zero-width space *before* matching, so
  `ignore<U+200B>previous instructions` collapsed to adjacency and the `[\s]+`
  (≥1 whitespace) separator failed to match → the frame passed. Internal separators are
  now `[\s]*` across all five injection targets (parity with the credential family's
  existing `[\s-]*` fix).
- **guard/confine — read-denylist omitted Claude Code and Gemini CLI configs (HIGH).**
  A confined server could read `~/.claude.json` / `~/.gemini` — which hold sibling
  servers' plaintext `env` credentials — under the sandbox's `(allow default)` read
  posture. Both are now in the secret-directory denylist (all six clients covered).
- **guard/patterns — deep-nesting inspection blind spot (MEDIUM).** The leaf walk's
  depth cap silently dropped an injection buried >32 levels deep in `structuredContent`.
  Replaced the recursive depth-cap with an iterative, node-budget-bounded walk — closes
  the blind spot and the recursion stack-overflow risk in one change.
- **scanner — O(n²) ReDoS in the base64 pattern (MEDIUM).** A long unpadded
  base64-alphabet run in attacker-controlled registry metadata made `search`/`audit`
  backtrack ~2.5 s per 32 KB field. Bounded the quantifier (`{40,512}`) — padding stays
  required, so nothing new matches on benign input.
- **relay — malformed frame crashed the guard (LOW).** A non-JSON-RPC line on the
  wrapped server's stdout (e.g. a startup banner) became an uncaught exception and
  crash-looped the relay. All frame-read sites now fail closed: emit a RELAY
  `malformed-frame` block event and tear down the source, forwarding nothing.
- **search/info — terminal escape injection via registry free-text (LOW).**
  Registry-controlled `description` / `title` / `repository.url` / `websiteUrl` reached
  the terminal without stripping ANSI/OSC/control chars (link/window-title/line-overwrite
  spoofing). The human-render branches now route through `sanitizeForTerminal`; `--json`
  output stays byte-faithful.

### Fixed

- **Two Tier-1 scanner false-positive classes** surfaced by a full-registry sweep — the
  "Bearer" credential phrase and the "system prompt" injection pattern no longer fire on
  benign prose (structural/verb-anchored patterns; regression-tested).

### Documentation

- **`docs/VISION.md`** — the strategy layer (thesis, trust flywheel, horizons with exit
  metrics, the "never" doctrine), cross-linked from the roadmap and README.

### Dependencies

- `ora` 9.4.0 → 9.4.1, `ossf/scorecard-action` bump, and the dev-dependency group
  (`vitest` / `@vitest/coverage-v8` 4.1.9 → 4.1.10, `@types/node` patch).

## [0.19.0] - 2026-07-03

The rest of Wave 1 in one release — developer reach and CI citizenship: mcpm now manages **Gemini CLI**, `mcpm verify` and `mcpm audit --sarif` make it a first-class CI gate (client-free integrity + SARIF code-scanning), `mcpm doctor` gains a structured `--json` and a redacted `--report`, and the README documents every collision-free install channel (npm/npx/pnpm/mise).

### Documentation

- **Install matrix + distribution doc (D6)** — the README now lists npm / npx / pnpm /
  **mise** (`mise use -g npm:@getmcpm/cli`, via mise's built-in `npm:` backend — no
  registry entry needed) as install channels, all resolving the scoped `@getmcpm/cli`
  package. New `docs/DISTRIBUTION.md` documents the deliberate **name-collision
  decision**: the `mcpm` Homebrew formula (and PyPI name) belong to the unrelated
  [mcpm.sh](https://mcpm.sh) project, so mcpm ships through the collision-free scoped
  channels rather than fighting for `brew install mcpm`. A Homebrew tap + mise
  registry short-name are deferred (documented).

### Added

- **`mcpm audit --sarif` (D3)** — emit a SARIF 2.1.0 report for GitHub
  code-scanning (`github/codeql-action/upload-sarif`). One rule per real
  `Finding.type`; each finding becomes a result anchored **file-level** to
  `mcpm.yaml` (audit scans installed servers, which have no source line — a
  fabricated line number would be a lie), with severity mapped to SARIF
  `error`/`warning`/`note` and a stable fingerprint so GitHub tracks the same alert
  across runs. Report-only (never fixes); exit code matches `audit` (`1` when risky).
- **`mcpm verify` + an official GitHub Action (D2)** — a repo-only, **client-free**
  integrity gate for CI. `mcpm verify` loads `mcpm-lock.yaml` and runs the same
  fail-closed integrity pass as `mcpm up --frozen` — BLOCK (exit 1) on integrity
  drift, an unverifiable record, a format mismatch, or a suspicious missing baseline
  — but, unlike `up`, it needs **no AI clients installed**, so it runs on a hosted
  runner (where `up` hard-fails on zero detected clients). `--json` emits a
  structured model; a composite Action at `.github/actions/mcpm-verify` wraps it with
  a job step summary. Pre-commit rides the same verb. Deliberately **one verb**:
  provenance (Sigstore) will *extend* `mcpm verify` later, never fork it. v1 scope is
  npm `dist.integrity`; pypi/oci/url are reported as unenforceable, and stack-vs-lock
  staleness is a deferred follow-up.
- **`mcpm doctor --json` and `--report`** — `doctor`'s checks are now built into a
  structured `DoctorModel` (clients with server + guarded counts, runtimes, advisory
  cross-client drift, typed issues, `ok`). `--json` emits that model (shape UNSTABLE);
  `--report` emits a **redacted, pasteable** environment snapshot for bug reports —
  OS/arch, mcpm + node versions, per-client server counts, runtime availability,
  confine-backend + secret-store backend, and issue **counts** only. It deliberately
  carries **no server names or arguments** (issue messages that embed a server name
  are reduced to counts). A new `.github/ISSUE_TEMPLATE/bug.yml` requires a pasted
  report — the telemetry-free way to learn what setup hit a bug.
- **Gemini CLI adapter (`~/.gemini/settings.json`)** — mcpm now reads and writes
  MCP servers for **Gemini CLI** (Google's terminal agent) as a first-class client
  (`--client gemini-cli`). Same top-level `mcpServers` map as Claude Code / Cursor,
  so every command that enumerates clients — `install`, `remove`, `list`, `audit`,
  `doctor`, `sync --check`, `up`, `guard`, … — picks it up automatically. Scope is
  the **user-global** config; per-project `.gemini/settings.json` is intentionally
  out of scope. Writes preserve every unrelated setting in the file (`theme`,
  `selectedAuthType`, …) via the existing atomic read-modify-write + `.bak` backup.
  Note: Gemini reads `url` as an SSE endpoint and `httpUrl` as HTTP — mcpm writes
  `url`, the same URL-transport caveat that already applies to non-Cursor clients.
  Zero new deps.

### Internal

- **Shared frozen-verify extraction** — `classifyIntegrity` + a new pure
  `frozenVerdict` moved from `up.ts` into `src/stack/frozen-verify.ts`, consumed by
  both `up --frozen` and the new `mcpm verify`. `up`'s output and block matrix are
  byte-identical (its 13 frozen tests pass unchanged).

### Fixed

- **`mcpm_doctor` MCP tool now reports real issues** — it previously returned a
  hardcoded `issues: []` and listed only *detected* clients. It now reuses the same
  `DoctorModel` builder as the CLI, so an agent calling the tool sees malformed
  configs and missing-runtime issues (and the full per-client health), not an empty
  list.

## [0.18.0] - 2026-07-03

A developer-reach release: mcpm becomes usable with **Claude Code**, the most widely-used MCP host. Also the first release to actually ship the CycloneDX SBOM as a release asset (the v0.17.0 attach step tripped over GitHub immutable releases; now fixed).

### Added

- **Claude Code adapter (`~/.claude.json`)** — mcpm now reads and writes MCP
  servers for **Claude Code**, the most widely-used MCP host, as a first-class
  client (`--client claude-code`). Every command that enumerates clients —
  `install`, `remove`, `list`, `audit`, `doctor`, `sync --check`, `up`, `guard`,
  … — picks it up automatically. Scope is the **user-global** `mcpServers` map;
  per-project servers (`projects[<path>].mcpServers`) are intentionally out of
  scope for now. Writes preserve every unrelated key in the file (`projects`,
  `oauthAccount`, `numStartups`, …) via the existing atomic read-modify-write +
  `.bak` backup. Distinct from the existing `claude-desktop` client (a different
  app and file). Zero new deps.

### Internal

- **Release SBOM now attaches under immutable releases** — the publish workflow
  attached the CycloneDX SBOM via a follow-up `gh release upload`, which GitHub
  rejects (HTTP 422) on repos with immutable releases enabled; v0.17.0 published
  to npm but its release ended up asset-less. The SBOM is now passed to
  `gh release create` as a positional asset, so it's sealed with the release
  atomically. This release is the first to carry it correctly.
- **Confine macOS dogfood flake closed at root** — the `--confine` tamper check
  intermittently failed closed on the pins store instead of the confine gate
  because the happy-path driver killed the relay child without awaiting exit, so
  its off-thread pins write raced the tamper step. The driver now waits for the
  child to fully exit before tampering.

## [0.17.0] - 2026-07-03

A credibility-floor release for developer/enterprise adoption: supply-chain evidence (`SECURITY.md`, a CycloneDX SBOM on every release, OpenSSF Scorecard), a macOS CI leg that verifies the `--confine` enforcement path end-to-end, published stability contracts (`docs/CONTRACTS.md`), and a fail-safe registry-delisting gate.

### Added

- **Registry-delisting gate** — `mcpm install` and `mcpm up` now **fail closed** when
  the official MCP registry marks a server `deleted` (removed/withdrawn), and
  `mcpm audit` surfaces a `deleted` **or** `deprecated` listing as an advisory
  finding. This consumes the registry's own lifecycle `status` — a free community
  revocation signal mcpm already fetched on every run but ignored. **Fail-SAFE by
  design:** only an explicit `deleted` blocks; a `deprecated` or absent/unknown
  status never blocks (registry status is an availability signal, not an integrity
  one — a new benign status the registry adds later must not brick installs). The
  registry's optional `statusMessage` is surfaced in the reason. Zero new deps.
- **CycloneDX SBOM attached to each release** — every GitHub release now carries a
  machine-readable `mcpm.cdx.json` (CycloneDX) SBOM of mcpm's own dependency tree,
  generated from the committed `pnpm-lock.yaml`. A concrete procurement/compliance
  artifact for downstreams (EU CRA, SOC 2 evidence).
- **`docs/CONTRACTS.md` — stability contracts** — documents the exit codes CI can
  depend on (notably `sync --check` → `2` on drift, `up --frozen` fail-closed → `1`),
  the versioned `mcpm.yaml` / `mcpm-lock.yaml` formats, which `--json` shapes are
  stable, and the semver-exempt `~/.mcpm` internals. No behaviour change — it names
  guarantees that already hold.

### Internal

- **Supply-chain evidence pack** — added `SECURITY.md` (vulnerability-disclosure
  policy, scope, supported-versions, and the already-shipped npm provenance story),
  `CONTRIBUTING.md`, and an [OpenSSF Scorecard](.github/workflows/scorecard.yml)
  workflow that publishes a project-health/supply-chain posture score. No behaviour
  change; these make mcpm's own security posture reviewable without asking.
- **macOS CI leg for `--confine`** — CI now runs the hermetic `pnpm dogfood:confine`
  on a `macos-latest` runner, so the flagship OS-sandbox enforcement path is
  CI-verified rather than only verified locally (the ubuntu matrix can't exercise
  Seatbelt / `sandbox-exec`).
- **CI-gate exit-code smoke tests** — added end-to-end assertions for the contract
  above (`sync --check` drift = `2` with a positive no-drift control; `up --frozen`
  missing-stack = `1`).

## [0.16.0] - 2026-07-02

An enforcement release: `mcpm guard --confine` wraps a relayed stdio server in an OS sandbox — the guard's first *containment* primitive, complementing every prior *detection* feature.

### Added

- **`mcpm guard --confine` — OS-sandbox confinement for relayed stdio servers (F1)** — the first enforcement primitive in mcpm-guard. Every prior guard feature is detection: it reasons about JSON-RPC bytes and warns/blocks. But the relay is a stdio MITM — it can inspect every frame yet cannot *contain* the child MCP server it spawns; a server that decides to read `~/.ssh` or write `~/Library/LaunchAgents` never expresses that through inspectable traffic. `--confine` wraps the child in an OS sandbox so it physically cannot read secret files or persist, regardless of the JSON-RPC it emits (watch vs contain, as complementary layers). **macOS only in v1** (Linux `bwrap` deferred), via Seatbelt / `sandbox-exec`. The **standard tier** enforces: READ allow-all *except* a secret-dir denylist (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`/`gcloud`, `~/.npmrc`, `~/.docker`, `~/.kube`, `~/.netrc`, `~/.git-credentials`, `~/.cargo/credentials`, `~/.pypirc`, `~/Library/Keychains`, browser cookie stores, the MCP client config dirs, and mcpm's own `~/.mcpm`); WRITE deny all of `$HOME` *except* caches, the per-server scratch dir, system temp, and `/dev` — one rule that blocks the whole persistence class (`~/.zshrc`, LaunchAgents, PATH-shadowing `~/bin`, git hooks); NET launcher-classified — package launchers (`npx`/`uvx`/`pip`/`docker`/…) get network `all`, everything else egress-deny `none`. The store is `~/.mcpm/guard-confine.yaml` (+ `.integrity` sidecar), the source of truth for enrollment; it **fails closed** on integrity/shape/format-version mismatch (like `pins.json`). The wrap marker gains two tokens before the `--` separator — `--confine-profile-hash <sha256>` (a content hash binding marker↔stored-profile) and `--confine-required` (replicated into the IDE config so it survives a wiped store) — both neutral to `--orig-hash`. The **spawn-time decision** (in run-inner, before the relay spawns the child) treats the store as source of truth: CONFINE when enrolled + hash matches + backend available; **FAIL CLOSED** (refuse to start, exit 1) on hash mismatch, a malformed hash, a stripped marker on a require_confine server, or a wiped store on a require_confine server; otherwise a **hybrid posture** — when no OS backend is present (Linux/CI/Windows) or the marker/profile is missing on a non-required server, it WARNs loudly and runs UNCONFINED (never silently). New `guard-events.jsonl` events (category `CONFINE`): `confine-applied`, `confine-hash-mismatch`, `confine-marker-stripped`, `confine-profile-missing`, `confine-backend-missing`, `confine-marker-malformed` — these are events, not OWASP signatures (the catalog count is unchanged at 9 entries over 8 targets). **Honest caveats:** macOS only (Linux `bwrap` and a strict tier deferred); the `sandbox-exec` path is not exercised in the ubuntu-only CI (mocked arg-vector unit tests + local darwin verification, the same gap the os-keychain shell-outs carry); confinement is opt-in (without it, enable/disable is unchanged); it does *not* stop network exfil in general (net is launcher-permissive), and does *not* protect against a same-user attacker who can rewrite both the IDE config and `~/.mcpm`. (#110)
- **`mcpm guard enable --confine` + `mcpm guard doctor-confine`** — the user-facing commands for F1. `guard enable --confine` (bare flag ⇒ "standard" tier; `--confine off` ⇒ disabled, same as omitting) enrolls every *unwrapped stdio* server it wraps into the sandbox, respecting `--server` / `--client` (url/HTTP and already-wrapped servers are not enrolled). `guard doctor-confine [--json]` is read-only: it reports OS-backend availability (platform + `/usr/bin/sandbox-exec` presence) and the enrolled servers (tier / net / require_confine), pointing to `guard status` for per-client wrap state. `guard disable` (existing) removes the wrap marker, which unconfines (a leftover profile in the store is harmless). **Deferred to a fast-follow:** the per-server `guard confine <server>` / `--off` / `--show` / `--require` / `--allow-read/-write/-net` command — per-server confine is achievable today via `enable --confine --server X` + `disable --server X`. (#111)

### Changed

- **`--orig-hash` is now verified at spawn time, not only on disable/unwrap (#108)** — the wrap marker's `--orig-hash` (the original server command binding) is checked when the relay spawns the child. **Phase 1 = WARN-once on mismatch** — it does *not* fail closed yet (a future release promotes it after zero-mismatch dogfood evidence); an *absent* hash (legacy pre-#29 wrap) is skipped, not failed. Emits an `orig-hash-mismatch` event (category `RELAY`). (#108)

### Fixed

- **`writePins` no longer leaves a 0-byte `pins.json` on an interrupted write** — the drift-store writer touched `pins.json` empty (`flag: wx`) *before* locking and writing content; a crash/kill — or a concurrent, unlocked `readPins` — in that window left an empty file, so the next launch parsed `""` → `PINS-READ-ERROR` and failed the guard **closed** (bricked until the file was manually removed). It now touches with valid serialized content, so an interrupted write stays readable (an absent sidecar is the first-run path). Pre-existing; surfaced by the new confine dogfood, with a regression test that reproduces the crash window.

### Internal

- **`store-integrity.ts` extraction (refactor, #109)** — `fileSha` / `assertNotSymlink` / `writeFileAtomic` were extracted from `pins.ts` and `policy.ts` into one shared `src/guard/store-integrity.ts` (the confine store reuses it). Behavior is identical; the symlink-refusal message now names the store (`pins` / `policy` / `confine`). (#109)
- **Hermetic macOS confine dogfood (`pnpm dogfood:confine`)** — an end-to-end pre-release gate that drives the real `enable → guard run → sandbox-exec → relay` chain in a throwaway `$HOME` (canonicalized so Seatbelt `subpath` rules match), with a **positive control**: a secret that reads fine unconfined must be denied (`EPERM`, not `ENOENT`) inside the sandbox. It also asserts stdio integrity through the relay, tamper-fails-closed via the CONFINE gate, and a `CONFINE` event is logged. macOS-only (SKIPs elsewhere); covers the enforcement path the ubuntu-only CI can't exercise. Added to the launch checklist.

## [0.15.0] - 2026-06-22

A developer-experience release: `mcpm sync --check` surfaces cross-client config drift, plus a dependency-hygiene sweep.

### Added

- **`mcpm sync --check` — cross-client config-drift dashboard (F7)** — a read-only, symmetric view across every detected client (Claude Desktop, Cursor, VS Code, Windsurf): for each server it shows which clients have it, which are missing it, and whether the clients that *do* have it agree on the server's shape. It renders a matrix (`✓` present / `·` absent / `≠` shape conflict) with per-server detail; `--json` emits the drift model; `--check` exits non-zero (`2`) when drift is found, for CI. Shape comparison covers command, args, and env/header **key sets** — it **never compares env or header values**, so secrets never reach the output. `mcpm doctor` gains a matching advisory "Cross-client" section (informational — it never changes doctor's exit code). The write/convergence path (`--union` / `--from-client`) is deferred to a follow-up.

### Fixed

- **`mcpm guard mute hidden-chars-in-metadata` now works** — the hidden-character detector emits this signature id, but it wasn't in the catalog that `mute` / `list-signatures` enumerate, so the command exited `1` even though the block message instructs running it. It's now a catalog entry (no change to detection behavior).

### Changed

- **Dependency hygiene** — bumped `hono` (→ 4.12.25), `vite` (→ 7.3.5), and added an `esbuild` override (→ 0.28.1) to clear all open Dependabot alerts. The hono advisories are in HTTP-server / serve-static / Lambda code paths that mcpm's stdio-only guard never exercises, so they were never reachable — this restores a clean alert surface. `typescript` and `@types/node` major-version bumps are now pinned out (they break the `tsc` lint gate).

## [0.14.0] - 2026-06-20

A runtime-defense release: the guard blocks tools that advertise an exfil-named schema parameter.

### Added

- **Guard blocks exfil-named tool-schema parameters at `tools/list` (F5)** — a new structural detector walks each tool's `inputSchema.properties` **keys** and blocks the server's tool list when a parameter is named with the documented context-exfiltration sigil convention (`_system_prompt_`, `_conversation_history_`, `_chain_of_thought_`, `_reasoning_trace_`, `_context_window_`, `_exfil*`) — names the model would silently auto-fill from the conversation/system prompt, leaking it with zero user interaction. This closes a structural gap: the content-regex pipeline only walks string *values*, never property *keys*. It blocks at advertisement time, before the model ever sees the tool. **Zero-FP by design:** only the underscore-*wrapped* sigil form is denied (the attacker tell); bare names a legit tool uses (`system_prompt`, `messages`, `reasoning`) and framework runtime slots (`_context_`, `_memory_`, `_thinking_`) are deliberately excluded. **Honest scope:** a tripwire for the documented convention — a renamed parameter evades it. Muteable via `mcpm guard mute exfil-param-in-schema`. The guard now ships **9 catalog entries**.

## [0.13.0] - 2026-06-20

A supply-chain release: `mcpm up --frozen` turns the integrity tripwire into a fail-closed CI gate.

### Added

- **`mcpm up --frozen` — fail-closed supply-chain integrity gate (F3)** — opt-in via the flag or `policy.frozen`. Before installing anything, `up` verifies every locked npm server's published `dist.integrity` against the lock; on **integrity drift**, an **unverifiable** record (offline / yanked / no comparable hash), a **format mismatch**, or a **suspicious missing baseline**, it **blocks the entire run** (installs nothing, exits non-zero) — `npm ci` semantics. This promotes the v0.10 WARN-only integrity tripwire (H11) to a real CI gate. **Honest by design:** a lock with no baselines yet (pre-v0.10 or offline-locked) gets a benign "run `mcpm lock` online once" refusal, *not* a poison verdict; non-npm (pypi/oci) servers get a coverage notice (no baseline mechanism exists — deferred); and a block means *npm's published record diverged from your lock*, **not** that mcpm caught the bytes `npx`/`uvx` fetch at launch.

## [0.12.1] - 2026-06-19

A correctness patch from a full-surface dogfood (102 commands, no crashes/hangs/security issues found — these are honesty fixes to command output).

### Fixed

- **`guard reset-integrity` / `guard accept-drift` no longer claim success on a no-op** — `reset-integrity` with no `pins.json` (and `accept-drift` for a server with no existing pin) printed "refreshed" / "re-pinned" / "removed" as if work happened. They now report "no pins.json found — nothing to refresh" / "no existing pin … nothing to re-pin/remove".
- **`secrets rm` of a never-stored secret now errors instead of falsely reporting removal** — it printed "Removed secret '…'" for a secret that didn't exist; it now errors ("No secret stored for '…'", exit 1), mirroring `secrets get`.
- **`search` column relabeled "Status"** — the column was headed "Trust Score" but rendered the registry lifecycle status ("active"). Search is a fast discovery list and doesn't run the scanner per result; the computed trust score lives in `mcpm why` / `info` / `install` / `audit`.
- **Shell completions dropped the removed `init developer/data/web` packs** — bash/zsh/fish completions still suggested the curated starter packs removed in v0.x.

## [0.12.0] - 2026-06-19

A supply-chain hygiene release: `mcpm up` can now flag cross-server tool-name collisions (a shadowing signal).

### Added

- **`mcpm up --check-shadowing` — cross-server tool-name-collision detection (F2, v1 slice)** — opt-in via the flag or `policy.checkShadowing`, `up` reads the guarded tool inventories (from pins) across the resolved server set and reports any tool name exposed by two or more servers — a *shadowing* signal, where a lower-trust server can intercept calls meant for a trusted one. **WARN-tier:** advisory on an interactive run; under `--ci` a collision exits non-zero. **Honest scope (stated in the output):** best-effort over **already-guarded** servers only (pins are populated when a server first runs under guard, so a never-guarded server contributes no names), and exact-name match — it is a stack-hygiene / re-audit aid, not a fresh-install control. Pure detector, zero new deps; the broader `origin-index` persistence and cross-origin text heuristic are a documented fast-follow.

## [0.11.0] - 2026-06-18

A runtime-defense feature release: the guard relay now blocks credential-phishing prompts a server tries to push at the user.

### Added

- **Guard blocks credential-phishing elicitation/sampling prompts (F6)** — two new signatures (`MCP-CREDENTIAL-PHISHING`) catch a server that prompts the user to enter a crypto-wallet seed/recovery phrase, mnemonic, or wallet private key (wallet-drainer), or a card CVV/CVC, SSN, or card/bank PIN (financial phishing). They ride the H7 (#78) server-initiated scan path, so a tripped `elicitation/create` or `sampling/createMessage` is blocked with the JSON-RPC error routed back to the server. Each pattern is **solicitation-anchored** (an imperative ask, not a passing mention) so benign conversation history and field-name prose don't false-positive, and the relay's broad H7 injection scan is left fully intact (no role-filtering). Generic api-key/password/token elicitation is deliberately **not** blocked — a server collecting its own config secret during setup is the common, legitimate case. The guard now ships **8 signatures over 8 inspected targets** (was 6).

## [0.10.1] - 2026-06-14

A documentation-accuracy patch (republished so the npm package page reflects it).

### Changed

- **README states what the guard does on every tool call (#85)** — a new "What happens on every tool call" subsection makes the runtime mechanic explicit: the relay inspects both halves of each call (request arguments out, response back) plus the tool definition against the install-time pin, and replaces a tripped frame with a synthetic JSON-RPC error so the payload never reaches the model. Server-initiated `sampling`/`elicitation` requests are inspected the same way, with the error routed back to the server.

### Fixed

- **Stale `init` / starter-packs documentation (#85)** — the README still showed `mcpm init developer` "installing 3 servers" and the removed `developer`/`data`/`web` packs; rewritten to match the shipped scaffold-an-`mcpm.yaml` behavior from #83.

## [0.10.0] - 2026-06-14

A runtime-defense hardening release: six guard upgrades that widen what the inspection relay can see and enforce, plus mcpm's first supply-chain integrity signal. The test suite grew to 1,654.

### Added

- **Guard inspects retrieved-content carriers + hidden-character detection (H1+H2, #74)** — the relay now inspects `resources/read`, `prompts/get`, `initialize.instructions`, and `structuredContent` carriers (warn-and-forward on retrieved data, block-capable on pre-invocation context), and flags zero-width / hidden Unicode *before* normalization strips the signal.
- **Fail-closed posture for un-guardable transports (H9, #76)** — URL/HTTP/SSE servers that no stdio relay can wrap are deny-by-default across install/up/guard-enable, with explicit, recorded consent (`--allow-unguarded` / `policy.allowUrlServers`).
- **Field-level schema-drift tiering + `list_changed` re-validation (H4, #77)** — a rug-pulled tool is tiered: description-only drift warns and forwards (co-scanned for injection), while schema/annotation drift blocks; `notifications/tools/list_changed` re-validates against the pin.
- **Sampling / elicitation prompt-injection scanning (H7, #78)** — server-authored `sampling/createMessage` and `elicitation/create` content is scanned for injection and blocked back to the originating server (new relay block-to-origin seam).
- **Initialize-handshake drift detection (H5, #79)** — capability escalation and server-identity changes since first observed are surfaced (warn-once, no auto-re-pin).
- **npm supply-chain integrity tripwire (H11, #81)** — `mcpm lock` captures npm's published `dist.integrity` for each pinned npm server; `mcpm up` re-checks the same version and warns on `⚠ INTEGRITY DRIFT`, catching a compromised-account republish. Advisory only — it checks the registry's published record, not the bytes `npx`/`uvx` actually run.

### Changed

- **`mcpm init` scaffolds a stack file instead of installing dead packs (#83)** — the curated `developer`/`data`/`web` packs referenced registry IDs that no longer resolve, so `init <pack>` installed nothing. `init` now writes a starter `mcpm.yaml` (won't clobber an existing one; `--force` to overwrite) and points users at `mcpm search`.
- **README leads with the runtime guard (#80)** — headline and positioning refreshed around the runtime-defense capabilities.

### Fixed

- **Stale shell completions (#82)** — bash/zsh/fish now complete the full command set (including `guard`, `secrets`, `lock`, `up`, `diff`, `why`, `export`, `outdated`, `alias`, `publish`) and the `guard`/`secrets` subcommands.
- **`mcpm_search` MCP tool annotation (#82)** — now carries `readOnlyHint`, like the other read-only tools.

## [0.9.0] - 2026-06-10

First feature off the post-v0.8.1 security + DevX roadmap (`docs/ROADMAP.md`): F4, release-age cooldown — which also fixes a live trust-score inversion bug — plus a registry-parse fix surfaced while dogfooding it. The test suite grew to 1,427.

### Added

- **Release-age cooldown + install-script-shape awareness (F4)** — `mcpm install` gains `--min-release-age <hours>` (fail-closed gate: blocks releases younger than the threshold AND releases whose publish timestamp is missing or unparseable, so a registry cannot defeat the gate by omitting `_meta`) and `--allow-fresh` (bypasses only that gate). New opt-in stack-policy keys: `policy.minReleaseAgeHours` (same fail-closed semantics for `mcpm up`) and `policy.blockInstallScripts`. New finding types: `release-cooldown` (medium — an unconditional soft penalty whenever a release is younger than the 24h cooldown, with or without the gate) and `install-script` (low launcher-shape awareness for npm `npx -y` packages; medium for declared dangerous runtime flags on every registry type). `mcpm export` now seeds `policy.minReleaseAgeHours: 24` in generated stacks.

### Changed

- **Migration: trust scores shift under F4** — every npm-launched server takes a -2 static deduction (low `install-script` launcher finding), and releases younger than 24h take an additional -5 (medium `release-cooldown`) plus lose the +3 age bonus. Lockfiles written by earlier mcpm versions carry snapshots WITHOUT these deductions, so stacks with `blockOnScoreDrop: true` will report a score drop on every npm server after upgrading — re-run `mcpm lock` once after upgrading to refresh snapshots. The block reason now includes this remediation hint.

### Fixed

- **`mcpm search` against the live registry (#71)** — `search` (and `getServer` / version lookups) threw `Invalid search response` because the schema modeled `runtimeArguments` entries as `{type, value}` with `value` required, but the official MCP registry Argument type makes `value` optional and uses named (`{type:"named", name:"--rm"}`) and positional (`{type:"positional", valueHint:"…"}`) forms — so any server declaring a named argument was rejected. The schema now accepts the real Argument shape, and every consumer (install argv render/validation, the prompt-injection scan, and the F4 dangerous-flag check) was made total over it: a dangerous flag declared via `name` (e.g. `--eval`) is still rejected, a bundled short flag (`-eCODE`) can no longer smuggle a dangerous flag past the allowlist, and a benign `valueHint` that resembles a flag is not falsely flagged.

## [0.8.1] - 2026-06-09

Registers the `mcpm_up` MCP tool and ships a focused post-ship security review (multi-agent find → adversarial-verify across the MCP server surface, secrets/crypto, and registry layers), each finding fixed in an independently-reviewed PR (#65, #66). The test suite grew to 1,302.

### Added

- **`mcpm_up` MCP tool (#64)** — `mcpm serve` now registers and exposes `mcpm_up`, so an MCP client can install a whole `mcpm.yaml` stack with trust verification (the handler existed but was never wired into the server). `mcpm serve` now exposes 9 tools.

### Security

- **MCP `.env` secret-leak lockdown (#65)** — the untrusted `mcpm_up` surface already blocked `process.env`, but still read the working-directory `.env`, so an attacker-controlled stack file could siphon the host's `.env` into an installed server config. The MCP surface now skips the `.env` entirely (`allowEnvFile:false`); the CLI is unchanged.
- **`mcpm_up` trust floor (#65)** — the batch `up` MCP path now enforces the same non-overridable `HARD_TRUST_FLOOR` the single-install tool uses (#24), so a stack file with no policy (or `minTrustScore:0`) can't slip a low-trust server past the gate.
- **Symlink path containment (#65)** — the `mcpm_up` `stackFile` check now resolves the real path (`realpath`) and rejects an in-cwd symlink pointing outside the working directory; the not-found fall-through covers `ENOENT`/`ELOOP`/`ENOTDIR` so internal filesystem errors don't leak to the caller.
- **Remote-URL hardening (#66)** — `validateRemoteUrl` allows plaintext `http` only for loopback hosts (`localhost`/`127.0.0.1`/`::1`/`*.localhost`) and requires `https` elsewhere (a plaintext remote written to an IDE config is interceptable); the `mcpm up` URL path now validates stack-file `url:` servers, which were previously written unvalidated.
- **Runtime-arg path traversal (#66)** — `validateRuntimeArgs` rejects a `..` path-traversal segment in any argument (the allowlist had permitted `.`/`/` inside values).
- **Dependency bumps (#62, #61)** — `hono` override → `^4.12.21` (clears 4 transitive Dependabot alerts: Set-Cookie injection, IPv6 IP-restriction bypass, `app.mount` mis-route, JWT any-scheme); `semver` → 7.8.2. All Dependabot alerts now clear.

### Fixed

- **`mcpm_up` failure reporting (#65)** — a whole-batch failure is surfaced via the `error` field instead of being pushed (as a message string) into the `failed` array, which is contracted to hold server names.
- **Empty-string env values (#65)** — env resolution compares against `undefined` instead of truthiness, so an explicitly-empty declared value is no longer silently dropped.
- **Honest keychain notice (#66)** — the secret-storage notice no longer claims "protects against other-user/offline access" unconditionally; it is accurate about the machine-derived-key fallback and points to `mcpm secrets migrate`.

### Docs

- Added rendered architecture diagrams (Mermaid) and a doc-drift reconciliation across README / ARCHITECTURE / GUARD / POLICY / SIGNATURES (#63).

## [0.8.0] - 2026-06-02

A deep multi-agent code review (find → adversarial-verify across the guard, store, scanner, registry, and command layers) surfaced a batch of latent bugs and hardening gaps. 33 confirmed findings were fixed across six independently-reviewed PRs (#49–#54); the test suite grew to 1,238.

### Security

- **Guard integrity strip-bypass (#54)** — `guard disable` no longer reconstructs a command from a wrap marker whose `--orig-hash` was stripped. A missing hash now fails closed instead of skipping SHA-256 verification.
- **Guard fail-closed pin/policy load (#54)** — a `readPins` failure (integrity mismatch, permission error, corrupt file) now refuses to start the relay with a stderr `PINS-READ-ERROR` instead of silently running with drift detection disabled; a `readPolicy` integrity/read error is surfaced on stderr before the safe full-enforcement fallback; `guard cleanup` refuses to prune on a tampered pins file. Pin files are now schema-validated (Zod), not bare-cast.
- **Symlink-safe writes (#52, #54)** — the `~/.mcpm` store writer (secrets, servers, aliases), the store lock file, and the pins/policy integrity sidecars now refuse symlinked targets and write exclusively (`O_EXCL`), matching the config-write hardening.
- **Store write-locking (#52)** — secret/server/alias read-modify-writes are serialized to prevent lost updates across concurrent processes; secret resolution now reads a single consistent locked snapshot, so a concurrent delete can't surface a phantom "secret not found" at launch.
- **Registry SSRF + injection (#50)** — the version path segment is URL-encoded (no path/query injection from a lock/stack version string); the IPv6 private-range check now covers all of `fe80::/10` (link-local) and `fc00::/7` (ULA), plus 6to4 `2002::/16` and CGNAT `100.64.0.0/10`; the publish response body is capped (shared 10 MB reader) to prevent OOM.
- **Scanner homoglyph evasion (#51)** — install-time secret *and* prompt-injection scans now fold cross-script (Cyrillic/Greek) confusables, closing a lookalike-character evasion, while preserving the zero-width-obfuscation detector.

### Fixed

- **Trust-score double-counting (#51)** — static and external scan findings were each deducted twice; findings are now bucketed by source, so enabling an external scanner no longer artificially lowers scores. A `webhook_url` arg with no explicit `isSecret` is now flagged, and typosquat distance is case-insensitive.
- **`mcpm up` false success (#53)** — a server whose every client write failed is no longer reported as `installed`; strict-removal no longer counts removed servers as installs (`removed` is its own status); `--strict --yes` is honored in interactive mode.
- **`mcpm update` stale config (#53)** — updates now rewrite the client-config entry for the new version (preserving existing env), not just the store record.
- **`mcpm outdated` hidden regressions (#53)** — a trust-score drop that accompanies a version bump is no longer suppressed in the human-readable output.
- **`mcpm diff` drift detection (#53)** — the long-declared `mismatch` status is now emitted (best-effort version recovery for npx/uvx/OCI), so lock-vs-config drift is visible.
- **External scanner failures (#51)** — a non-zero `mcp-scan` exit that still emitted findings is parsed instead of silently treated as clean; a genuine failure surfaces a diagnostic instead of an empty result.
- **Registry search errors (#53)** — a registry outage during setup is reported as a search failure instead of an indistinguishable "no servers found".

### Changed

- Removed dead code and a redundant per-client `resolveInstallEntry` pass in `install`/`import` (#49).

## [0.7.1] - 2026-06-02

### Security

Resolved the 12 remaining MEDIUM/LOW findings from the security review:

- **Registry SSRF / decompression-bomb** (#21) — the registry client now uses `redirect:"manual"` (rejects 3xx instead of following), caps response bodies at 10 MB, and host-validates a custom `baseUrl` (https-only, no private/loopback hosts).
- **Guard env isolation** (#20) — a wrapped server now receives only a safe baseline env (`buildSafeEnv`) plus its own declared env keys, never the relay's full `process.env` (ambient `OPENAI_API_KEY`/`AWS_*`/`GITHUB_TOKEN` are no longer forwarded).
- **Guard-disable integrity** (#29) — the wrap marker carries a SHA-256 of the original entry; `guard disable` refuses to reconstruct a command from a tampered marker.
- **Fail-safe trust gate** (#22, #24) — unknown scanner severities map to `high` (not downgraded); the publish gate blocks on exfil-shaped args and aggregated mediums; the MCP `minTrustScore` is clamped to a hard floor so `0` can't disable the no-human-in-loop install gate; `mcpm_up` no longer auto-confirms.
- **Guard detection hardening** (#30, #27) — homoglyph (Cyrillic/Greek) confusables are folded before matching; match input is bounded to prevent ReDoS/huge-input cost. FP corpus re-validated (0/24).
- **Atomic config-write safety** (#25, #26) — the `.bak` backup now preserves the raw original bytes and is written once; temp/backup writes are exclusive (`O_EXCL`) and refuse symlinked paths.
- **Import trust scan** (#23) — `mcpm import` now runs a tier-1 trust assessment on discovered servers (matching `install`).
- **Guard cleanup** (#28) — orphan-pin detection compares raw server names (was sanitized vs raw, causing prune mismatches).
- **Honest sidecar labeling** (#19) — integrity sidecars documented as integrity-not-authenticity (no behavior change).

### Upgrade notes

- After upgrading, **re-run `mcpm guard enable`** for any already-wrapped servers — the new wrap marker carries the declared-env key list, so a server wrapped by an older mcpm should be re-wrapped to keep its declared env.
- `mcpm` now refuses to read/write a **symlinked** client config (security #26); point it at a real file if you symlink configs.

## [0.7.0] - 2026-06-01

### Added

- **`mcpm why <server>`** — explain a server's trust score as an auditable breakdown: each component's earned/max points, every finding (severity + message + location), the registry-meta cap flag, and the declared env vars. Read-only; supports `--json`.

### Security

Resolved the 4 HIGH-severity findings from a security review:

- **Publish token exfiltration** — `mcpm publish --registry <host>` no longer sends the GitHub token to an arbitrary host. The URL is validated (https-only; loopback/private/IPv4-mapped-IPv6/internal hosts rejected; no embedded credentials) before the token is attached, and `fetch` uses `redirect:"manual"` so a 3xx can't carry the token onward.
- **Health-check env leak** — the env forwarded to the spawned (untrusted) server during a health check is now an allowlist, not a denylist, so custom-named secrets (`STRIPE_KEY`, …) no longer leak.
- **Guard detection bypass** — guard now scans `result.structuredContent`, the JSON-RPC `error` object, and the full tool `inputSchema` (not just `description`), closing a one-line payload-relocation evasion. FP corpus re-validated (0/24).
- **Secret-store honesty** — docs/notices no longer overclaim at-rest guarantees for the machine-keyed store; the decision is recorded in the Decisions Log.

### Changed

- Added `.github/dependabot.yml` (weekly github-actions + npm updates).

## [0.6.0] - 2026-06-01

### Added

**Encrypted secrets — `mcpm secrets`.** Store MCP server credentials AES-GCM-encrypted in `~/.mcpm` instead of as plaintext in client config files. When a server is wrapped by mcpm-guard, the credential is resolved into the server's environment at launch, so the plaintext never touches disk.

New command:

- `mcpm secrets set <server> <KEY>` — store an encrypted secret (masked prompt)
- `mcpm secrets list [server]` — list stored secret keys (values are never shown)
- `mcpm secrets get <server> <KEY> --reveal` — print a decrypted secret
- `mcpm secrets rm <server> <KEY>` — delete a stored secret

New flags:

- `mcpm install --secrets keychain` and `mcpm up --secrets keychain` — write `mcpm:keychain:…` placeholders for secret env vars instead of plaintext (opt-in; default unchanged). `up --secrets keychain` is rejected under `--ci`.

### Changed

- `mcpm guard disable` now warns when an unwrapped config still references `mcpm:keychain:` placeholders that will no longer resolve.
- Node support: dropped Node 20, added Node 26 (`engines` now `>=22`).

### Security

- Keychain ids are derived injectively (sanitized prefix + SHA-256 suffix), so two distinct server names can never share a secret namespace.
- A server's secrets are persisted in a single atomic batch — no orphaned half-written secrets if one fails.

## [0.5.0] - 2026-05-17

### Added

**mcpm-guard — runtime defense bundled into the package manager.** Wraps every installed MCP server with an inspection relay; blocks prompt-injection in tool responses, schema rug-pulls since install, and exfil-shaped tool-call arguments. The first MCP runtime defense distributed inside a package manager — adoption is one command (`mcpm guard enable`) instead of an afternoon of per-IDE config wrapping.

New commands:

- `mcpm guard enable [--client] [--server] [--dry-run]` — wrap detected client configs
- `mcpm guard disable [--client] [--server]` — unwrap (per-server scope supported)
- `mcpm guard status` — show what's wrapped + pin state per server
- `mcpm guard demo` — synthetic prompt-injection scenario; see a live block in seconds
- `mcpm guard accept-drift <server> [--tool] --new-hash <sha> --yes` — re-pin after a legitimate server upgrade
- `mcpm guard mute <signature-id> [--for <duration>]` — disable a signature with optional auto-expiry
- `mcpm guard unmute <signature-id>` — re-enable
- `mcpm guard pause [--for <duration>] [--off]` — pause all inspection for a window (debugging escape hatch)
- `mcpm guard cleanup [--yes]` — prune pin entries for uninstalled servers
- `mcpm guard list-signatures [--json]` — show the shipped OWASP MCP Top 10 signature catalog
- `mcpm guard reset-integrity [--policy] [--yes]` — regenerate the integrity sidecar after manual edits

What it catches (3 shipped signatures + 2 drift detectors):

- OWASP-MCP-1 — tool-description poisoning + schema drift since install (rug-pull defense; install-time SHA-256 pin + same-session hash cache catches mid-session mutation)
- OWASP-MCP-2 — instruction injection in tool responses (NFKC + zero-width-strip + ignore/disregard/forget/role-override variants)
- OWASP-MCP-7 — sensitive-path exfil in tool arguments (.ssh / .aws/credentials / .env / id_rsa / .gnupg / .kube/config)

Performance: p99 0.065ms small / 3.1ms large message overhead through the SDK framing helpers (78× / 8× under design budget).

Detection is deterministic regex-only — no model API calls, no secrets in CI. Detection sophistication is not the v0.5.0 wedge; distribution is. (LLM-as-judge tier deferred to v0.5.1+.)

Files written under `~/.mcpm/`: `pins.json` + `.integrity` sidecar (schema pins), `guard-policy.yaml` + `.integrity` sidecar (user overrides), `guard-events.jsonl` (append-only event log; parse with `jq`).

Threat model + full reference: `docs/GUARD.md`, `docs/SIGNATURES.md`, `docs/POLICY.md`.

### Changed

- `BaseAdapter` gains `replaceServer(configPath, name, entry)` — atomic write + `.bak` discipline, used by guard's wrap orchestration but available to any future feature.

### Security

The guard subsystem went through 6 rounds of independent security review during development; every CRITICAL and HIGH finding was fixed before commit. Highlights:

- **applyPolicy logic bug** that would have let any single mute silently downgrade `block` on unrelated critical findings — caught + fixed with dedicated regression suite
- **SDK transport misread** — original substrate proposed full Transport classes; reviewer caught they hardcode process stdio. Fixed by using the framing helpers directly
- **Integrity sidecars** added to both `pins.json` and `guard-policy.yaml` — protects against same-machine tampering (npm postinstall scripts, etc.)
- **Zod-validated YAML parse** rejects malformed policy shapes (e.g. numeric `paused_until` that would otherwise bypass all inspection)
- **DoS-resistant relay** — 64MB per-direction buffer cap, signal-listener cleanup on child exit, write-after-close handler on `child.stdin`
- **Detection evasion hardening** — NFKC + zero-width-strip + bidi-override strip + whitespace alternation (`[\s]+`) + multiple synonym variants per attack class
- **Env scoping** — pin-capture subprocesses get an allowlisted env (no leak of `OPENAI_API_KEY` / `AWS_*` / `GITHUB_TOKEN` to a server we're wrapping precisely because we don't fully trust it)

CI gates: MCPTox-derived deterministic fixture eval (25 fixtures across attack categories) + FP-rate corpus measurement (5-session seed, < 2% threshold; 0/24 false positives on the seed).

### For contributors

- `src/guard/` is the new subsystem (~3,000 lines incl. tests)
- 159 new guard tests added; full suite is 1,053 tests
- `docs/GUARD.md` for the runtime model, `docs/SIGNATURES.md` for signature authoring, `docs/POLICY.md` for the policy file format
- 30 deferred-work entries logged in `TODOS.md` (#16-30) — separate signatures repo, base64-decoding preprocessor, NFC normalize migration, LLM-judge tier, full 20-server FP corpus capture, etc.

## [0.4.0] - 2026-05-12

### Added
- `mcpm outdated` — detect version drift and trust regression across installed servers. Shows which servers have newer releases and flags servers whose trust score has degraded since install.
- Encrypted secrets store (`mcpm secrets`) — store MCP server credentials locally using AES-GCM encryption with PBKDF2 key derivation. Zero native dependencies; uses Node.js built-in `crypto.subtle`.
- `mcpm publish` — scaffold, validate, and submit MCP server packages to the registry. Includes a 5-step interactive wizard (`mcpm publish scaffold`), a pre-flight trust gate (`mcpm publish check`), and submission (`mcpm publish`).
- ServersFile schema v2 — servers file now uses `{ mcpmSchemaVersion: 2, servers: [...] }` format with backward-compatible migration from the legacy bare-array format.

### Removed
- Telemetry infrastructure removed — aligns with the documented "No telemetry. No analytics. No account required." guarantee.

## [0.3.3] - 2025-01-01

See previous releases for earlier changelog entries.
