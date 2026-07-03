# mcpm Roadmap — Developer & Enterprise Adoption

> Status: **DRAFT for review** · Baseline: **v0.16.0** · Drafted: 2026-07-03
>
> Companion to [`ROADMAP.md`](./ROADMAP.md) (the security/DevX feature roadmap, now ~80%
> delivered). That roadmap answered *"what should mcpm detect and enforce?"* — this one
> answers *"what makes developers install it and enterprises allowed to bless it?"*
>
> Produced by a grounded research-and-planning pass: two repo audits (capability map,
> enterprise-readiness checklist) + four web-research lenses (competitive landscape,
> enterprise requirements, developer-adoption levers, open-core seams) → 20 candidates →
> per-candidate adversarial critique with repo access (every effort estimate was
> re-derived against actual code) → completeness critique. All 20 candidates survived,
> but **every one except two was re-sliced** by the critique; the slices below are the
> corrected versions.

---

## Positioning verdict (what the research says)

**mcpm holds capabilities nothing else in the 2026 landscape has:** the
lockfile + `dist.integrity` + `--frozen` CI gate, TOFU schema pinning with drift
tiering, a deterministic local JSON-RPC guard relay, a no-container OS sandbox
(Seatbelt), and the cross-client drift dashboard. Competitors validate the space —
Snyk acquired Invariant's mcp-scan, Stacklok sells ToolHive Enterprise, ~$40M of
pure-play MCP-security seed funding, postmark-mcp / CVE-2025-6514 / 40+ MCP CVEs
in early 2026 — but they cluster in two places mcpm is not: **hosted gateways for
remote MCP** (Kong, Lasso, Pomerium, AWS AgentCore) and **cloud-connected scanners**
(mcp-scan ships tool descriptions to Snyk's API).

**The defensible position:** the neutral, deterministic, local-first
**endpoint auditor/enforcer** — policy comes *in* via MDM/git (no backend),
enforcement happens *on-device*, evidence goes *out* through the org's existing log
pipeline. Client-native enterprise controls (Claude Code `managed-mcp.json`, Cursor
admin, VS Code org policy) are real but fragmented per-client — **no cross-client
auditor exists**. That is mcpm's enterprise wedge.

**Open-core guardrail (from the Semgrep/HashiCorp/Tailscale evidence):** keep 100%
of agent-side capability OSS forever — never gate detection quality, never
relicense signatures, no license keys / phone-home in the CLI. What a future
commercial layer may sell is the *plane* (fleet aggregation, hosted dashboards,
SSO on a console). The OSS CLI's job now is to ship the **seams**: stable schemas,
exit-code contracts, `--json` everywhere, documented log format. Bring-your-own
plane must genuinely work.

**The three biggest risks are not features:**
1. **Awareness** — the repo has ~2 stars, no website, no launch content, and is
   absent from every MCP-security roundup. The best feature roadmap loses to this.
2. **Bus factor = 1** — enterprises fail vendors on this in review regardless of
   features. Cheap mitigations (Scorecard, governance docs, disclosure policy) are
   folded into Wave 0.
3. **Vendor absorption + remote-MCP drift** — Cursor ships sandboxing, Claude Code
   ships MCP management; guard/confine cover stdio while 2026 momentum is
   streamable-HTTP. Waves 3's remote-conformance work and the cross-client auditor
   are the hedge: be the *neutral multi-client layer* vendors won't build.

Also flagged: the Python **mcpm.sh** (Path Integral) is an established same-named
MCP manager (zero security features, but it squats PyPI + the name). Verify naming
strategy (brew formula name, SEO, "getmcpm" branding) **before** the distribution
push in Wave 1.

---

## Prioritized plan

Scoring inputs: adoption impact (1–5, for the stated track), differentiation vs the
competitive landscape (1–5), critic-corrected effort. Sequenced into waves; each item
names the **critique-corrected first slice**.

| Wave | ID | Item | Track | Effort* | Imp | Diff |
|---|---|---|---|---|---|---|
| 0 | E3 | Supply-chain evidence pack for mcpm itself | ent | S | 4 | 1 |
| 0 | B1a | macOS CI leg + `dogfood:confine` in CI | both | S | 3 | 2 |
| 0 | E11 | CONTRACTS.md — frozen exit-code contract | ent | S | 3 | 3 |
| 0 | E9a | Registry `status` delisting gate (free revocation slice) | ent | S | 3 | 4 |
| 1 | D1 | **Claude Code adapter** (user-global slice) | dev | S | 5 | 3 |
| 1 | D4a | Gemini CLI adapter | dev | S | 4 | 2 |
| 1 | D7 | `doctor --json` / `--report` + issue forms | dev | S | 3 | 2 |
| 1 | D2 | `mcpm verify` (repo-only) + official GitHub Action | dev | M | 4 | 4 |
| 1 | D3 | `mcpm audit --sarif` | dev | S | 3 | 4 |
| 1 | D6 | mise registry entry + Homebrew tap | dev | S | 2 | 1 |
| 2 | E5 | Private registry mirror + corporate proxy | ent | S | 4 | 2 |
| 2 | E2 | SIEM-ready guard event log (slice 1) | ent | S–M | 4 | 4 |
| 2 | E4 | `mcpm sbom` — CycloneDX from the lockfile | ent | S | 3 | 5 |
| 2 | E6 | `mcpm report --json` fleet posture snapshot | ent | S–M | 4 | 4 |
| 2 | E10a | `mcpm policy check` — cross-client compliance auditor | ent | S–M | 4 | 5 |
| 3 | E1 | Managed org policy layer (MDM/git, non-overridable) | ent | **L** | 5 | 5 |
| 3 | B2 | Linux confine backend (bubblewrap) | both | L | 3 | 5 |
| 3 | B3 | F8: Sigstore provenance verify + signer-identity drift | ent | L | 3 | 3 |
| 3 | E7 | Remote-MCP OAuth metadata conformance (`--probe-remote`) | ent | S–M | 3 | 4 |
| 3 | E9b | Signed org denylist feeds (`policy.denylistFeeds`) | ent | M | 3 | 4 |
| 3 | D5 | "State of MCP supply-chain hygiene" report (launch vehicle) | dev | M | 4 | 3 |
| later | D4b | Codex CLI adapter (TOML — real M, needs BaseAdapter format hooks) | dev | M | 3 | 2 |
| later | B1b | Windows CI leg (test-harness `HOME` refactor first) | both | L | 3 | 3 |
| later | E10b | `policy compile` emitters (managed-mcp.json / Cursor / VS Code) | ent | M | 3 | 5 |
| later | D6b | devcontainer feature (sequenced behind project-scope adapter) | dev | M | 2 | 1 |

\* Efforts are the **critic-corrected** numbers, not the candidates' original claims.

---

## Wave 0 — credibility floor (✅ SHIPPED in v0.17.0)

> **Status (2026-07-03):** all four Wave-0 items (E3, B1a, E11, E9a) shipped in
> **v0.17.0**. Wave-1 **D1** (Claude Code adapter) is merged to `main` and ships on
> the next tag. Descriptions below are kept as the original plan of record.


Cheap, and every enterprise conversation dies without them.

- **E3 · Evidence pack.** `SECURITY.md` at repo root (expand README §Security: scope,
  supported-versions/EOL table, the already-promised 48h SLA) so GitHub's Security tab,
  OpenSSF Scorecard, and vendor scanners find it. One `publish.yml` step generating a
  CycloneDX SBOM of mcpm attached to the GitHub release (`npm sbom` or `cyclonedx`
  devDep). A short "Supply chain" doc section stating what *already exists*:
  `pnpm publish --provenance` = npm Sigstore attestation, verifiable via
  `npm audit signatures`. **Cut** (per critique): `gh attest` (duplicates npm
  provenance), separate SUPPORT.md. Fold bus-factor mitigations here: Scorecard
  action, CONTRIBUTING.md.
- **B1a · macOS CI leg.** Add `macos-latest` (one Node version) to `ci.yml` and run
  `pnpm dogfood:confine`. Closes the exact "flagship verified locally, untested in CI"
  gap `ROADMAP.md` names twice. One workflow edit, zero code. (Windows = B1b, **L**,
  later — the `process.env.HOME` test-redirection pattern silently doesn't work on
  win32; that's a harness refactor, not a matrix entry.)
- **E11 · CONTRACTS.md.** Freeze only what's real: the exit-code table for CI-gate
  surfaces (`up --frozen/--ci/--check-shadowing`, `sync --check` = exit 2 on drift,
  `audit`, `doctor`, guard fail-closed spawn = 1); declare `mcpm.yaml` v1 +
  `lockfileVersion` 1 stable with a breaking-change policy; the semver-exempt list;
  an explicit line declaring `--json` shapes UNSTABLE except `sync --json` (the one
  CI consumes — hand-freeze that). **Cut:** generated JSON schemas (zero `--json`
  surfaces are Zod-typed today; 13 hand-written schemas would drift immediately).
  Add hermetic exit-code rows to `cli-smoke.test.ts`.
- **E9a · Registry delisting gate.** The official registry's `status` field
  (deleted/deprecated) is already parsed at `src/registry/schemas.ts:87` and ignored
  everywhere. BLOCK on install/up (WARN in audit) when a server is delisted. A
  community revocation feed mcpm already fetches on every run — ~S.

## Wave 1 — developer reach (the #1 lever)

The completeness critic's verdict: the candidate set over-indexed enterprise for a
2-star product; **D1 is the single highest-leverage item in the entire set.**

- **D1 · Claude Code adapter — user-global slice only. ✅ SHIPPED** (merged to `main`,
  ships next tag; see CHANGELOG `[Unreleased]`). Added `claude-code` as a plain
  5th `CLIENT_ID` targeting `~/.claude.json` (rootKey `mcpServers`). It fits the
  existing one-path-per-client contract, so detector, `sync --check`, `guard enable`,
  `list`, `install`, `import` all work day one. Include the TODOS #23 Zod-validation
  fix (extra important — `~/.claude.json` carries lots of non-MCP state), and
  *document* the concurrent-writer race with Claude Code's own rewrites. **Explicitly
  out (not "deferred"):** project `.mcp.json` scope — it breaks the clientId→path
  contract across six consumers, and guard wrapping would commit machine-specific
  markers into a shared git file. Project scope needs its own design (see D6b/E10b).
  Claude Code is the fastest-growing dev product ever; mcp-scan already covers it.
- **D4a · Gemini CLI adapter. ✅ SHIPPED** (on `main`, ships next tag; see CHANGELOG
  `[Unreleased]`). Standalone S as predicted: `~/.gemini/settings.json`, same
  `mcpServers` rootKey, a rootKey-only `BaseAdapter` subclass (6th first-class
  client). User-global scope only; per-project `.gemini/settings.json` out of scope.
  URL caveat: Gemini reads `url`=SSE / `httpUrl`=HTTP, mcpm writes `url`. (Codex =
  D4b, real M — TOML needs BaseAdapter read/write format hooks + a `smol-toml`-class
  dep decision; don't blend the estimates.)
- **D7 · doctor --json / --report. ✅ SHIPPED** (on `main`, ships next tag; see
  CHANGELOG `[Unreleased]`). `doctorHandler` now builds a structured `DoctorModel`
  (the first of the four structured-output mappers to land — carries `schemaVersion`
  as the shared convention) then renders; `--json` emits it; `handleDoctor` reuses the
  model, fixing the hardcoded `issues: []`. `--report` = redacted snapshot (OS/arch,
  mcpm+node versions, per-client server **counts**, runtime availability, confine +
  secret-store backend, issue counts) — **no server names/args**. `bug.yml` requires
  a pasted report. Note: doctor issues stayed a doctor-specific typed list (not forced
  into the audit `Finding` shape — different domain); the shared "one model" is the
  `schemaVersion` + JSON convention, not a monolithic type.  Original plan:
  Refactor `doctorHandler` to build a structured
  `DoctorModel` then render; `--json` emits it — and reuse the model in
  `src/server/handlers.ts handleDoctor`, fixing the latent bug where the MCP-server
  doctor hardcodes `issues: []`. `--report` = redacted snapshot from shipped surfaces
  only (OS/arch, versions, detected clients, guard/confine status, secret-store
  backend — no server names/args). `.github/ISSUE_TEMPLATE/bug.yml` requires a pasted
  report — the telemetry-free friction channel (flutter/brew/gh norm). **Cut:**
  PATH-origin classification (that's F9-PR2; don't smuggle it in).
- **D2 · `mcpm verify` + GitHub Action. ✅ SHIPPED** (on `main`, ships next tag; see
  CHANGELOG `[Unreleased]`). Confirmed the critique: `classifyIntegrity` + a new pure
  `frozenVerdict` were extracted from `up.ts` into `src/stack/frozen-verify.ts`, and
  `mcpm verify [--json]` runs that pass **client-free** (no client detection, no
  `~/.mcpm`, no writes) with the same BLOCK semantics + exit codes as `up --frozen`
  (exit 1 on drift / unverifiable / format mismatch / mixed missing baseline; benign
  refuse on a lock-wide no-baseline; pypi/oci/url reported as unenforceable). Composite
  Action at `.github/actions/mcpm-verify` (step summary from `--json`, static badge,
  pre-commit snippet). `up`'s block matrix is byte-identical (13 frozen tests
  unchanged). **v1 scope = npm `dist.integrity`**; stack-vs-lock staleness deferred.
  Original plan: The critique killed the "thin wrapper"
  framing: none of the existing commands run on a hosted runner (`up` hard-fails on
  zero detected clients; `sync --check`/`audit` are vacuously green there). First a
  CLI PR: **`mcpm verify [--json]`** — repo-only, client-free; loads
  `mcpm.yaml` + `mcpm-lock.yaml` and runs the extracted `--frozen` verify pass with
  the same BLOCK semantics/exit codes. Then a composite Action wrapping *only*
  `mcpm verify` (SHA-pinned, step summary from `--json`, static badge). Pre-commit
  rides the same verb. **Naming is deliberate:** B3 later *extends* `mcpm verify`
  with provenance — one verb, integrity now, provenance later.
- **D3 · `mcpm audit --sarif`. ✅ SHIPPED** (on `main`, ships next tag; see CHANGELOG
  `[Unreleased]`). Pure `src/output/sarif.ts` mapper beside the `--json` branch;
  rules from the real `Finding.type`s (**8**, not 7 — the union grew; the rule catalog
  is a TS-exhaustive `Record` so a new type forces an update); artifactLocation =
  `mcpm.yaml` (file-level, no fake line numbers) + a `logicalLocation` for the server
  name + a stable `partialFingerprints`. Report-only, exit matches `audit` (risky→1).
  GitHub code-scanning upload documented in the README. **Cut:** guard-events SARIF.
- **D6 · Distribution (trimmed).** mise registry PR (near-zero — npm backend alias) +
  `getmcpm/homebrew-mcpm` tap + README install matrix. Framed honestly as
  convenience, not enterprise unblock. **Cut:** devcontainer feature until a
  project-scope adapter exists (inside a container there are no host GUI configs to
  manage). **Blocker:** resolve the mcpm.sh name collision first.

**Awareness (non-code, runs alongside Wave 1):** submit to the MCP-security
roundups/awesome-lists that currently omit mcpm; a comparison page (mcpm vs
mcp-scan vs ToolHive vs Docker MCP — the capability table from this research); a
launch post timed with D1 ("guard + lockfile now cover Claude Code"). D5 (Wave 3)
is the big content vehicle.

## Wave 2 — enterprise unblockers (self-serve, still zero backend)

- **E5 · Private registry + proxy (KEEP as-is, S).** `MCPM_REGISTRY_URL` routed
  through a factory replacing the **11** bare `new RegistryClient()` call sites *plus*
  the 12th hardcoded registry in `publish/submit.ts:32`; `MCPM_NPM_REGISTRY` for
  `npm-integrity.ts` with the same https/no-creds validation;
  `MCPM_ALLOW_PRIVATE_REGISTRY` opt-in (visible notice) for RFC1918 mirrors;
  `AIRGAP.md` stating plainly that `HTTPS_PROXY` via `NODE_USE_ENV_PROXY` needs
  Node 24+ while engines is >=22; verify offline `--frozen` fail-closed with a real
  network-off dogfood before documenting it. The cheapest hard-blocker removal on
  the enterprise track.
- **E2 · SIEM-ready event log, slice 1.** `schema_version` + user + hostname +
  tool/method name in `buildEventLogEntry` (small `GuardEvent` addition threaded at
  `relay.ts` where the message is in hand); size-based rename rotation at the single
  `appendEvent` choke point; `docs/EVENTS.md` as a semver'd schema contract with
  Splunk universal-forwarder + Sentinel AMA file-tail recipes — both ingest JSONL
  natively, so slice 1 needs **no exporter** to be SIEM-ready. Slice 2 (on demand):
  `guard events --format ocsf` with proper params-hash plumbing. **Drop CEF**
  outright. Context: the NSA's 2026-05-20 MCP CSI recommends logging every tool
  invocation with identities and hashes — guard is close to a reference
  implementation; this closes the identity/rotation gap.
- **E4 · `mcpm sbom`.** Lockfile-only CycloneDX 1.6 to stdout/`--output`: purl mapping
  for all three recorded registryTypes (`pkg:npm`/`pkg:pypi`/`pkg:docker`), SRI→hex
  when `npmIntegrity` present, URL servers as CycloneDX `services`, trust snapshot as
  properties. **Deterministic by default** (omit serialNumber/timestamp so CI can
  diff). No lockfile → error pointing at `mcpm lock`. Zero deps. EU CRA machine-
  readable SBOM obligations land 2027-12-11; AI Act Annex III logging applies
  2026-08-02 — this plus E2 is the compliance-evidence story.
- **E6 · `mcpm report --json`.** A pure JOIN of existing structured models per
  client × server: entry, pins, trust (extract `handleAudit`'s scan loop to return
  `AuditResult[]`), drift (`buildDriftModel`), guard status (`StatusReport` — add the
  missing `guard status --json`), confine store — wrapped in
  `{schema_version, hostname, user, timestamp}`. Degrades gracefully offline
  (trust: null + reason). This is the ISO 42001 / NIST AI RMF "agent inventory"
  artifact — generated locally, aggregated by *their* pipeline (fleet aggregation
  stays NEEDS-BACKEND; don't build it). **Cut from this PR:** `doctor --json`
  (lands in D7), `up --json`, org-policy compliance field (null until E1).
- **E10a · `mcpm policy check` — the auditor before the compiler.** A standalone
  ~4-field policy YAML (allow/deny server-name globs, `requireGuard`, `minTrustScore`)
  — **designed as a strict subset of E1's eventual schema** so no second format war.
  Audits all supported clients by reusing `collectClientStates`/`drift.ts`; sync-style
  table + `--json` + the 0/2/1 exit contract for MDM/CI. This is the "provable laptop
  compliance" artifact — the uncontested whitespace (client-native controls are
  per-client; nobody audits across clients). Compiler emitters = E10b, later, gated
  on client schemas being version-pinned.

## Wave 3 — flagship bets (v1.0-shaped)

- **E1 · Managed org policy layer (L — critic re-costed from M).** System-path
  loading (`/Library/Application Support/mcpm/managed-policy.yaml`,
  `/etc/mcpm/policy.yaml`, Windows equivalent) then `MCPM_ORG_POLICY`; strict Zod,
  `apiVersion: 1`; fields = existing `PolicySchema` + allow/deny globs +
  `requireGuard`. **Pure max-restriction merge** (org can only tighten). Enforce at
  ALL FOUR mcpm-mediated entry points — `up`, `install` (which currently has zero
  policy plumbing — the expensive part), `guard disable` (refuse under
  `requireGuard`), and the `mcpm serve` handlers (the one in-tool bypass). Honest
  posture doc: mcpm is not an OS MDM — a user can still hand-edit client JSON;
  that's what E10a audits. Mirrors the Claude Code managed-settings precedent
  (Jamf/Intune-distributed, non-overridable) — the exact rollout template
  enterprises already know.
- **B2 · Linux confine backend (KEEP, L).** Not "Linux support" — it completes the
  single loudest differentiator (Cursor ships Linux sandboxing; macOS-only is half a
  headline) and it's the first confine backend **ubuntu CI can enforce-test on every
  PR**. Dispatch seam is `apply.ts` (`decide.ts` unchanged — it already takes
  `backendAvailable` as input). bwrap only, standard tier only; **cut** the
  Landlock/seccomp fallback or L becomes XL. `doctor-confine` must detect bwrap AND
  unprivileged-userns availability (Ubuntu 24.04 AppArmor restriction) — the Linux
  no-backend rate will dwarf macOS's.
- **B3 · F8 Sigstore provenance + signer-identity drift (L).** Ship the ROADMAP F8 v1
  slice as specified there: npm-only offline verify (`@sigstore/verify` +
  `@sigstore/bundle` against a vendored `trusted_root.json` — flagged as a small
  pure-JS dep *tree*); optional provenance block in the existing lock snapshot
  (mirror the H11 optional-integrity pattern, no lockfile version bump); `up` WARNs
  on `provenance_drift`, report-only; `why` Provenance section. Extends the
  `mcpm verify` verb from D2. **Delete the dep-free fallback mode** — unverified
  cert-string checks are fail-open theater.
- **E7 · Remote-MCP OAuth metadata conformance (trimmed to S–M).** Not "OAuth
  conformance" — a *metadata-presence* check under an explicit
  `mcpm audit --probe-remote` flag (visible "contacting <url>" notice): expect
  401 + `WWW-Authenticate resource_metadata` (RFC 9728), Zod-validate the PRM doc,
  report whether PKCE S256 / RFC 9207 `iss` are advertised. Findings ride the
  existing audit table. Label RFC 8707 enforcement / token-passthrough as
  unverifiable-without-a-token; defer. This is also the hedge against the
  stdio→streamable-HTTP shift — and note the 2026 spec RC deprecates
  Roots/Sampling/Logging (12-month window), which touches guard's sampling-scan
  surface: track it.
- **E9b · Signed org denylist feeds.** `policy.denylistFeeds` in mcpm.yaml: HTTPS/git
  URL + **required ed25519 pubkey** (Node `crypto.verify`, zero deps), TTL cache,
  enforced inside the existing `checkTrustPolicy` path. Drop the hash-pinned-content
  option (freezes the feed — self-defeating for revocation).
- **D5 · "State of MCP supply-chain hygiene" (the launch vehicle).** Full-registry
  **aggregate-only** report: % verified publishers, release-age distribution,
  % script-running launch shapes, exfil-named-param counts — with the committed raw
  registry snapshot for reproducibility and "reproduce any row with
  `npx @getmcpm/cli why <server>`" as the CTA. **Cut from v1:** per-server
  naming-and-shaming rows (the FP landmine that torches credibility on launch day) —
  publish those only after manual triage, as a follow-up. Repeat quarterly (gitleaks/
  Socket grew exactly this way).

---

## Cross-cutting decisions (from the completeness critique)

1. **One finding/event model.** D3 (SARIF), D7 (DoctorModel), E2 (events), E6
   (report) are four structured-output mappers — define one internal model + mappers,
   not four ad-hoc shapes. Do this in the first of the four to land.
2. **One `verify` verb.** D2 ships `mcpm verify` = lockfile-integrity; B3 extends the
   same verb with provenance. Never two meanings.
3. **E10a's policy YAML ⊂ E1's schema.** Locked at design time, or we ship a second
   policy format and a migration tax.
4. **Inventory blind spots stated honestly.** Claude Desktop `.mcpb` extensions,
   VS Code profile/extension-contributed servers, and project-scope configs
   (`.mcp.json`, `.cursor/mcp.json`) are invisible to E6/E10a today. Each report
   carries an explicit coverage statement until a detect-only pass exists.
5. **Claude Code plugin packaging** (slash-command plugin wrapping
   `audit`/`sync --check`/`guard`) is an uncovered distribution channel worth a spike
   after D1 — distribution *inside* the fastest-growing client.
6. **Sequencing of contracts:** E11's exit-code table ships in Wave 0, but any JSON
   freeze waits for D7/E6/E2 surfaces to land.

## What this explicitly does NOT change

The security-feature pipeline from `ROADMAP.md` continues alongside: **F10 response
DLP** stays the next detector (fits Wave 2 timing), **F9** merges into D7 + its own
PR2/PR3 slices, **F8 = B3** above. Hard constraints hold: local-first, no hosted
backend, deterministic default path, no tracking, ~zero new deps (exceptions flagged
inline: `@sigstore/*` for B3, possible `smol-toml` for D4b — each an explicit
decision, not a drift).

## Suggested release mapping

- **v0.16** — F1 `guard --confine` (shipped; predates this roadmap).
- **v0.17** — ✅ Wave 0 (E3 + B1a + E11 + E9a) — the credibility floor.
- **v0.18** — D1 (Claude Code adapter, already merged) + D4a + D7 + the CI story
  (D2 verify/Action, D3 SARIF) + D6 — the Claude Code headline + developer reach.
- **v0.19** — E5 + E2 + E4 + E6 + E10a (the enterprise self-serve evidence kit).
- **v1.0** — E1 + B2 + B3 (managed policy, Linux confine, provenance — the
  "enterprise-ready" claim becomes true, and 1.0 signals the semver discipline
  enterprises ask for) + D5 as the launch content.
- **post-1.0** — E7, E9b, E10b, D4b, B1b, devcontainer, Claude Code plugin spike.
