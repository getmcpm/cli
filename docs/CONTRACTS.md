# mcpm Stability Contracts

What you can safely automate against, and what may change without warning. mcpm is
pre-1.0 (`0.x`); this document is the promise we *do* keep in the `0.x` line, and it
tightens (never loosens) at 1.0.

## Exit codes (stable)

These are the contract CI and scripts should depend on. `0` = success, non-zero =
do-not-proceed.

| Command | `0` | non-zero | Notes |
|---|---|---|---|
| `mcpm --version` | always | — | prints `X.Y.Z` |
| `mcpm up` | applied cleanly | `1` | blocks the run when any server is **blocked** (trust floor, integrity, policy) or **failed**, regardless of `--ci` |
| `mcpm up --frozen` | lockfile verified, applied | `1` | fail-closed pre-install verify: blocks on integrity drift, an unverifiable record, a format mismatch, or a missing stack/lock |
| `mcpm verify` | lockfile integrity verified | `1` | repo-only, **client-free** CI gate: the same fail-closed integrity pass as `up --frozen` (drift / unverifiable / format mismatch / suspicious missing baseline), plus `1` when no lock file is found. `--json` emits the verify model |
| `mcpm up --ci` | applied, no prompts | `1` | non-interactive; also non-zero on shadow collisions when combined with `--check-shadowing` |
| `mcpm sync --check` | all clients in sync **and every config readable** | **`2`** on drift/conflict, on an entry that failed shape validation, or on a config that could not be read at all; `1` on error | **`2` is the drift signal** — the value CI consumes. `--json` emits the drift model. Since 0.37.0 (#59), `2` also covers "could not verify": previously an unreadable entry or config exited `0`, reporting in-sync over input never compared |
| `mcpm audit` | scan complete | `1` when overall trust level is **risky**; **`2`** when the invocation cannot be satisfied | advisory findings (e.g. a delisted/deprecated server) lower the score but do not by themselves flip the exit. `2` is scoped to four invocations mcpm refuses outright: `--min-trust` above the highest score audit could produce for *every* scanned server, `--fix --json` without `--yes`, `--min-trust` without `--fix`, and `--sarif` with `--fix`. It is **not** a general "usage errors exit 2" promise — Commander's own argument-parse failures (e.g. `--min-trust 150`) still exit `1` |
| `mcpm doctor` | no blocking issues | `1` | health check; the cross-client advisory section never changes the exit code |
| `mcpm install` | installed | `1` | non-zero on a policy/trust block (`--min-trust`, `--min-release-age`, a registry-**deleted** server) or any failure |
| `mcpm guard run` (relay) | child exit `0` | child's code; `1` | propagates the wrapped child's exit; **fails closed with `1`** on a confine hash mismatch, a stripped required marker, or a pins-integrity error |
| `mcpm guard cleanup` | ran: pruned, a dry run, or nothing to prune | `1` when it refuses | refuses when `pins.json` cannot be read or fails its integrity check, and when a pin is held by no readable client config while some detected client's config cannot be read (the servers there are unknown, so the pin cannot be proven orphaned). **Changed in 0.43.0 (#236):** every refusal exited **`0`**, so `mcpm guard cleanup --yes && <next step>` read a refusal as success |
| `mcpm info` / `mcpm why` | found | `1` when the named server is not in the registry | **Changed in 0.42.0:** both printed `Server '<name>' not found` and exited **`0`**, so `mcpm info X && <next step>` ran the next step on a server that is not there. The message and its stream (stdout) are unchanged; only the code moved, to match `install`/`remove` and the general rule below |

Any command exits `1` on an unhandled error. New non-zero codes may be *added* for
new failure modes, but the meanings above will not be repurposed within `0.x`.

## Config & lockfile formats (stable, versioned)

- **`mcpm.yaml`** carries a top-level `version: "1"`. New optional fields may be
  added; a breaking change bumps this and ships a documented migration.
- **`mcpm-lock.yaml`** carries `lockfileVersion: 1`. The `integrity` block is
  additive/optional (older locks still parse); a breaking change bumps the number.

Registry locks distinguish the MCP publication `version` from the actual
`packageVersion`. Launches use npm `identifier@version`, PyPI `identifier===version`,
or an explicit OCI tag/digest. PyPI uses strict `===` equality so a locked public
version cannot select a different local-version suffix. OCI tags are mutable; they pin a launch coordinate,
not image bytes. A digest-bearing identifier is retained even when the registry
also supplies a descriptive release version.

`up` binds the retained publication metadata to the locked package type, identifier
and package version for every selected server/client before backups, secrets or
config writes, including dry-run. Cursor cannot switch a locked package to HTTP.
Old npm locks may infer package versions from agreeing integrity/provenance
snapshots; absent evidence requires re-locking. Missing/alias package versions in
a registry listing require fixing the listing. Contradictory lock snapshots refuse
in `up --frozen` and `verify`. Package-manager downloads are independent of mcpm's
published-record checks: these are not `npm ci` enforcement of downloaded bytes.

## MCP tool-result shapes

**Since v0.46.0: `mcpm_search` and `mcpm_info` have versioned success contracts.**
Both return `schemaVersion: 1`, advertise an MCP `outputSchema`, and return the
same object in `structuredContent` and the existing JSON text block. Existing
fields retain their types: search's `trustScore` is a number; info's `trustScore`
is the full score/breakdown object. Other tools remain **unstable in `0.x`**.

Within schema version 1, the documented fields and meanings below are stable.
Consumers must accept additive fields and new finding/reason codes. A breaking
change requires a new schema version and a documented migration; stop on an
unknown version rather than assuming a pass.

| Field | Search | Info | Meaning |
|---|---|---|---|
| `schemaVersion` | top level | top level | `1` |
| `trustScore` | each `servers[]` row: number | top level: score object | Existing assessment, not a probability of safety |
| `maxPossible` / `level` | each row | inside `trustScore` | Score denominator / existing `safe`, `caution`, `risky` classification |
| `registryStatus` | each row | top level | `{status: string \| null, statusMessage: string \| null, blocksInstall: boolean}` |
| `assessment` | each row | top level | `{maxAchievableScore: number, checks: object, findings: Finding[]}` |

`registryStatus.status` is the registry's trimmed, lower-case lifecycle value;
missing/empty means `null`, and unrecognized values mean unknown status. Only
`deleted` sets `blocksInstall: true`. A false value says only that this lifecycle
gate does not block; it does **not** grant installation or override trust/policy.
The optional registry explanation is control-character-stripped and capped at
256 characters. Descriptions, explanations and finding messages are untrusted
data, never instructions or authorization.

`assessment.checks` currently reports `staticScan: "completed"` and
`healthCheck`, `externalScan`, `releaseCooldown`, `packageIntegrity`, and
`provenance` as `"not_run"`. No package is executed by search/info. This scope
explains differences from CLI `why` (which adds cooldown and provenance evidence)
and `verify` (which checks locked records); do not compare their scores as if
they performed identical checks. `findings` carries severity, type, message,
location and optional source from the single tier-1 scan.

`maxAchievableScore` is the assessment-wide pre-health-check ceiling (currently
62/80), not a predicted score for this server. npm launchers incur a low finding
and currently top out at 60/80. Unrun checks are not passed checks; `level` and
score thresholds are unchanged.

On a handler failure, the MCP result has `isError: true` and no structured
success evidence; JSON-RPC argument/protocol failures may instead reject the
call. Diagnostic text is not a stable error code. An empty successful search
is `{schemaVersion: 1, servers: []}`. Neither error nor no match is a clean scan.

**Added in 0.42.0, both additive (#92):**

- `mcpm_audit` — every per-server row now carries `error: string | null`. It is
  `null` on a row that scored, and a specific reason on a row that did not. The
  `{score: 0, maxPossible: 80, level: "risky"}` placeholder on a failed row is
  UNCHANGED, so a consumer that only reads the score keeps working; previously
  the reason existed nowhere on this surface and an agent could not tell a
  delisted server from a network blip from a genuinely risky one.
- `mcpm_up` — a new `notices: string[]`, always present (`[]` when empty),
  carrying the advisory lines `handleUp` printed, in order. These reached only
  the CLI's stdout before, which this surface does not have.

**Changed outcome in 0.43.0 (backlog #116, #234):** `mcpm_install` on a server the
registry marks `deleted` now refuses (the tool call errors; nothing is written) where
it installed it. `mcpm_setup` drops such a match before choosing a keyword's best
candidate and reports it in `skipped` with the same message instead of installing
it, so `skipped` can now hold a row for a deleted server alongside an install for
the same keyword. This aligns the MCP surface with the CLI's `mcpm install` /
`mcpm up` delisting gate; only an explicit `deleted` blocks, `deprecated` and an
absent status do not. The message names the status and carries the registry's
`statusMessage`, control-character-stripped and truncated to 256 characters.

## `--json` output (mostly UNSTABLE for now)

`--json` is available on `search`, `install`, `list`, `info`, `audit`, `update`,
`outdated`, `diff`, `sync`, `why`, `doctor`, `verify`, `guard list-signatures`,
`guard doctor-confine`, `guard inspect`, and `publish check`. **Treat these
shapes as unstable in `0.x`** — fields may be added or renamed — with these
exceptions:

- **`mcpm sync --json`** (the drift model) is **frozen** because CI consumes it
  alongside the exit-`2` contract above.
  **Changed in 0.37.0 (#59), deliberately and not additively:** `ServerDrift`
  gains `malformed` and `DriftModel` gains `unreadableClients`, but membership
  of `servers[]` and the `drifted`/`inSync` counts also change — a server whose
  entry failed shape validation used to be absent from the model entirely, and
  a client whose config could not be parsed contributed nothing. `sync --check`
  therefore now exits **2** where it previously exited **0** for a config mcpm
  could not read. The old exit `0` was the bug: the gate reported "in sync"
  over input it had never compared.

### `verify --json`, schema version 1

**Since v0.46.0: the existing `VerifyModel` has a stable versioned contract.**
No result fields, gate decisions or exit codes change. Required fields:

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | `1` | Contract version; accept additive fields, stop on unknown versions |
| `ok` | boolean | All applicable record checks and declared-stack coverage passed |
| `verified` / `checkedNpmCount` | number | Matched npm published records / npm records with baselines |
| `noBaselines` | boolean | npm entries exist but no integrity baseline can be checked |
| `blocked` | array | `{name, reason, identifier?, npmVersion?}`; reasons include `drift`, `format`, `could-not-verify`, `missing-baseline` |
| `unenforceable` | string array | Package types/URL servers with no integrity-check mechanism |
| `provenanceBlocked` | array | `{name, identifier, npmVersion, reason, detail}`; reasons include `signer-changed`, `regression`, `unverifiable` |
| `checkedProvenanceCount` | number | Previously crypto-verified baselines eligible for re-check |
| `uncovered` | string array | Declared servers absent from the lock |
| `vacuous` | boolean | Empty lock with no stack confirming it is intentional |
| `error` | optional string | Lock/stack load or operational failure; diagnostic text is not stable |

Exit `1` or `ok: false` means stop, including an operational `error` or an
unknown block reason. `ok: true` can coexist with `unenforceable` entries and
zero provenance checks: report those limits rather than claiming full coverage.
Zero checked npm records do not prove any package verified. Only crypto-verified
provenance baselines are re-checked; an empty `provenanceBlocked` array is not
proof that every publisher was verified. A matching published record does not
prove downloaded bytes or code safety. See [agent workflows](AGENT-WORKFLOW.md).

**Additive (backlog #71), on the unstable shapes:** `guard inspect --json`
findings, each `guard-events.jsonl` line's findings, and
`guard list-signatures --json` entries all gain an `owasp` field — the OWASP MCP
Top 10 pin (see `docs/owasp-mcp-mapping.md`). `mcpm audit --sarif` gains a
`run.taxonomies` entry for the same taxonomy, plus a `relationships` array
(kind `subset`, referencing the taxonomy by `name`) on any rule whose finding
type is pinned to a category. `guard list-signatures`' human output gains an
`owasp` line. Nothing existing is renamed, removed, or re-valued.

**Unreleased coverage diagnostic:** `guard inspect --json` and relay events use
the existing finding shape for `guard-unsupported-input-request` (`COVERAGE`,
`high`, `sampling_prompt`, default `warn`). It means an embedded request's method
or container/parameter shape was not covered; `warn` does not mean it was fully
inspected. Known sampling/elicitation siblings still run the detectors and may
block the enclosing result. This diagnostic is not a catalog regex signature;
finding ids remain open to additions. See [protocol coverage](GUARD.md#protocol-and-carrier-coverage).

The remaining `--json` shapes stabilize per-command as they are schema-typed and
documented; until then, pin to the exit codes, not the field names.

`mcpm doctor --report` is a **redacted, human-pasteable** text snapshot (not JSON):
OS/arch, mcpm + node versions, per-client server counts, runtime availability,
confine + secret-store backend, and issue *counts*. It carries **no server names or
arguments** by design (for pasting into public bug reports). Format is UNSTABLE.

`mcpm audit --sarif` emits **SARIF 2.1.0** — the most CI-automated structured output
mcpm produces (uploaded to GitHub code-scanning). The outer shape is governed by the
SARIF spec; there is one rule per `Finding` type. The rule catalog and severities may
still change within `0.x`. Its exit code follows `audit` (risky → `1`).

## Semver-exempt internals (may change any release)

These are implementation details, guarded by their own `format_version` fields and
in-place migrations — they are **not** part of the public contract:

- `mcpm guard run --inner …` — the internal relay argv and its wrap-marker tokens
  (`--orig-hash`, `--confine-profile-hash`, `--confine-required`).
- The `~/.mcpm/` store files — `pins.json` (`PINS_FORMAT_VERSION`),
  `guard-policy.yaml`, `guard-confine.yaml` (`CONFINE_FORMAT_VERSION`), and their
  `.integrity` sidecars.
- `~/.mcpm/guard-events.jsonl` — append-only; fields may be *added*. A stable,
  documented event schema is planned (see the adoption roadmap's SIEM item); until
  then, parse defensively (unknown fields, best-effort writes).

## Platform support

- **macOS, Linux** — supported and CI-tested (Ubuntu matrix; macOS runs the confine
  dogfood).
- **Windows** — code paths exist (config paths, DPAPI keychain) but are **not yet
  CI-verified**; treat as best-effort. `--confine` is macOS-only.
