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
| `mcpm sync --check` | all clients in sync | **`2`** on drift/conflict; `1` on error | **`2` is the drift signal** — the value CI consumes. `--json` emits the drift model |
| `mcpm audit` | scan complete | `1` when overall trust level is **risky** | advisory findings (e.g. a delisted/deprecated server) lower the score but do not by themselves flip the exit |
| `mcpm doctor` | no blocking issues | `1` | health check; the cross-client advisory section never changes the exit code |
| `mcpm install` | installed | `1` | non-zero on a policy/trust block (`--min-trust`, `--min-release-age`, a registry-**deleted** server) or any failure |
| `mcpm guard run` (relay) | child exit `0` | child's code; `1` | propagates the wrapped child's exit; **fails closed with `1`** on a confine hash mismatch, a stripped required marker, or a pins-integrity error |

Any command exits `1` on an unhandled error. New non-zero codes may be *added* for
new failure modes, but the meanings above will not be repurposed within `0.x`.

## Config & lockfile formats (stable, versioned)

- **`mcpm.yaml`** carries a top-level `version: "1"`. New optional fields may be
  added; a breaking change bumps this and ships a documented migration.
- **`mcpm-lock.yaml`** carries `lockfileVersion: 1`. The `integrity` block is
  additive/optional (older locks still parse); a breaking change bumps the number.

## `--json` output (mostly UNSTABLE for now)

`--json` is available on `search`, `install`, `list`, `info`, `audit`, `update`,
`outdated`, `diff`, `sync`, `why`, `doctor`, `verify`, `guard list-signatures`, and
`guard doctor-confine`. **Treat these shapes as unstable in `0.x`** — fields may be
added or renamed — with one exception:

- **`mcpm sync --json`** (the drift model) is **frozen** because CI consumes it
  alongside the exit-`2` contract above.

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
