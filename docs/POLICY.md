# mcpm-guard policy file reference (v0.5.0)

`~/.mcpm/guard-policy.yaml` is a user-editable YAML file that overrides the shipped signature defaults + the pause state. The relay reads it once per session (every spawn of `mcpm guard run --inner`).

## Quickest path: use the CLI

Don't hand-edit unless you have a specific reason. The supported workflows are:

```bash
mcpm guard mute owasp-mcp-2-instruction-injection-in-response --for 5m
mcpm guard unmute owasp-mcp-2-instruction-injection-in-response
mcpm guard pause --for 10m
mcpm guard pause --off
```

These commands edit `guard-policy.yaml` for you AND keep the integrity sidecar in sync.

## When you DO hand-edit

If you edit the file directly:

```yaml
signature_overrides: # optional
  - id: owasp-mcp-2-instruction-injection-in-response
    action: ignore                   # one of: ignore | warn | block | log_only
    expires_at: 2026-06-01T00:00:00Z # optional ISO 8601 — auto-removed on next session
  - id: owasp-mcp-7-path-exfil-in-args
    action: block                    # promote a default-warn to default-block
paused_until: 2026-05-17T18:00:00Z    # optional ISO 8601 — all inspection passes through until this time
```

Then **you must run `mcpm guard reset-integrity --policy --yes`**, because the integrity sidecar (`~/.mcpm/guard-policy.yaml.integrity`) still holds the SHA-256 of the previous content. The relay refuses to use the policy file if the sidecar mismatches — that's the rug-pull defense for the policy itself (so a malicious `npm postinstall` script can't silently mute signatures).

## Field reference

### `signature_overrides`

An array of per-signature overrides. Each entry:

| field | type | required | meaning |
|---|---|---|---|
| `id` | string | yes | Must match a shipped signature id (see `mcpm guard list-signatures`) |
| `action` | enum | yes | `ignore` (drop the finding entirely) / `warn` / `block` / `log_only` (keep the finding for the event log but treat as pass). `warn` and `block` are set **unconditionally** — `applyPolicy` (`src/guard/run-inner.ts`) assigns the override action outright rather than applying it as a severity-conditioned downgrade/upgrade, so `block` on a `low`-severity signature promotes it, and `warn` on a `high` one that would already warn is a no-op |
| `expires_at` | ISO 8601 string | no | Override auto-expires on or after this timestamp |

### `paused_until`

ISO 8601 string. When set + in the future, the relay short-circuits all inspection: every message passes through without scanning. The relay does NOT continuously poll — it reads `paused_until` once at session start. To pause during an active session, restart the wrapped server (e.g. quit + relaunch the IDE).

## Validation

The relay parses the YAML through a strict Zod schema. Malformed shapes (e.g. `paused_until: 99999999999999` — numeric, not ISO string) cause Zod to fall back to **empty policy** — fail toward more restrictive enforcement.

Date strings must be **full ISO 8601 UTC** (e.g. `2026-05-17T18:00:00Z`). The schema is
`z.string().datetime()` with no `offset` option, so it accepts **only** the `Z` form:

- `2026-05-17` (date-only) — **rejected**
- `2026-05-17T18:00:00+02:00` (numeric offset) — **rejected**
- `2026-05-17T18:00:00Z` — accepted

This is not a lenient coercion. Because the file is validated with a single whole-file
`safeParse` and a `.catch({})` fallback, ONE bad date string discards the **entire policy** —
every override and any `paused_until` — and the relay proceeds with an empty policy. That
fails toward more enforcement, not less, but it means a mistyped date silently un-mutes
everything you muted rather than erroring. Always write the `T...Z` form.

## Action semantics (the bug fix that mattered)

Security review Step 7 caught a critical bug where `log_only` on any one finding silently downgraded the `block` action from ALL other unmuted findings. The current implementation is:

- Each finding's contribution to the action is computed independently from its (per-finding) override
- The overall action is the MAX across all per-finding actions
- `log_only` only suppresses the finding it overrides — never others

**Decoded findings (F10 Detector-B).** A finding recovered from a base64-**decoded**
payload is WARN-only by default (the decode is heuristic — see `docs/SIGNATURES.md`).
An `action: block` override on that signature id **does** re-promote it to block for
your session — an intentional opt-in escape hatch. Enable it only for a server you've
confirmed should never emit that content encoded, since it reintroduces the decoded
false-positive risk the default clamp exists to avoid.

In practice: muting one signature can't silently disable detection on a co-occurring critical finding. Tested in `src/guard/__tests__/apply-policy.test.ts`.

## Integrity sidecar

`~/.mcpm/guard-policy.yaml.integrity` holds the SHA-256 of `guard-policy.yaml` content. Any mismatch on read raises `PolicyIntegrityError`; the relay emits a `POLICY-INTEGRITY-ERROR` warning on stderr and falls back to full enforcement for the rest of the session (fail-safe, not a per-message block); running `mcpm guard reset-integrity --policy --yes` after review re-trusts the file.

This protects against a same-machine attacker (npm postinstall script, malware) writing to the policy file silently. It does NOT protect against a same-user attacker who can ALSO compute the new sidecar — see `docs/GUARD.md` threat model.

## Concurrency

Both `pins.json` and `guard-policy.yaml` use `proper-lockfile` around writes. Two simultaneous `mcpm guard mute` invocations serialize cleanly; the second waits for the first to release.
