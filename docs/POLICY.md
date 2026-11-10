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
paused_until: 2026-05-17T18:00:00Z    # optional ISO 8601 — sessions started before this time stay paused until restarted
```

Then **you must run `mcpm guard reset-integrity --policy --yes`**, because the integrity sidecar (`~/.mcpm/guard-policy.yaml.integrity`) still holds the SHA-256 of the previous content. The relay refuses to use the policy file if the sidecar mismatches — this detects edits that leave a stale sidecar. The sidecar is an unkeyed hash: a same-user process that can rewrite both files can bypass it.

## Field reference

### `signature_overrides`

An array of per-signature overrides. Each entry:

| field | type | required | meaning |
|---|---|---|---|
| `id` | string | yes | Must match a shipped signature id (see `mcpm guard list-signatures`) |
| `action` | enum | yes | `ignore` (drop the finding entirely) / `warn` / `block` / `log_only` (keep the finding for the event log but treat as pass). `warn` and `block` are set **unconditionally** — `applyPolicy` (`src/guard/run-inner.ts`) assigns the override action outright rather than applying it as a severity-conditioned downgrade/upgrade, so `block` on a `low`-severity signature promotes it, and `warn` on a `high` one that would already warn is a no-op |
| `expires_at` | ISO 8601 string | no | Override is removed at session startup on or after this timestamp; running sessions retain their snapshot |

### `paused_until`

ISO 8601 string. If in the future at session startup, the relay short-circuits inspection for that entire session. It does not poll or resume at the timestamp. Pause, unpause, mute and unmute changes require restarting the wrapped server; to resume a paused session, clear the pause (or wait for expiry) and then restart.

## Validation

The relay parses the YAML through a Zod schema. Malformed shapes (e.g. `paused_until: 99999999999999` — numeric, not ISO string) cause Zod to fall back to **empty policy**, applying shipped default actions.

Date strings must be **full ISO 8601 UTC** (e.g. `2026-05-17T18:00:00Z`). The schema is
`z.string().datetime()` with no `offset` option, so it accepts **only** the `Z` form:

- `2026-05-17` (date-only) — **rejected**
- `2026-05-17T18:00:00+02:00` (numeric offset) — **rejected**
- `2026-05-17T18:00:00Z` — accepted

This is not a lenient coercion. Because the file is validated as a whole file
with a `.catch({})` fallback, ONE bad date string discards the **entire policy** —
every override and any `paused_until` — and the relay proceeds with an empty policy.
All custom overrides are lost, including stricter `block` promotions as well as mutes
and pause state. A default-warning signature promoted to block returns to warn/forward;
this is not necessarily more restrictive. Always write the `T...Z` form.

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

`~/.mcpm/guard-policy.yaml.integrity` holds the SHA-256 of `guard-policy.yaml` content. Any mismatch on read raises `PolicyIntegrityError`; the relay emits a `POLICY-INTEGRITY-ERROR` warning on stderr and falls back to shipped default actions for the rest of the session (not a per-message block); running `mcpm guard reset-integrity --policy --yes` after review re-trusts the file.

The fallback discards stricter block promotions as well as permissive overrides,
just like the invalid-policy fallback above.

This detects a content change that leaves the sidecar stale. It does not
authenticate policy against a same-user attacker who can recompute both files;
see the [guard threat model](GUARD.md).

## Concurrency

`pins.json` takes one `proper-lockfile` lock around each read-modify-write, so concurrent guard sessions, `accept-drift` and `cleanup` never lose each other's pins. `guard-policy.yaml` locks only around its write, so two simultaneous `mcpm guard mute` invocations can still lose one update (known gap).
