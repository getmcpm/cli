# Changelog

All notable changes to this project will be documented in this file.

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
