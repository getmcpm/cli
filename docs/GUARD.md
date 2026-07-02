# mcpm-guard — Runtime defense reference (v0.5.0)

Long-form reference for `mcpm guard`. For the 5-minute getting-started path, see the README's "Runtime defense" section.

---

## Mental model

A wrapped MCP server's stdio looks like this:

```
   IDE (Claude Desktop / Cursor / ...)
            │  JSON-RPC over stdio
            ▼
   ┌──────────────────────────┐
   │ mcpm guard run --inner   │  ← the relay (spawned by the wrapped config)
   │  • inspect parent → child │
   │  • inspect child → parent │
   │  • compare against pins   │
   │  • block, warn, or pass   │
   └────────────┬─────────────┘
                │  spawned child process
                ▼
   the real MCP server (e.g. servers-filesystem)
```

`mcpm guard enable` rewrites your detected client configs (Claude Desktop / Cursor / VS Code / Windsurf) so each server's `command` becomes the relay, with the original command/args sandwiched after a `--` separator. `mcpm guard disable` restores the original entries.

Detection is layered:

| Layer | Triggered by | Scope |
|---|---|---|
| **Pattern engine** | Every message | NFKC-normalized regex against tool descriptions / responses / arguments / annotations |
| **Schema pinning** | `tools/list` responses | SHA-256 hash of {description, schema, annotations} vs the pin captured at install |
| **Same-session drift** | 2nd+ `tools/list` in one session | Catches mid-session rug-pull attempts before the pin write commits |
| **Field-level drift tiering (H4)** | a drifted `tools/list` tool | Per-field hashes split a **description-only** change (cosmetic → warn, forwarded — the parallel description pattern scan still blocks regex-detectable injection) from a **schema / annotations** change (security → block); a pre-H4 pin with no field hashes stays a coarse block. An announced `notifications/tools/list_changed` arms a single-shot re-validation against the pin. `accept-drift` drops the field hashes (reverts that tool to coarse blocking) until the next first-session capture re-derives them. |
| **Policy overrides** | Every message | `~/.mcpm/guard-policy.yaml` signature overrides (ignore / warn / block / log_only) and global pause state (paused_until) |

### Full message flow

The relay inspects each direction independently — a request (parent → child) and the matching response (child → parent) each run the full pattern + pin + policy pipeline before anything is forwarded:

```mermaid
sequenceDiagram
participant IDE as IDE<br/>(Claude Desktop)
participant Relay as mcpm guard<br/>run --inner
participant Child as Real MCP<br/>Server
participant PinStore as ~/.mcpm/pins.json
participant PolicyFile as ~/.mcpm/<br/>guard-policy.yaml
participant EventLog as ~/.mcpm/<br/>guard-events.jsonl

Note over IDE,EventLog: ENABLE PHASE (mcpm guard enable)<br/>Rewrites IDE config: real-server-cmd → mcpm guard run --inner -- real-server-cmd

Note over IDE,EventLog: RUNTIME PHASE - JSON-RPC Inspection<br/>Load policy (muted signatures, paused_until)

IDE->>Relay: JSON-RPC request<br/>(method: tool call)

rect rgb(200, 150, 150)
Note over Relay: PARENT→CHILD INSPECT
Relay->>Relay: inspectMessage()<br/>Pattern engine<br/>(OWASP-MCP Top 10)
Relay->>Relay: Check signatures vs<br/>tool_call_args<br/>(e.g., owasp-mcp-7-path-exfil)
Relay->>Relay: applyPolicy()<br/>signature_overrides
end

alt BLOCK or WARN
Relay->>EventLog: append event
Relay->>IDE: JSON-RPC error<br/>(code: -32099)
else PASS
Relay->>Child: forward request
end

Child->>Relay: JSON-RPC response<br/>(e.g., tools/list)

rect rgb(150, 200, 150)
Note over Relay: CHILD→PARENT INSPECT
Relay->>Relay: inspectMessage()<br/>Pattern engine<br/>(OWASP-MCP Top 10)

alt hasToolsList()?
Relay->>PinStore: Load pins
Relay->>Relay: inspectForDriftSync():<br/>Hash live schema<br/>vs pinned hash
Relay->>Relay: SECURITY F3:<br/>Check sessionFirstHashes<br/>for same-session drift
alt Schema mismatch or in-session drift
Relay->>EventLog: append finding<br/>(signature: schema-drift)
Relay->>IDE: JSON-RPC error<br/>(block)
else Schema matches
Relay->>Relay: Off-thread:<br/>Async pin write +<br/>snapshot refresh
end
end
end

Relay->>Relay: applyPolicy()<br/>on pattern + drift findings
Relay->>Relay: mergeInspect()<br/>Highest severity wins

alt BLOCK
Relay->>EventLog: append event
Relay->>IDE: JSON-RPC error<br/>(code: -32099,<br/>remediation)
else WARN (policy: log_only)
Relay->>EventLog: append event
Relay->>IDE: forward response<br/>(event logged)
else PASS
Relay->>IDE: forward response
end

Note over IDE,EventLog: Event log entry (if findings):<br/>{ts, server_name, direction,<br/>action, findings:[{signature_id,<br/>category, severity, target,<br/>matched_text_excerpt, remediation}]}
```

---

## All commands

### `mcpm guard`
Bare invocation. Shows status if any servers are wrapped, otherwise prints help.

### `mcpm guard enable [--client <id>] [--server <name>] [--dry-run]`
Wraps detected client configs. Use `--client` to scope to one (`claude-desktop` / `cursor` / `vscode` / `windsurf`); `--server` to scope to a single server name. `--dry-run` prints the planned changes without writing.

The wrap transformation in JSON:
```
{ "command": "<orig>", "args": [...], "env": {...} }
  ↓
{ "command": "node", "args": ["<abs path to mcpm>/dist/index.js", "guard", "run", "--inner", "--server-name", "<name>", "--declared-env", "<csv of env key names>", "--orig-hash", "<sha256 hash>", "--", "<orig>", ...], "env": {...} }
```

A pre-batch `.bak` snapshot is written per touched client (`<config>.guard-enable.bak`) so the whole operation is recoverable even if a single per-server write fails mid-batch.

The `--orig-hash` token is now verified at spawn time too (previously it was checked only on `disable`/unwrap). This is **Phase 1: warn-once** on mismatch — it does *not* fail closed yet (a future release promotes it after zero-mismatch dogfood evidence); an absent hash (a legacy pre-`--orig-hash` wrap) is skipped, not failed.

### `mcpm guard disable [--client <id>] [--server <name>]`
Reverses the wrap by parsing the wrap marker out of the args and reconstructing the original entry. Falls back to the `.bak` if the wrap pattern is malformed (e.g. user hand-edited the config since enable).

### `mcpm guard enable [...] --confine [off]`
Opt-in OS sandbox for the servers being wrapped (macOS only, unreleased — next minor). See **OS confinement (`--confine`)** below. The bare flag enrolls every unwrapped stdio server it wraps at the "standard" tier; `--confine off` is the same as omitting the flag (no enrollment). Respects `--client` / `--server`.

### `mcpm guard doctor-confine [--json]`
Read-only. Reports OS-backend availability (platform + presence of `/usr/bin/sandbox-exec`) and the enrolled servers (tier / net / require_confine). Points to `mcpm guard status` for per-client wrap state. See **OS confinement (`--confine`)** below.

### `mcpm guard status`
Prints what's wrapped and the pin state per server (unprotected / first-session-pin pending / fully protected).

### `mcpm guard demo`
Runs the in-process `prompt-injection` scenario. The output is byte-identical to what the production relay emits, so screenshotting the demo accurately represents what a real block looks like. Additional scenarios (`path-exfil`, `rug-pull`) ship in v0.5.0.1.

### `mcpm guard accept-drift <server> [--tool <name>] [--new-hash <sha256:...>] [--remove] [--yes]`

Re-pin a tool's schema after a legitimate upgrade. **Requires `--yes` (no prompt today)**, and one of:

- **`--new-hash sha256:...`** — copy the exact hash from the block-message remediation field. Required by default (no implicit "accept whatever comes next" window).
- **`--remove`** — drop the pin entirely.

`--tool` scopes to one tool; otherwise applies to all tools on that server.

### `mcpm guard mute <signature-id> [--for <duration>]`
Adds an `ignore` override to `~/.mcpm/guard-policy.yaml`. `--for 5m` / `1h` / `24h` / `7d` auto-expires.

The signature id must exist in the shipped set — typos are rejected with a list of valid ids (see `mcpm guard list-signatures`).

### `mcpm guard unmute <signature-id>`
Removes the override.

### `mcpm guard pause [--for <duration>] [--off]`
Pauses ALL guard inspection for a window (default 10 min). The relay continues forwarding traffic but skips inspection. `--off` lifts an active pause.

Use during debugging when guard is in the way and you want to turn it off without unwrapping configs.

### `mcpm guard cleanup [--yes]`
Prunes pin entries for servers no longer installed in any client config. Dry-run by default; pass `--yes` to apply.

### `mcpm guard list-signatures [--json]`
Shows the vendored OWASP MCP Top 10 signature catalog with id / category / severity / target / description.

### `mcpm guard reset-integrity [--policy] [--yes]`
Regenerates the integrity sidecar after manually editing `~/.mcpm/pins.json` (default) or `~/.mcpm/guard-policy.yaml` (`--policy`).

Required when:
- You copy `pins.json` between machines
- You hand-edit `guard-policy.yaml` directly (rather than via `mcpm guard mute/unmute/pause`)

The relay refuses to use either file if its sidecar doesn't match — this is the rug-pull defense for the configuration itself.

### `mcpm guard run --inner --server-name <name> -- <command> [args]`
**Internal command**, semver-exempt, not for direct user use. Invoked by wrapped client configs. Requires the `--inner` flag and refuses direct invocation without it.

---

## OS confinement (`--confine`)

> Status: shipped to `main` across PRs #108–#111, **unreleased (next minor)**. **macOS only in v1.** Opt-in — without `--confine`, `enable`/`disable` behave exactly as before.

Every guard feature above is **detection**: the relay reasons about the JSON-RPC bytes flowing through it and warns or blocks. But the relay is a stdio MITM — it can inspect every frame yet cannot *contain* the child MCP server it spawns. A server that simply *decides* to read `~/.ssh` or write `~/Library/LaunchAgents` never expresses that intent through inspectable traffic. `--confine` is the first **enforcement** primitive: it wraps the relayed child in an OS sandbox so it physically cannot read secret files or persist, regardless of the JSON-RPC it emits. Detection and confinement are complementary — watch vs contain.

### The standard tier

On macOS, confinement is applied via Seatbelt (`sandbox-exec`). The one shipped tier is "standard":

- **READ — allow-all except a secret-dir denylist.** Reads are permitted everywhere *except* a curated set of credential/config locations: SSH / AWS / gcloud / gh / GnuPG keys, `~/.npmrc` / `~/.docker` / `~/.kube` / `~/.netrc` / `~/.git-credentials` and similar credential files, macOS Keychains, browser cookie stores, the MCP client config dirs, and mcpm's own `~/.mcpm` store.
- **WRITE — deny-all-of-`$HOME` except caches + scratch.** A single rule blocks the whole persistence class (`~/.zshrc`, `~/Library/LaunchAgents`, PATH-shadowing `~/bin`, git hooks). Writes are allowed only to caches (`~/.npm`, `~/.cache`, `~/Library/Caches`), the per-server scratch dir, system temp (`/tmp`, `/private/tmp`, `/var/folders`, `/var/tmp`), and `/dev`.
- **NET — launcher-classified.** Launchers that fetch at startup (npx / uvx / pip / pipx / docker / npm / pnpm / yarn / bun) get network "all"; everything else gets egress-deny "none".
- The server's own scratch dir (`~/.mcpm/sandbox/<server>`) is both readable and writable.

### Enabling and disabling

```
mcpm guard enable --confine                 # enroll every wrapped stdio server, standard tier
mcpm guard enable --confine --server foo    # scope to one server
mcpm guard enable --confine off             # same as omitting: no enrollment
```

`--confine` enrolls only **unwrapped stdio** servers it wraps — url/HTTP servers and already-wrapped servers are skipped. To **unconfine**, run the existing `mcpm guard disable` (optionally `--server <name>`): it removes the wrap marker, which removes confinement. A leftover profile left behind in the store is harmless.

### Inspecting

`mcpm guard doctor-confine [--json]` is read-only: it reports OS-backend availability (platform + `/usr/bin/sandbox-exec` presence) and the enrolled servers with their tier / net / require_confine flags. For per-client wrap state, use `mcpm guard status`.

### Hybrid posture (what happens without a backend)

Confinement never fails silently. The store (`~/.mcpm/guard-confine.yaml`) is the source of truth for "is server X enrolled".

- **Confine** when the server is enrolled + the profile hash matches + an OS backend is available.
- **Run unconfined with a loud notice** when there is no OS backend (Linux / CI / Windows) or the marker/profile is missing on a **non-required** server. Never silent — backend availability is pre-checked, never inferred from a spawn error.
- **Fail closed (refuse to start, exit 1)** at spawn time on: a profile-hash mismatch (tamper), a malformed hash, a stripped marker on a `require_confine` server, or a wiped store on a `require_confine` server.

### Marker tokens

The wrapped config entry carries two new tokens **before** the `--` separator: `--confine-profile-hash <sha256>` (a content hash of the rendered profile, binding the marker to the stored profile) and `--confine-required` (a bare flag, present iff the server is `require_confine`, replicated into the IDE config so it survives a wiped store). Both are **neutral** to `--orig-hash` — excluded from its hash input, and the `--` position is unchanged — so unwrap/disable still work.

### Store

`~/.mcpm/guard-confine.yaml` (+ an unkeyed `.integrity` sidecar) is the enrollment source of truth. Like `pins.json`, it **fails closed** on integrity / shape / format-version mismatch. The sidecar is tamper-*evidence*, not authenticity (issue #19) — the same honest labeling as the pins and policy sidecars.

### Caveats

- **macOS only.** Linux `bwrap` support and a STRICT tier (read-allowlist / scratch-only-write / host-granular net) are deferred.
- The macOS `sandbox-exec` path is **not exercised in CI** (ubuntu-only); it is covered by mocked arg-vector unit tests plus local darwin verification — the same gap the os-keychain darwin shell-outs already carry.
- Net is launcher-permissive, so confinement does **not** stop network exfil in general, and it does **not** defend against a same-user attacker who can rewrite both the IDE config *and* `~/.mcpm`.
- **Deferred fast-follow:** the per-server `mcpm guard confine <server>` command (`--off` / `--show` / `--require` / `--allow-read/-write/-net`) is not shipped. Per-server confine is achievable today via `enable --confine --server X` + `disable --server X`.

---

## Files mcpm-guard touches

| Path | Purpose | Format |
|---|---|---|
| `~/.mcpm/pins.json` | Per-tool SHA-256 schema pins | JSON, see `docs/SIGNATURES.md` for the structure |
| `~/.mcpm/pins.json.integrity` | SHA-256 of `pins.json` content | One-line sha256 sidecar |
| `~/.mcpm/guard-policy.yaml` | User overrides + pause state | YAML, see `docs/POLICY.md` |
| `~/.mcpm/guard-policy.yaml.integrity` | SHA-256 of `guard-policy.yaml` | One-line sha256 sidecar |
| `~/.mcpm/guard-confine.yaml` | OS-confinement enrollment (tier / net / require_confine per server) | YAML, fails closed like pins.json |
| `~/.mcpm/guard-confine.yaml.integrity` | SHA-256 of `guard-confine.yaml` | One-line sha256 sidecar |
| `~/.mcpm/guard-events.jsonl` | Append-only event log | JSON-Lines |
| `<client config>.guard-{enable,disable}.bak` | Pre-batch backup per touched client | Original JSON content |

All files are written `0o600`; the parent dir is `0o700`.

Confinement adds events (not signatures — the catalog count is unchanged) to `guard-events.jsonl` under category `CONFINE`: `confine-applied`, `confine-hash-mismatch`, `confine-marker-stripped`, `confine-profile-missing`, `confine-backend-missing`, `confine-marker-malformed`; plus `orig-hash-mismatch` (category `RELAY`, from the spawn-time `--orig-hash` verify).

---

## Day-1 vs Day-7 vs Day-30 surface

- **Day 1:** `enable`, `disable`, `status`, `demo`. That's it.
- **Day 7:** `accept-drift` (you've hit your first legitimate server upgrade), `mute` (you've hit your first FP), `list-signatures` (you're curious what's protecting you).
- **Day 30:** `pause` (debugging), `cleanup` (you've uninstalled some servers), `reset-integrity` (you copied your `~/.mcpm/` between machines).

---

## When guard breaks your workflow

If a wrapped server stops working after `enable`, the order of escalation:

1. **`mcpm guard status`** — is the server in `unprotected (first-session-pin pending)` mode? That's fine; the next session captures the pin.
2. **`~/.mcpm/guard-events.jsonl`** — is there a block entry for that server? The `remediation` field tells you the exact command to run.
3. **`mcpm guard mute <id> --for 5m`** — temporary mute while you investigate.
4. **`mcpm guard pause --for 10m`** — turns off all inspection for 10 minutes.
5. **`mcpm guard disable --server <name>`** — permanently unwraps just that one server while keeping others protected.

If guard itself crashes (e.g. on PATH disruption — the wrapped command points at `mcpm`):
- All wrapped servers go dark simultaneously across all IDEs.
- Restore from `<client config>.guard-enable.bak` manually, or re-install `@getmcpm/cli` to restore the binary.

---

## Threat model (what guard does and doesn't protect against)

**Protects:**
- Prompt-injection text in tool responses (e.g. Slack messages, web fetches) — OWASP MCP-2
- Tool-description poisoning (Invariant Labs disclosure) — OWASP MCP-1
- Rug-pull schema mutation after install — OWASP MCP-1 via pinning
- Same-session double-`tools/list` poisoning — via per-session hash cache

**Does NOT protect against:**
- Compromised install — the wrap is opt-in via `mcpm guard enable`; if your machine is already compromised, the attacker can disable guard
- Same-user file tampering — `~/.mcpm/pins.json` and `~/.mcpm/guard-policy.yaml` have integrity sidecars, but a same-user attacker can compute new sidecars; the sidecars are an "accidental tamper / cross-user" defense, not anti-malware
- Verbatim attack-phrase documentation — the regex engine cannot distinguish "ignore previous instructions" used as documentation from the same phrase used as an instruction. The LLM-as-judge tier in v0.5.1+ would close this gap
- HTTP-transport servers — v0.5.0 wraps stdio only. HTTP guard is v0.5.1+

**Performance budget:** spike measured 0.065ms p99 small / 3.1ms p99 large message overhead through the SDK framing helpers (OQ1 closed). With NFKC + 15 regexes per leaf added on top, expected p99 is < 10ms for large messages.
