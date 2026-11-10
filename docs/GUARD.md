# mcpm-guard — Runtime defense reference

Long-form reference for `mcpm guard`. For the 5-minute getting-started path, see the [README quick start](../README.md#quick-start).

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

`mcpm guard enable` rewrites your detected client configs (Claude Desktop / Claude Code / Cursor / VS Code / Windsurf / Gemini CLI) so each server's `command` becomes the relay, with the original command/args sandwiched after a `--` separator. `mcpm guard disable` restores the original entries.

Detection is layered:

| Layer | Triggered by | Scope |
|---|---|---|
| **Pattern engine** | Every message | NFKC-normalized regex against tool descriptions / responses / arguments / annotations |
| **Schema pinning** | `tools/list` responses | SHA-256 hash of {description, schema, annotations} vs the pin captured on first runtime observation (TOFU, not install-time approval). Text is folded to Unicode **NFC** first (canonical equivalence only — never NFKC), so a normalization-only change is not drift |
| **Same-session drift** | 2nd+ `tools/list` in one session | Catches mid-session rug-pull attempts before the pin write commits |
| **Field-level drift tiering (H4)** | a drifted `tools/list` tool | Per-field hashes split a **description-only** change (cosmetic → warn, forwarded — the parallel description pattern scan still blocks regex-detectable injection) from a **schema / annotations** change (security → block); a pre-H4 pin with no field hashes stays a coarse block. An announced `notifications/tools/list_changed` arms a single-shot re-validation against the pin. `accept-drift` drops the field hashes (reverts that tool to coarse blocking) until the next first-session capture re-derives them. |
| **Policy overrides** | Startup snapshot applied to messages | `~/.mcpm/guard-policy.yaml` signature overrides (ignore / warn / block / log_only) and global pause state (paused_until) |

### Protocol and carrier coverage

The stdio relay inspects message content; it does not negotiate versions or
translate protocols. Legacy and modern peers must still be compatible with each
other. The base modern coverage shipped in v0.47.0; the Skills discovery row
below shipped in v0.48.1. This matrix uses
the [MCP 2026-07-28 changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover),
and [MRTR contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr).

| Carrier | Inspection and limits |
| --- | --- |
| Legacy `initialize` | Existing instructions/identity patterns and capability/name drift pins remain in effect. |
| Modern discovery | A `complete` result with nonempty string `supportedVersions` and object `capabilities` identifies a declaration. Instructions and `_meta["io.modelcontextprotocol/serverInfo"]` are pattern-scanned; capability/name drift shares the legacy pin format without moving the baseline automatically. |
| Reserved server identity metadata | Pattern-scanned on every result, even without discovery. Identity metadata on ordinary results is not separately pinned. An unrelated top-level `instructions` field is not treated as declaration context. |
| `inputRequests` sampling/elicitation | Embedded system prompts, message content, elicitation messages/schema text, and sampling tool definitions reach existing detectors. Detected critical input-context attacks block. Multiple requests share the existing traversal-budget checks; tool-name collisions are checked within each sampling request. |
| Unknown/malformed `inputRequests` | Emits `guard-unsupported-input-request` (`high`, default `warn`). Coverage is incomplete; the frame is forwarded and logged. Supported siblings are still inspected and can block. Local policy overrides apply normally. |
| `roots/list` input requests | No model/user prompt content to scan. Forwarded; directory authorization remains the client's responsibility. |
| `requestState` and retries | Opaque retry state is preserved without decoding or inspecting it. Retry correlation and the authorization of returned input are responsibilities of the client/server. |
| Skills and resource discovery metadata (v0.48.1) | `skills/list` entries and `skills/get` entry frontmatter/`_meta`, plus resource listing name/title/description/annotations/`_meta`, reach the shared metadata patterns and concealment/budget checks under `discovery_metadata`. Critical instruction matches block; ordinary `resources/read` file text stays warn-and-forward. Directory reads and `resources/list` share a reply shape, so both resource listing surfaces are inspected regardless of URI scheme. |
| Ordinary tool/resource/prompt results | Existing field-scoped detectors and retrieved-data warn clamp remain unchanged, including results that omit `resultType`. |
| External schema references, skill archives, binary media | No external `$ref` resolution, archive fetching/extraction, image/audio understanding, or complete extension validation. Existing in-frame string scanning does not establish coverage of these contents. |
| HTTP transports | No runtime relay inspection. Existing deny-by-default/explicit unguarded consent behavior remains. |

The coverage warning detects unsupported methods and scan-container shapes,
including skipped sampling message/tool entries and wrong-typed system prompts;
it is not general request-schema validation. Binary and external content can still
be outside inspection even when a known request has no findings.

A blocked MRTR input request is part of the original response: the guard sends
a synthetic error to the **client**, preserving the outer response id. It does
not send the legacy server-request error back to the child. Benign input requests,
retry state and warnings are forwarded without editing their payloads. Repeated
discovery with the same identity/capabilities does not produce drift; version and
instructions remain outside drift hashes, as with legacy initialize.

The authored modern fixtures run through `guard inspect` and a real guarded
subprocess, alongside the existing legacy regression suite. These checks do not
measure adoption or interoperability in installed IDE clients, and do not certify
all 2026-07-28 protocol behavior. Dual-era `mcpm serve` support shipped separately
in v0.48.0; see [serve validation](SERVE-PROTOCOL-VALIDATION.md).

[Skills guard validation](SKILLS-GUARD-VALIDATION.md) records the real SDK fixture
and direct/guarded comparisons. These are heuristic injection findings, not a
Skills schema validator, publisher authentication, manifest/content verification,
host consent or activation enforcement. Metadata patterns include `<important>`
and `<system>` and can flag legitimate instructions; local policy overrides apply.

The separate [sandbox compatibility harness](PROTOCOL-VALIDATION.md) compares
the pinned published release with official SDK v1/v2 peers and Inspector over
stdio. It records named protocol outcomes, guard errors and persistence under
container isolation. The separate [native client suite](NATIVE-CLIENT-VALIDATION.md)
exercises named VS Code/Claude Code builds, their real global configurations and
MCP calls in disposable macOS VMs. Other clients/platforms, live model behavior
and full conformance remain unverified; each matrix states its tested scope.

### Full message flow

The relay inspects each direction independently — a request (parent → child) and the matching response (child → parent) each run the full pattern + pin + policy pipeline before anything is forwarded:

```mermaid
sequenceDiagram
participant Client
participant Relay as mcpm stdio relay
participant Child as MCP server
participant Events as Event log
Note over Client,Child: Explicit guard enable wraps config; restart server to load it
Note over Relay: Load policy at startup; tool pins use first observation (TOFU)
Client->>Relay: Request
Relay->>Relay: Inspect request and apply policy
alt block
Relay->>Events: Log block
Relay->>Client: JSON-RPC error (when replyable)
else warn
Relay->>Events: Log warning
Relay->>Child: Forward original request
else pass (including log_only contribution)
Relay->>Child: Forward original request
end
Child->>Relay: Response
Relay->>Relay: Inspect content and applicable pin drift; apply policy
alt block
Relay->>Events: Log block
Relay->>Client: Substitute JSON-RPC error
else warn
Relay->>Events: Log warning
Relay->>Client: Forward original response
else pass (including log_only contribution)
Relay->>Client: Forward original response
end
Note over Relay,Events: Findings may be logged even when log_only contributes pass
```

---

## All commands

### `mcpm guard`
Bare invocation. Shows status if any servers are wrapped, otherwise prints help.

### `mcpm guard enable [--client <id>] [--server <name>] [--dry-run]`
Wraps detected client configs. Use `--client` to scope to one (`claude-desktop` / `claude-code` / `cursor` / `vscode` / `windsurf` / `gemini-cli`); `--server` to scope to a single server name. `--dry-run` prints the planned changes without writing.

Claude Code stdio writes now compare current/original and proposed launches with
the versioned 2.1.296 file-policy projection before wrapping, backups or confine
profile writes. Denied or unknown local policy refuses with exit 1 (dry-run too).
A passing file projection still reports overall host policy unknown; unobserved
server-managed/MDM/session/other-project restrictions can change native behavior.
See [supported sources, matching and limits](MANAGED-POLICY-VALIDATION.md).


The wrap transformation in JSON:
```
{ "command": "<orig>", "args": [...], "env": {...} }
  ↓
{ "command": "node", "args": ["<abs path to mcpm>/dist/index.js", "guard", "run", "--inner", "--server-name", "<name>", "--declared-env", "<csv of env key names>", "--orig-hash", "<sha256 hash>", "--", "<orig>", ...], "env": {...} }
```

A pre-batch `.bak` snapshot is written per touched client (`<config>.guard-enable.bak`) so the whole operation is recoverable even if a single per-server write fails mid-batch.

The `--orig-hash` token is now verified at spawn time too (previously it was checked only on `disable`/unwrap). This is **Phase 1: warn-once** on mismatch — it does *not* fail closed yet (a future release promotes it after zero-mismatch dogfood evidence); an absent hash (a legacy pre-`--orig-hash` wrap) is skipped, not failed.

Declared startup settings (`NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`,
`NODE_ICU_DATA`, `NODE_V8_COVERAGE`, `NODE_COMPILE_CACHE`, `NODE_REDIRECT_WARNINGS`,
`NODE_DEBUG`, `NODE_DEBUG_NATIVE`, `NODE_TLS_REJECT_UNAUTHORIZED`,
`OPENSSL_CONF`, `OPENSSL_MODULES`, `GLIBC_TUNABLES`, `LD_*`, `DYLD_*`) and
`MCPM_*` controls and `HOME`/`USERPROFILE`/`HOMEDRIVE`/`HOMEPATH`/`PATH` overrides are carried in the reserved `MCPM_GUARD_CHILD_ENV` field instead
of configuring the guard process. The guard validates that transport against the
original declared key list, resolves keychain placeholders into the child env,
and never restores these settings into its own `process.env`. Disable reconstructs
the original env. The transport is plaintext JSON; keychain placeholders remain
unresolved references on disk. The existing original-entry hash still covers key names, not
values. Registry metadata declaring these names produces a high tier-1
`install-script` advisory finding, including names supplied through defaults.

**Existing wrapped configs need migration:** upgrading alone cannot stop a loader
variable already attached to the IDE-launched guard. Stop/restart the affected
server after `mcpm guard disable --client <id> --server <name>` followed by
`mcpm guard enable --client <id> --server <name>` (retain `--confine` if used).
`enable` skips entries that are already wrapped. A legacy wrap with declared
child-only settings refuses to spawn its server until rebuilt; a startup loader
can still execute before that refusal, so rebuild before launching it.

This protects settings declared in the server config. Loader settings inherited
from the IDE or shell still act before mcpm starts and must be removed from that
launch environment separately. An ambient loader setting that collides with a
transported loader key also causes a child-startup refusal; remove it from the IDE
environment before restarting. Declared home/path overrides apply only to the
child, so they cannot redirect the guard away from its enrolled profile or binary. The reserved transport field cannot itself be declared by a
server. Malformed, missing, or contradictory transport data refuses the child
launch without printing its values.

On macOS, the restricted `sandbox-exec` binary strips `DYLD_*` settings before
executing its child (verified with `DYLD_LIBRARY_PATH`). A confined launch with
any declared `DYLD_*` setting therefore refuses to start. Remove unused settings
or explicitly reconsider confinement; unconfined launches preserve them.

### `mcpm guard enable [...] --allow-unguarded`
A URL/HTTP-transport server entry has no `command`, so the stdio MITM relay cannot wrap it — it would run with **zero** runtime inspection. H9 turned that silent skip into a fail-closed deny-by-default: such a server is refused unless you record explicit, informed consent with `--allow-unguarded`. Consent is persisted to `~/.mcpm/guard-unguarded.json` (`src/guard/unguarded.ts`), so later runs stay quiet for the servers you already allowed instead of re-prompting. The same flag exists on `mcpm install` and `mcpm up`.

Consent does **not** add protection — it records that you accepted its absence. The underlying limitation stands: no relay exists for non-stdio transports (a streamable-HTTP MITM is deferred).

### `mcpm guard disable [--client <id>] [--server <name>]`
Reverses the wrap by parsing the wrap marker out of the args and reconstructing the original entry. Falls back to the `.bak` if the wrap pattern is malformed (e.g. user hand-edited the config since enable).

### `mcpm guard enable [...] --confine [off]`
Opt-in OS sandbox for the servers being wrapped (macOS only, shipped in v0.16.0). See **OS confinement (`--confine`)** below. The bare flag enrolls every unwrapped stdio server it wraps at the "standard" tier; `--confine off` is the same as omitting the flag (no enrollment). Respects `--client` / `--server`.

### `mcpm guard doctor-confine [--json]`
Read-only. Reports OS-backend availability (platform + presence of `/usr/bin/sandbox-exec`) and the enrolled servers (tier / net / require_confine). Points to `mcpm guard status` for per-client wrap state. See **OS confinement (`--confine`)** below.

### `mcpm guard status`
Prints what's wrapped and the pin state per server (unprotected / first-session-pin pending / fully protected).

Wrapper recognition checks the launcher and complete marker, including its original-entry hash. Bare/absolute `mcpm` (`mcpm.cmd`/`mcpm.exe` on Windows) launchers and Node scripts resolved to an installed `@getmcpm/cli` package's declared `dist/index.js` bin are supported, including npm/npx caches, global installs, development checkouts and older Node paths. Runtime arguments of another server are not proof of a guard wrapper and remain enrollable.

Malformed markers, missing package paths and pre-hash legacy wrappers are ambiguous: status/doctor report them without counting them guarded, and enable/disable/update refuse to rewrite them. Restore the original server from a trusted client-config backup, then enable again. Recognition is static configuration evidence: it does not authenticate binary bytes or forged package metadata, prove an old Node still exists, or prove the client loaded the wrapper. A moved script with an arbitrary alias may need manual recovery because its former identity cannot be inferred.

### `mcpm guard demo`
Runs the in-process `prompt-injection` scenario. The output is byte-identical to what the production relay emits, so screenshotting the demo accurately represents what a real block looks like. Additional scenarios (path-exfil, rug-pull) are planned but not yet shipped.

### `mcpm guard accept-drift <server> [--tool <name>] [--new-hash <sha256:...>] [--remove] [--yes]`

Re-pin a tool's schema after a legitimate upgrade. **Requires `--yes` (no prompt today)**, and one of:

- **`--new-hash sha256:...`** — copy the exact hash from the block-message remediation field. Required by default (no implicit "accept whatever comes next" window).
- **`--remove`** — drop the pin entirely.

`--tool` scopes to one tool; otherwise applies to all tools on that server.

### `mcpm guard mute <signature-id> [--for <duration>]`
Adds an `ignore` override to `~/.mcpm/guard-policy.yaml`. `--for 5m` / `1h` / `24h` / `7d` expires for subsequent sessions. Restart the wrapped server to load policy changes; an existing session retains its startup overrides.

The signature id must exist in the shipped set — typos are rejected with a list of valid ids (see `mcpm guard list-signatures`).

### `mcpm guard unmute <signature-id>`
Removes the override.

### `mcpm guard pause [--for <duration>] [--off]`
Sets a pause window (default 10 min) for new guard sessions. A session started within it forwards without inspection for its entire lifetime. Policy is read only at startup: `--off` or expiry affects subsequent sessions, so restart the wrapped server to resume inspection. Pause/mute commands do not change an already-running session.

Use during debugging when guard is in the way and you want to turn it off without unwrapping configs.

### `mcpm guard cleanup [--yes]`
Prunes pin entries for servers no longer installed in any client config. Dry-run by default; pass `--yes` to apply.

A server whose config entry is malformed still counts as installed, so its pin is kept. A detected client's config that **cannot be read** (unparseable — VS Code permits JSONC comments/trailing commas, while the other clients use strict JSON — or a permission error, including on the directory that holds it) holds servers cleanup cannot see. So if any pin is held by no readable config, cleanup refuses — in the dry run and with `--yes` alike — names each unreadable client, its config path and the error, prunes nothing, and exits `1`: that pin cannot be told apart from one belonging to a live server there, and pruning it would erase the server's rug-pull baseline. Fix the config and re-run. If every pin is held by a readable config, the unreadable one cannot change the result: cleanup reports nothing to prune, notes the unreadable config, and exits `0`. A client with no config file at all is not an error. A refusal because `pins.json` fails its integrity check also exits `1`.

### `mcpm guard inspect [file] [--json]`

Runs the signature catalog over MCP JSON-RPC frame(s) **offline** — no relay, no
wrapped server, no network. Reads a file argument or stdin (`-`), and accepts one
JSON frame (pretty-printed is fine) or NDJSON with one frame per line.

```bash
mcpm guard inspect suspicious-response.json     # human-readable
cat frames.ndjson | mcpm guard inspect --json   # one verdict line per frame
```

Exit status makes it a CI gate over captured traffic: `2` if anything would be
blocked, `1` if anything warns (or a frame would not parse or could not be
inspected), `0` if all pass.

Verdicts are the same default actions the relay applies, **including the
warn-only carrier clamp**. Local policy overrides (mutes, `log_only`) are
deliberately **not** applied — this answers "what do the signatures see", not
"what would this machine's config do". Use `guard status` for the latter.

`--json` emits exactly one verdict per input frame **in input order**, and an
unparseable frame — or one that makes a detector throw — yields an explicit
`{"action":"error"}` for that frame only, rather than being skipped or aborting
the run. Both are contract guarantees external harnesses depend on: one line per
verdict is what makes positional correlation safe, and an explicit error is what
keeps "the guard says this is safe" distinguishable from "the guard fell over" —
without losing every verdict after it.
Output is escaped so no character in an attacker-controlled excerpt — including
U+2028/U+2029 and 8-bit C1 controls — can split a line or reach a terminal as a
control sequence.

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

> Status: shipped in v0.16.0 (PRs #108–#111). macOS only in v1. Opt-in — without `--confine`, `enable`/`disable` behave exactly as before.

Every guard feature above is **detection**: the relay reasons about the JSON-RPC bytes flowing through it and warns or blocks. But the relay is a stdio MITM — it can inspect every frame yet cannot *contain* the child MCP server it spawns. A server that simply *decides* to read `~/.ssh` or write `~/Library/LaunchAgents` never expresses that intent through inspectable traffic. `--confine` is the first **enforcement** primitive: it wraps the relayed child in an OS sandbox with selected secret-path read denials and write/network restrictions. The finite denylist does not cover every credential location; configured credentials are intentionally delivered to the child. Network-enabled launchers can send accessible data. Detection and confinement cover different boundaries.

### The standard tier

On macOS, confinement is applied via Seatbelt (`sandbox-exec`). The one shipped tier is "standard":

- **READ — allow-all except a secret-dir denylist.** Reads are permitted everywhere *except* a curated set of credential/config locations: SSH / AWS / gcloud / gh / GnuPG keys, `~/.npmrc` / `~/.docker` / `~/.kube` / `~/.netrc` / `~/.git-credentials` and similar credential files, macOS Keychains, browser cookie stores, the MCP client config dirs, and mcpm's own `~/.mcpm` store.
- **WRITE — deny-all-of-`$HOME` except caches + scratch.** A single rule blocks the whole persistence class (`~/.zshrc`, `~/Library/LaunchAgents`, PATH-shadowing `~/bin`, git hooks). Writes are allowed only to caches (`~/.npm`, `~/.cache`, `~/Library/Caches`), the per-server scratch dir, system temp (`/tmp`, `/private/tmp`, `/var/folders`, `/var/tmp`), and `/dev`.
- **NET — launcher-classified.** Launchers that fetch at startup get network "all"; everything else gets egress-deny "none". The full set (`LAUNCHER_COMMANDS`, `src/guard/confine/derive.ts`) is 14 commands: `npx`, `npm`, `pnpm`, `yarn`, `bun`, `bunx`, `uv`, `uvx`, `pip`, `pip3`, `pipx`, `pipenv`, `poetry`, `docker` — matched on the lowercased basename without extension, so `/usr/bin/npx` and `npx.cmd` both classify.
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
- The `confine-macos` CI job runs the hermetic confinement dogfood against real macOS Seatbelt. This exercises the named subprocess/profile checks, not native IDE loading, Windows/Linux enforcement or complete sandbox resistance.
- Net is launcher-permissive, so confinement does **not** stop network exfil in general, and it does **not** defend against a same-user attacker who can rewrite both the IDE config *and* `~/.mcpm`.
- **Deferred fast-follow:** the per-server `mcpm guard confine <server>` command (`--off` / `--show` / `--require` / `--allow-read/-write/-net`) is not shipped. Per-server confine is achievable today via `enable --confine --server X` + `disable --server X`.

---

## Runtime relay, confinement and agent hooks

These boundaries can complement one another; mcpm does not install an agent-hook
integration. Hook capabilities below refer to Claude Code's rolling official
documentation checked **2026-11-10**, not every host or the pinned 2.1.296 fixture.

| Question | mcpm stdio relay | mcpm `--confine` | Agent lifecycle hooks (Claude Code example) |
| --- | --- | --- | --- |
| Where does it act? | Supported MCP request/response frames for explicitly wrapped stdio servers; pattern findings and first-observation tool drift | The spawned server process's OS operations, according to its profile | Host events such as session/prompt, pre-tool and post-tool; can include native Bash/Edit tools and MCP calls |
| What can it change? | Blocks substitute errors before forwarding; warnings forward original frames | Selected secret-path reads, writes and launcher-dependent network access are denied by macOS Seatbelt | Supported synchronous pre-tool handlers can deny/change input; supported post-tool handlers can replace output, subject to event/host contracts |
| Is a model required? | No; deterministic local inspection | No; OS enforcement | No for command hooks, which can be deterministic/local too. Prompt/agent hooks may invoke models |
| What is outside coverage? | HTTP/SSE, unwrapped servers, agent-native tools, uninspected binary/external content and arbitrary server effects | Agent-wide activity and hook processes; secrets outside the denylist or intentionally passed in env; general exfiltration with network enabled | Events/tools the host does not dispatch, disabled/unloaded hooks, other clients and activity outside that host; an event callback is not OS containment |
| What about failure or timing? | Policy pause/overrides and unsupported carriers affect coverage; a response block cannot undo server effects already performed | Backend absence has documented hybrid/refusal rules; no universal sandbox/cancellation guarantee | Handler error/timeout policy varies by event/config/version. Async hooks cannot block; post-tool decisions cannot undo completed effects |

Claude's [PreToolUse reference](https://code.claude.com/docs/en/hooks#pretooluse)
and [post-tool decision control](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)
describe event-specific permissions/input/output controls. A post-tool
`decision: block` alone does not hide the original output or undo its effects;
output replacement is a separate supported response. See
[background hooks](https://code.claude.com/docs/en/hooks#run-hooks-in-the-background),
[hook security considerations](https://code.claude.com/docs/en/hooks#security-considerations)
and [limitations](https://code.claude.com/docs/en/hooks-guide#limitations).
Command hooks execute with the user's permissions. Their policy decisions are
not an OS sandbox, and neither hooks nor this relay establish blanket bypass immunity.

Two repository experiments retain narrower evidence:

- [#158 native inline-hook lifecycle](NATIVE-PLUGIN-LIFECYCLE.md) observed one
  command-hook fixture across update/reload/disable and fresh-process restarts:
  eight observations, three native processes, zero model requests. It does not
  prove text-skill activation, whole-plugin activation or general hook enforcement.
- [#95 command-hook confinement](HOOK-CONFINEMENT-DECISION.md) measured a separate
  restrictive direct-command candidate, **not native hook-host dispatch**. Three
  of five useful cases worked; both public inspect commands failed at user-info
  startup. Selected effects stayed denied, but a detached grandchild survived
  cancellation. The fixed candidate remains **NO-GO** for production integration;
  cleanup does not repair cancellation. No production hook backend shipped, and
  this result is not evidence that hooks generally fail.

Use host hooks for supported workflow rules, relay inspection for shared MCP
traffic checks, and opt-in confinement for selected server effects. Each requires
its own enrollment, coverage and failure evidence.

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
| `~/.mcpm/guard-unguarded.json` | H9 consent record: URL/HTTP-transport servers you allowed to run WITHOUT relay inspection (`--allow-unguarded`) | JSON |
| `~/.mcpm/guard-events.jsonl` | Append-only event log | JSON-Lines |
| `<client config>.guard-{enable,disable}.bak` | Pre-batch backup per touched client | Original JSON content |

All files are written `0o600`; the parent dir is `0o700`.

To review recorded blocks, for example:

```sh
jq 'select(.action == "block")' ~/.mcpm/guard-events.jsonl
```

Review events before muting a signature or accepting a drift hash; neither action
should be an automatic response to a block.

Confinement adds events (not signatures — the catalog count is unchanged) to `guard-events.jsonl` under category `CONFINE`: `confine-applied`, `confine-hash-mismatch`, `confine-marker-stripped`, `confine-profile-missing`, `confine-backend-missing`, `confine-marker-malformed`; plus `orig-hash-mismatch` (category `RELAY`, from the spawn-time `--orig-hash` verify).

Each logged finding also carries an OWASP MCP Top 10 pin (backlog #71 — see
`docs/owasp-mcp-mapping.md`), so you can filter the event log by category:

```sh
# every event with at least one MCP03 (Tool Poisoning)-pinned finding.
# `any(...)`, not `select(.findings[]...)` — the latter re-emits the event once
# per matching finding, so a two-finding event prints twice.
jq 'select(any(.findings[]; .owasp.id == "MCP03"))' ~/.mcpm/guard-events.jsonl
```

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
4. **`mcpm guard pause --for 10m`** — pauses new sessions started within 10 minutes; restart after clearing pause to resume inspection.
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
- Verbatim attack-phrase documentation — the regex engine cannot distinguish "ignore previous instructions" used as documentation from the same phrase used as an instruction. A future opt-in LLM-as-judge tier would close this gap
- **Very large frames are flagged, not silently half-inspected.** The leaf walk is
  bounded (100k nodes) to cap work and avoid stack exhaustion. Exhausting that
  budget raises `guard-inspection-truncated` rather than returning what it managed
  to scan: the guard will not report "clean" for a frame it did not finish
  reading. Before v0.26.0 this failed **open**, and ~73 KB of junk padding was
  enough to hide a critical injection.
- HTTP-transport servers — v0.5.0 wraps stdio only. HTTP guard is deferred (v0.10.0 made HTTP/SSE fail-closed deny-by-default; a streamable-HTTP MITM relay is still the full fix)

**Performance budget:** spike measured 0.065ms p99 small / 3.1ms p99 large message overhead through the SDK framing helpers (OQ1 closed). With NFKC + 15 regexes per leaf added on top, expected p99 is < 10ms for large messages.

Existing Claude Code wrappers are audited by the supported enable/dry-run policy
preflight. Upgrade alone does not rewrite them or stop running servers. An
authorized exact unwrap can restore native command denial; it does not grant
permission or provide a runtime policy-enforcement layer.
