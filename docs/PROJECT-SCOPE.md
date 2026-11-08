# Project/client scope inventory

`mcpm scope <project-root> [--json]` reads a bounded set of local configuration
sources for an explicitly selected directory. Claude Code remains the default;
`--client vscode` selects a separate fixed VS Code/Copilot profile. It does not run clients,
commands, hooks, credential helpers or MCP servers, and never writes client
configuration. Other client selectors are refused before inventory reads.

```sh
mcpm scope /path/to/project
mcpm scope /path/to/project --json
mcpm scope /path/to/project --client vscode --json
```

An empty root argument is rejected; use `.` to explicitly select the current directory.
The selected directory is canonicalized. The fixed MCP candidates are:

## Claude Code profile (default)

| Scope | Source |
|---|---|
| local | `~/.claude.json` → `projects[<root>].mcpServers` |
| project | `<root>/.mcp.json` → `mcpServers` |
| user | `~/.claude.json` → top-level `mcpServers` |
| managed | OS Claude Code policy directory → `managed-mcp.json` → `mcpServers` |

Local lookup considers the canonical root and the explicit absolute spelling.
If both have entries, that local source is malformed/ambiguous rather than
silently merged. It does not search other project keys. Managed paths are
`/Library/Application Support/ClaudeCode` on macOS, `/etc/claude-code` on Linux,
and `C:\Program Files\ClaudeCode` on Windows.

Each observed server includes its name, source, scope, declaration shape and
static guard-form classification. It never includes command strings, arguments,
URLs, environment/header values, expanded placeholders or instruction contents.
The existing entry shape validator checks known field types; it is not a complete
Claude Code configuration validator. A recognizable `mcpm` launcher/marker is
configuration metadata only. Node-script wrapper identity remains unknown:
configured executable paths and package metadata are not probed. Recognition
never authenticates a binary or proves that a guard is loaded or enforcing.

For matching names, `possibleShadowedBy` records observed declarations in higher
scopes using the documented **Claude Code CLI** order local, project, user.
It is not an effective-winner calculation: a malformed/unreadable higher source,
managed controls, approvals, session flags or other unexamined settings may
change what actually loads. The Desktop Code tab can have different precedence.
Every report therefore keeps host version, effective selection, loading and
enforcement unknown, including when no servers are observed.

Instruction inventory probes metadata/access only for `CLAUDE.md`,
`.claude/CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` and `.claude/AGENTS.md`
at the explicit root and each ancestor through filesystem root, plus user and
managed `CLAUDE.md`. Ancestor instruction files combine rather than shadow.
All candidates have unknown applicability: AGENTS support, settings, exclusions
and imports vary by host/version. Instruction contents and imports are not read.
There is no recursive directory listing, whole-home discovery or Git execution.
Rules, nested/on-demand instructions, additional workspace roots, settings,
plugins, connectors, environment overrides such as `CLAUDE_CONFIG_DIR`, session
flags and remote/registry policy are explicit coverage limits.

The version-1 JSON model reports `sources`, `servers`, `instructions`, `coverage`
and `root`. File states distinguish `missing`, `unreadable`, `malformed`,
`symlink-skipped`, `not-file`, `too-large` and `present`. JSON objects, containers
and duplicate object keys are checked; invalid UTF-8 is rejected; malformed server entries stay visible
by name. `configured: true` means a declaration was observed, not that Claude Code
accepted it. Raw parser/OS errors are never printed. Each config read is bounded to
1 MiB. Symlink components are skipped, including dangling links and directory
links; an explicitly selected root may itself resolve through a symlink.
The final file open uses `O_NOFOLLOW` and `O_NONBLOCK` where available to avoid
following a final symlink or blocking on a replacement FIFO. This is a snapshot, not
an atomic view against concurrent directory replacement.

Exit `0` means the fixed candidates were inventoried (present or absent);
`inventoryComplete: true` does not imply complete host coverage or healthy/active
configuration. Exit `1` means an invalid root or an incomplete fixed-source
inventory, including denied, malformed, symlink-skipped and oversized inputs.
Unsupported coverage alone does not change the exit code. Human output sanitizes
names and paths for terminals; JSON preserves metadata names and paths.

## VS Code profile (`--client vscode`)

This opt-in profile keeps the version-1 envelope with `client: "vscode"`; the
default Claude Code model/human output above is unchanged. Four fixed MCP
candidates are inventoried separately:

| Origin | Candidate | Format/container | Parser |
| --- | --- | --- | --- |
| `vscode-project` | `<root>/.vscode/mcp.json` | VS Code `servers` | JSONC |
| `copilot-project` | `<root>/.mcp.json` | portable `mcpServers`, or legacy bare server map | JSONC |
| `vscode-user` | default Code user-profile candidate → `mcp.json` | VS Code `servers` | JSONC |
| `copilot-user` | `~/.copilot/mcp-config.json` | portable `mcpServers` | strict JSON |

Default Code user candidates are `~/Library/Application Support/Code/User` on
macOS, `~/.config/Code/User` on Linux and `%APPDATA%/Code/User` on Windows
(home fallback if APPDATA is absent/unusable). These are candidate paths, not
proof of the selected profile. Named profiles, Insiders, portable installations,
alternate user-data directories, remote locations and `COPILOT_HOME` /
`XDG_CONFIG_HOME` overrides are not discovered. `.code-workspace` settings,
additional folders/URIs and developer-container configuration remain unexamined.

Each source includes `origin`, `format`, `container`, path/state and
`uninterpretedRootFields` (boolean, or `"unknown"` when parsing was unavailable).
Extra root-field names/values are not printed. Mixed containers stay incomplete;
interpretable declarations in other sources remain visible. For a bare project
map, every key is considered independently, including a malformed server named
`servers`. An own `mcpServers` key always selects the wrapped interpretation;
an invalid wrapper is not guessed to be a bare server.

Server rows retain origin/format/source, name, configured/declaration metadata,
guard form and `sameNameIn` references. Same-name rows observe duplication only;
there is no cross-format/harness precedence or effective-winner calculation.
Known field shapes are checked, not complete native configuration validity.
VS Code environment values can be strings, finite numbers or null; when that
shape exceeds the string-only wrapper recognizer, guard form remains unknown.
Uninterpreted supported fields are retained as unknown semantics rather than
being treated as native rejection. No commands, arguments, URLs, env/header
values, placeholders or instruction bodies appear in either output format.

Fixed instruction metadata candidates at the root and ancestors are
`.github/copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md` and
`.claude/CLAUDE.md`; user candidates are `.copilot/copilot-instructions.md`,
`.claude/CLAUDE.md` and `.codex/AGENTS.md` beneath home. The selected harness and
parent-repository settings control applicability, which remains unknown. Local
profile instructions, recursive `*.instructions.md`/rules, nested files, custom
locations, imports and `CODEX_HOME` overrides are not followed.

The same 1 MiB, duplicate-key, UTF-8, symlink, bounded-open and file-state rules
apply. JSONC accepts comments, trailing commas and a leading UTF-8 BOM only when
explicitly enabled for the corresponding source. The shared strict readers and
Claude Code profile remain strict. Exit 0 still means the fixed candidates were
inventoried, not that all profiles/harnesses are covered. Host version, selected
profile, forwarding, effective selection, loading and enforcement remain unknown.

The latest documentation distinguishes VS Code `servers` from portable Copilot
`mcpServers`: Copilot sessions read portable files and receive only eligible
forwarded VS Code entries; interactive-input entries are excluded. Workspace
portable and user portable capabilities also differ. This inventory does not
normalize formats or resolve those forwarding/activation rules.

## VS Code candidate validation — 2026-11-08 (not released)

The extension is a candidate for review, not part of published v0.51.0. Source
typecheck/build/coverage passed (3,877 tests passed, one skipped). The packed
candidate passed 139 modern/legacy comparisons, zero failures, two expected
unsupported combinations and four exclusions, plus a clean-install smoke.
Independent runtime/lock/harness and retained-capture read-back passed.
Candidate SHA-256:
`a76558b6009adf5f8a2428ae067ed173e0060dc6a13e936689be037d10ccea48`.
The public usage skill source is 1.3.1; this is not an npm publication.
Hosted PR #337 runs at `9a3968d` twice reached the outer 120-second protocol
launcher deadline: the first completed 131 passing cases with eight unrun; an
unchanged retry completed 135 passing cases with four unrun. Neither reported
a case assertion failure, and both remain failed/incomplete executions. The
outer launcher budget is now 180 seconds for the full 139-case workload; per-case
deadlines, assertions, resources and thresholds are unchanged. The launcher
regression exercises the real shell path with an ETIMEDOUT result and requires
exit 124, container kill before evidence export, and final removal. Fresh hosted
CI must validate the new head; local completion does not replace that check.
The normal native self-check entry points passed 124 tests, including 20 focused
scope receipt checks. The protocol result includes independent replay of 104
retained direct/guarded captures.

The separate manual harness runs twelve actual packed CLI cases without
filesystem mocks. Its harmless configured executable first has a working
positive control, then its marker is removed; every inventory invocation must
leave the marker absent and source bytes/modes unchanged. Fixtures cover all
four origins, both human/JSON output, unchanged default/explicit Claude models,
malformed/duplicate/strict-user-JSONC/symlink/denied inputs, invalid roots and
the bare-map malformed-neighbor regression.

Its pinned native reference is VS Code 1.141.0, commit
`2a59476c9bfcb90b3ddc372c36762471b7dfad1c`, Linux arm64. Native sources are
reset to empty/inert configurations before the first Code process. The inspected
`workbench.mcp.openUserMcpJson` command only opens/creates the current profile's
file; the test records its actual URI under fresh `/home/node`, with no
user-data-dir or XDG configuration override. A separate project document checks
JSONC editor syntax through an initial diagnostic snapshot, an unsaved malformed
control with an actual URI/version diagnostic event, then restored original
bytes with a matching zero-error event. This is profile-path/editor-syntax proof,
not native MCP selection, portable-format activation, forwarding or consent.
The actual native run passed all twelve packed CLI cases and the native reference.
It observed `/home/node/.config/Code/User/mcp.json`, an invalid-buffer diagnostic
event at document version 2 and a restored zero-error event at version 3, bound
to the actual text digests. Actual UID/GID 1000, zero effective capabilities,
NoNewPrivs 1, loopback-only networking and an EROFS root-write result matched the
outer boundary. Independent image/input read-back matched all 2,609 Code files,
66 candidate runtime JavaScript files, the resolved lock and helper fixtures.
Extraction umask removed group-write bits from some archive members; bytes and
executable bits were preserved, and actual extracted modes were bound.
The test container and evidence volume were removed after read-back.

Native report SHA-256:
`fd1a61ed449d0217ed3eaa627d64d6a7cbd445e6b329e6ffc3156c8899751f2b`.
Input manifest SHA-256:
`19e9768ee456cf0999210cc615efa09f696e05f6b7458369e20dc3c4c045cb61`.
Resolved validation lock SHA-256:
`14c50101fdb2e60fd384e43ee80f236472b22da585da0795e2de3f2567d286a4`.
Native image:
`848d7766bf1ebbb263db1b121ea4b19ad0ac7448c1e05845e3ee624010af5457`.
Receipts remain under `/private/tmp/mcpm-vscode141-native-evidence-attempt1-20261108`
and `/private/tmp/mcpm-vscode141-native-readback-20261108`. Astra independently
replayed the evidence and rejected eleven mutations of the actual receipt.
These are local candidate measurements; macOS/Windows native behavior remains
unmeasured. The earlier pinned Tart archive matched its hash, but `--version`
exited 137/SIGKILL and read-only signature checks found an invalid arm64 signature.
No VM started; no re-signing, quarantine change or security bypass was attempted.

### Manual offline validation

Use explicit public inputs and a fresh context; preparation never builds or runs
the client. Use the [official pinned Linux arm64 archive](https://vscode.download.prss.microsoft.com/dbazure/download/stable/2a59476c9bfcb90b3ddc372c36762471b7dfad1c/code-stable-arm64-1791276594.tar.gz)
(349,562,023 bytes). Its SHA-256 is
`3b6ea238a2aa9000bab0137c19f06d4e8edcb5587438a3afc9dc9739e793e934`.
Preparation checks that identity and archive paths, copies only four helper files,
the existing protocol manifest/lock with a candidate overlay, the candidate and
its runtime-JavaScript manifest, and inventories the extracted Code files.

```sh
node scripts/scope-vscode/run.mjs --prepare /path/to/candidate.tgz /path/to/vscode-linux-arm64.tar.gz /private/tmp/mcpm-vscode-context
docker build --platform linux/arm64 --iidfile /private/tmp/mcpm-vscode-context/image.id /private/tmp/mcpm-vscode-context
```

Create the resulting image with the measured boundary:

```sh
docker create --platform linux/arm64 --network none --read-only --user 1000:1000 \
  --cap-drop ALL --security-opt no-new-privileges --init --pids-limit 256 \
  --memory 2g --cpus 2 --mount type=volume,destination=/evidence \
  --tmpfs /home/node:rw,noexec,nosuid,size=256m,uid=1000,gid=1000 \
  --tmpfs /work:rw,noexec,nosuid,size=256m,uid=1000,gid=1000 \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m,uid=1000,gid=1000 \
  "$(cat /private/tmp/mcpm-vscode-context/image.id)"
```

Retain the returned container ID. No host
bind mounts, Docker socket, host network, real profiles or extra extensions are
permitted. The base and Node are pinned in the Dockerfile; build-time public
package provisioning is separate from offline execution.

Bound `docker start -a <container>` to 180 seconds (for example with Node's
`spawnSync` timeout). On timeout, kill the container before copying evidence.
Before removal, retain `/evidence`, actual container/image inspection and attach
exit/error/signal status; then `docker rm -fv <container>`. Check `report.json`,
raw CLI/native receipts, input hashes and actual runtime boundary together.
`check.mjs` has authored negative self-checks through the existing native CI
entry point; they are not native proof. The native process uses `--no-sandbox`
inside the outer container and disables Workspace Trust for this inert reference;
it establishes no Chromium-sandbox, native-consent or enforcement guarantee.

## Primary references

Claude Code semantics checked against the official documentation on 2026-11-05:

- [MCP scopes and precedence](https://code.claude.com/docs/en/mcp#scope-hierarchy-and-precedence)
- [Managed MCP configuration](https://code.claude.com/docs/en/managed-mcp#deploy-managed-mcpjson)
- [Instruction loading](https://code.claude.com/docs/en/memory#how-claude-md-files-load)
- [AGENTS.md applicability](https://code.claude.com/docs/en/memory#when-claude-code-reads-agentsmd)

VS Code references checked 2026-11-08: [configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
and [instruction locations](https://code.visualstudio.com/docs/agents/reference/custom-instructions-reference).
The retained docs pin is `microsoft/vscode-docs` commit
`acd9e8d8aee79ed597c6d1d7fe9b45b886e58e76`; the separate native/core pin above
anchors [project portable parsing](https://github.com/microsoft/vscode/blob/2a59476c9bfcb90b3ddc372c36762471b7dfad1c/src/vs/platform/mcp/common/mcpWorkspaceConfiguration.ts),
[strict user portable parsing](https://github.com/microsoft/vscode/blob/2a59476c9bfcb90b3ddc372c36762471b7dfad1c/src/vs/platform/mcp/common/mcpCopilotGlobalConfiguration.ts)
and the non-starting [profile-file command](https://github.com/microsoft/vscode/blob/2a59476c9bfcb90b3ddc372c36762471b7dfad1c/src/vs/workbench/contrib/mcp/browser/mcpCommands.ts).

These describe a host profile; this command does not execute or identify the
installed host version and cannot prove native selection or activation.

## Candidate validation — 2026-11-05

Sol implemented this slice; Astra reviewed and fixed a FIFO open race, invalid
UTF-8 acceptance and quadratic shadow comparisons, with regressions. Final source
checks passed: **3,758 tests, three skipped**, typecheck, build and diff checks.
The command's 24 focused tests include malformed/duplicate containers, prototype
names, canonical/alias project keys, missing/denied/symlink paths and read limits.

The packed placeholder-version candidate passed **87 modern/legacy direct/guarded
SDK comparisons, zero failures, two expected unsupported combinations and four
exclusions**. Independent read-back verified archive SRI, every runtime JavaScript
hash, the raw lock, harness/public skill hashes and actual container isolation.
Candidate SHA-256: `453caa38d607ecff8ed615a75b2bd49073320a344e6110092a8d014fbe2d21fd`.

A separate offline Linux/arm64 container ran the packed `scope` CLI as UID1000
with read-only root, cap-drop ALL, no-new-privileges and no host bind mounts.
Synthetic user/project/local duplicates and ancestor/user instruction candidates
were inventoried. JSON and human output omitted argument/env/header/URL and
instruction canaries; config bytes stayed unchanged and the server sentinel did
not execute. Denied, malformed and symlink project sources produced explicit
incomplete states/exit 1; missing required root argument and empty-string root also refused.

A **separate reference invocation** of pinned Claude Code 2.1.296 `mcp get`
selected the local duplicate and **executed the harmless sentinel**. The first
harness incorrectly assumed this native lookup would not execute servers; a
fresh corrected run records native behavior separately from `scope` guarantees.
The inventory command itself never invoked Claude Code or the server. This is
one native reference observation, not proof of universal precedence, activation,
permissions, provider/model behavior or other host versions/platforms.

Temporary receipts/probe remain in `/private/tmp/mcpm-141-reviewed-sandbox-evidence`,
`/private/tmp/mcpm-141-sandbox` and `/private/tmp/mcpm-141-reviewed-protocol`. The test
container and volume were removed after isolation/receipt read-back. This remains
a historical candidate; #315 merged and shipped in v0.50.0. Publication evidence
is recorded separately below.


## Published checkpoint — 2026-11-06

The exact npm v0.50.0 archive passed seven scope CLI cases and 87 protocol comparisons. Independent archive/runtime/lock/harness/skill and actual isolation read-back passed. The separate native reference still executed the synthetic sentinel; it is not scope no-execution or activation proof. See [publication and companion evidence](RELEASE-2026-11-06-v0.50.0.md) for hashes, CI/deployment state and limits. Historical candidate receipts above retain their original attribution.
