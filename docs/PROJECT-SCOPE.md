# Claude Code project/scope inventory

`mcpm scope <project-root> [--json]` reads a bounded set of local configuration
sources for an explicitly selected directory. It does not run Claude Code,
commands, hooks, credential helpers or MCP servers, and never writes client
configuration. Other host profiles are not supported by this command.

```sh
mcpm scope /path/to/project
mcpm scope /path/to/project --json
```

An empty root argument is rejected; use `.` to explicitly select the current directory.
The selected directory is canonicalized. The fixed MCP candidates are:

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

## Primary references

Semantics checked against the official documentation on 2026-11-05:

- [MCP scopes and precedence](https://code.claude.com/docs/en/mcp#scope-hierarchy-and-precedence)
- [Managed MCP configuration](https://code.claude.com/docs/en/managed-mcp#deploy-managed-mcpjson)
- [Instruction loading](https://code.claude.com/docs/en/memory#how-claude-md-files-load)
- [AGENTS.md applicability](https://code.claude.com/docs/en/memory#when-claude-code-reads-agentsmd)

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
a historical candidate; #315 merged and is included in v0.50.0 release preparation.
