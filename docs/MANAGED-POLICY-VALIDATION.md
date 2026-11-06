# Claude Code managed-policy preflight — candidate #122

This candidate adds the `claude-code-2.1.296-stdio-files` projection before
Claude Code user-global stdio configuration writes. It addresses a measured
failure in the published 0.50.0 baseline: replacing a denied server command with
a relay command can bypass native exact-command denial, while replacing an
allowed command can make a usable server fail the native allowlist.

## Consumer behavior

Run `mcpm guard enable --client claude-code --server <name> --dry-run` first.
The same preflight runs for the actual wrap and at the adapter write boundary,
including `install`, `update`, `up`, setup through those commands, guard disable,
and toggles. `up --dry-run` preflights before snapshots and secret persistence.
Recognized wrappers are preflighted during enable and preview even when no rewrap
is needed, so a legacy underlying-policy violation is not hidden by an
"already guarded" skip. It compares the current launcher, its recognized underlying command, the proposed
launcher including **every wrapper argument**, and its underlying command.
A denied or unknown proposed launch refuses the transformation; no policy bypass
flag is provided. Exact teardown of a recognized legacy wrapper can restore a
natively denied original command without granting permission. Replacing a denied
old command with a different allowed command is also permitted; the original
decision remains visible. Ordinary direct HTTP writes remain outside this stdio
projection and keep their native URL policy checks. Guard policy refusals exit 1, including dry-run, and count as
errors. They do not create config backups or confinement profiles. Unrelated
servers can still succeed; partial application must be inspected.

Reports contain decisions, rule-list indices and fixed source labels, never raw
commands, argument values, URLs or environment values. An ordinary unmanaged
stdio installation remains usable. A passing projection prints a warning that
overall host policy is **unknown**, including server-managed/MDM/registry/session
and other-project coverage. No managed policy is edited to accommodate a wrapper.

## Supported projection

The fixed source set is user `~/.claude/settings.json`, current-directory
`.claude/settings.json` and `.claude/settings.local.json`, and
`managed-settings.json` plus detection of `managed-mcp.json` under
`/etc/claude-code` on Linux or `/Library/Application Support/ClaudeCode` on macOS.
Reads reject symlink components (selected home/root directory aliases are
canonicalized), non-regular files, invalid UTF-8, duplicate decoded JSON keys,
malformed JSON and files larger than 1 MiB. Descriptor/path metadata changes
during a read produce unknown. Missing files are distinct from unreadable files;
an empty settings file is conservatively unknown rather than an empty allowlist.

Rules contain exactly one `serverName`, `serverCommand` or `serverUrl` key.
For stdio, command matching is an exact command-and-arguments array comparison;
environment blocks do not participate. Deny wins. An unset allowlist is
unrestricted within this file projection; an empty allowlist allows none.
Lists merge across the supported settings scopes, except a managed
`allowManagedMcpServersOnly` lock selects the managed allowlist. A command entry
in the allowlist prevents name-only entries from rescuing stdio commands.

`${VAR}` and `${VAR:-default}` expand without executing anything. Server command
values use the projected live settings environment; policy command values use
the launching environment plus managed settings environment. Deny fallback can
use user settings environment only when a variable is absent from the pinned
environment and has no `:-default`. An explicitly empty startup value stays empty.
Known native-filtered environment references, including color/runtime/credential
controls, are unsupported and produce unknown; this projection does not reproduce
the client's host-dependent environment filter. Missing or unsupported expansion
produces unknown. Names remain literal.

`managed-mcp.json` exclusive control and a matching managed `managedMcpServers`
name prevent rewriting a user-global definition: managed definitions' allowlist
exceptions are not transferred to a user-controlled wrapper. Other managed
provided names do not disable ordinary user-global installations.

## Explicit limits

This is a versioned **file-policy projection**, not a full native policy engine,
host version detection, proof of effective selection, or a runtime enforcement
claim. Native candidate receipts must identify their source/archive/harness and
pinned runtime separately. The Linux native target is Claude Code 2.1.296; no
macOS native result or all-client protection is implied.

A present managed drop-in directory, detected macOS MDM preference file,
Windows/WSL, alternate config directory, ancestor project settings, worktree
root selection, or unsupported local policy/source selector refuses the
transformation as unknown. A top-level `env` in legacy `~/.claude.json` is an
unsupported additional source and refuses stdio transformations. Supported settings
JSON must not contain `policyHelper`, `policyHelpers`, `parentSettings`, `managedSourcesBehavior`, `strictPluginOnlyCustomization` or
`wslInheritsWindowsSettings`; helpers never execute. The plan does not resolve
remote/registry-managed policy, embedding hosts, session flags, other projects,
future host environments or future policy changes. Those planes remain unknown
and are surfaced on successful writes and previews. File reads are snapshots,
not a transaction with a running client or concurrently changing policy tree.
Remote HTTP/SSE matching and managed-policy writes are outside this MVP.

Upgrading does not automatically rewrite existing wrappers, reevaluate their
already-running servers, or add a runtime native-policy enforcement layer. Inspect
existing wrappers with the supported dry-run. Where authorized, exact unwrapping
can restore the original command and its native denial; it does not grant that
command permission to run. Client restart/reload behavior remains separate.

## Evidence

Unit fixtures exercise real shared `replaceServer` and `addServer` write gates,
allow/deny/unset/empty rules, exact wrapper argv, scope merges, managed-only locks,
expansion and pinned environments, managed shadowing/exclusive control, malformed
and duplicate-key sources, unknown source selection, dry-run and confinement
refusal before backup/profile files. Existing scope-reader fixtures remain green.

Astra independently reproduced additional pre-review candidate bypasses through
plural policy-helper settings, native default/fallback precedence, a native-filtered
environment variable, legacy global environment settings and inherited JavaScript
object keys in variable lookup. The fixes refuse
unsupported sources/references, implement the pinned fallback order and require
own-property environment lookup. An attempted
credential-variable probe did not reproduce and is not counted as a finding.
Fresh artifact checks must use the final reviewed bytes, not those vulnerable
pre-review candidate archives.

### Reviewed candidate checkpoint — 2026-11-06

Sol built the slice; Astra independently reviewed and fixed confirmed regressions.
The frozen candidate archive SHA-256 is
`cca729bd4c97881f1a70c2bea458e91377b6de87e8639da156a117255244939d`.
Its package version is the repository placeholder `0.15.0`, not a published release.
The final policy-source SHA-256 is
`2306f09c1f74b9a464d740166444f37814c9677dc96f511857702d49b5561a3d`.
An independent read-back matched all 66 installed JavaScript files and the archive
in each native test image to the reviewed build. Receipts bind all changed source
and test files, root lock, native harness and public usage skill.

- Node 24.20.0: typecheck including tooling, build, 161 test files / 3,789 tests
  passed, three skipped. Coverage passed: 91.55% lines, 86.72% branches,
  90.28% statements, 86.75% functions; the negative-threshold probe passed.
- Linux arm64 / Node 26.11.1 / Claude Code 2.1.296: **19 native cases passed**.
  Seven enable cases cover unmanaged, denied, allowed, name-allowed, empty allow,
  expanded deny and allowing both original/wrapper. Five repair/preview cases
  cover three legacy teardown states and denied/unmanaged dry-runs. Five review
  regressions cover helpers, fallback precedence, filtered variables, legacy env
  and inherited keys. Two existing-wrapper audits refuse the unsafe state without
  changing it, including dry-run. Native connection claims include actual
  `initialize` and `tools/list` traffic from the synthetic peer.
- The same archive passed the modern/legacy direct/guarded protocol matrix:
  **87 passed, zero failed, two expected unsupported, four exclusions**. Archive
  SRI, all runtime files, raw dependency lock, harness/skill hashes and actual
  container boundaries were independently checked.
- Clean-install smoke of this exact local archive passed using the release
  dogfood script in supplied-spec mode; this is candidate evidence, not npm
  publication.
- Real macOS Seatbelt dogfood passed: positive control, denied synthetic-secret
  read, intact stdio, tampered profile refusal and recorded confinement event.

Native containers were offline, read-only, UID 1000, capability-free with
no-new-privileges, disposable state and no host binds or credentials. Native
`mcp get` deliberately executes only the synthetic peer; product configuration
operations did not execute it or expose the synthetic secret in their output.

One concurrent coverage attempt hit an existing five-second smoke-test timeout;
the idle rerun passed without changing tests. One existing-wrapper dry-run probe
incorrectly assumed no guard state existed after deliberately launching that
wrapper; its corrected fresh run compared the pre-operation state and passed.
Both failed attempts are retained and excluded from passing evidence.

Local evidence roots (temporary maintainer receipts, not public distribution):
`/private/tmp/mcpm-policy-122-final-native-20261106` (`identity.json`,
`verified-final.json`), `/private/tmp/mcpm-policy-122-final-audit-dry-v2-20261106`
and `/private/tmp/mcpm-policy-122-final-protocol-20261106/verified-binding.json`.
These are candidate observations, separate from the vulnerable published 0.50.0
baseline and any later actual-published artifact verification. No model/provider
turn, full host-policy coverage or macOS native-client result is claimed.

Semantics checked against official
[managed MCP documentation](https://code.claude.com/docs/en/managed-mcp) and
[settings source documentation](https://code.claude.com/docs/en/settings) on
2026-11-06. These pages describe later versions too; unsupported planes are
reported rather than guessed from the latest documentation.
