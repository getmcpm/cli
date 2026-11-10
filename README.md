<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/banner-light.svg">
    <img alt="mcpm — MCP security guard and package manager" src="./assets/banner-light.svg" width="680">
  </picture>
</p>

# mcpm — MCP security guard and package manager

**Assess MCP servers before installing, verify supply-chain records, and inspect
wrapped stdio traffic for known attack patterns on your machine.** mcpm combines
client configuration, trust evidence, tool-definition drift detection and an
opt-in macOS confinement profile in one CLI.

[![npm version](https://img.shields.io/npm/v/@getmcpm/cli)](https://www.npmjs.com/package/@getmcpm/cli)
[![license](https://img.shields.io/github/license/getmcpm/cli)](./LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/getmcpm/cli/ci.yml?label=tests)](https://github.com/getmcpm/cli/actions)

The default assessment and guard path is deterministic and local: no account,
model subscription, mcpm backend or telemetry. Registry resolution and package
record checks contact the public MCP registry and npm; server launchers may
fetch packages independently. An external scanner runs only if you explicitly
name an already-installed executable.

<p align="center">
  <img src="./assets/demo.gif" alt="mcpm CLI demonstration" width="680">
</p>

## Quick start

Requires **Node `^22.22.2 || ^24.15.0 || >=26.0.0`**: Node 22.22.2+, 24.15.0+
or 26+. Other versions, including 23 and 25, are outside the supported range.

```bash
npm install -g @getmcpm/cli
mcpm search filesystem
mcpm info io.github.domdomegg/filesystem-mcp
mcpm why io.github.domdomegg/filesystem-mcp
mcpm install io.github.domdomegg/filesystem-mcp
```

Search shows registry lifecycle status; `info` and `why` explain computed trust.
Review the findings and checks that did not run before accepting an installation.
The install command writes client configuration; it does not automatically enroll
the server in runtime protection. Registry names and available versions can change.

```bash
mcpm guard enable --dry-run
mcpm guard enable
# Restart the affected MCP server in your client to load the wrapper.
mcpm guard status
```

Use `--client <name>` or `--server <name>` to narrow enrollment. Status reports
recognized configuration and pin state; it does not prove your client loaded
that configuration. New servers start with first-session pinning pending.

The relay supports **stdio only**. HTTP/SSE servers have no runtime inspection;
explicit `--allow-unguarded` consent records that absence, without adding
protection. **Warnings forward the original traffic; blocks substitute an error.**
Optional `guard enable --confine` adds bounded macOS process restrictions;
network-enabled launchers can still send accessible data, including configured
credentials. See [guard coverage and confinement](docs/GUARD.md).

The binary is `mcpm`; the package is **`@getmcpm/cli`**. The Homebrew formula
`mcpm` belongs to a different project. Use this scoped npm package or the
[pnpm, npx and mise alternatives](docs/DISTRIBUTION.md).

## What it does

| Task | Evidence or behavior |
| --- | --- |
| Assess before installation | Metadata patterns for secrets, injection and suspicious package/schema shapes, with score components and unrun checks |
| Lock and verify | Package-version records, integrity and applicable Sigstore build-identity baselines; client-free CI verification |
| Guard MCP traffic | Explicit stdio wrapping, field-scoped patterns, first-observation tool pins, drift checks and policy-controlled actions |
| Manage client configuration | Detect, install, import, enable/disable and compare definitions across six client adapters |
| Inventory project exposure | Read-only `scope` source/instruction metadata: Claude Code default, explicit VS Code/Copilot selector |
| Review local artifact changes | Experimental archive-only skill/plugin snapshot comparison with byte/declaration coverage and unknown host state |

These operations answer different questions. An install-time metadata assessment
does not execute the server or audit its source. A complete inventory does not
establish active selection. A matching lock does not establish safe behavior.

## Security boundaries and evidence

A trust score is a signal about available evidence, **not a safety probability**.
Search listing is not publisher verification. Current assessment commands do not
run health checks; an unavailable external scanner does not earn a clean pass.
See [score math, scanner protocol and safety floors](docs/TRUST.md).

Tool pins use **trust on first observation (TOFU)** at runtime, not approval at
install. Initial malicious definitions can become the baseline. Later description
changes warn; schema/annotation changes block under the default drift rules.
Pattern findings can independently block. Review the actual upgrade before
accepting drift; do not automatically re-pin merely to clear a refusal.

The guard inspects supported JSON-RPC carriers, not every action a server takes.
Unknown embedded request shapes produce coverage warnings; binary media, external
schema references and fetched archives are outside complete inspection. Retrieved
resource/prompt text has warn-and-forward limits. A response block cannot undo
server-side effects that already happened. See the
[carrier matrix](docs/GUARD.md#protocol-and-carrier-coverage) and
[signature catalog](docs/SIGNATURES.md).

Confinement is opt-in and macOS-only. Its standard profile denies selected secret
paths and restricts writes, with launcher-dependent network access. It is not
general exfiltration prevention or an agent-wide sandbox. Backend absence can
produce an explicit unconfined launch for non-required enrollment; required and
integrity failures have separate refusal rules. See the
[precise confinement conditions](docs/GUARD.md#os-confinement---confine).

Sigstore verification authenticates **build identity**, not safe code. Integrity
checks compare published package records; mcpm does not intercept the bytes a
package manager downloads at server launch. Unkeyed local integrity sidecars
detect corruption but cannot authenticate against a same-user writer who can
rewrite both files.

The public [mcp-guardbench](https://github.com/getmcpm/mcp-guardbench) contains
versioned results and known misses measured through published `guard inspect`
binaries. Those stateless runtime results do not measure install-time detection
prevalence or promise coverage of unseen attacks. The
[v0.52.0 release record](docs/RELEASE-2026-11-08-v0.52.0.md) retains that release's
artifact, protocol and companion evidence. The metadata-only v0.52.1 patch keeps
the tested companions at 0.52.0; no fresh runtime measurement is implied.

## Common workflows

| Goal | Start here |
| --- | --- |
| Explain one candidate | `mcpm why <name>` |
| Review installed configuration and findings | `mcpm list`, `mcpm doctor`, `mcpm audit` |
| Find available updates | `mcpm outdated` |
| Compare clients | `mcpm sync --check` |
| Start a project stack | `mcpm init`, edit `mcpm.yaml`, then `mcpm lock` |
| Install a reviewed stack with frozen checks | `mcpm up --frozen` |
| Check a committed lock in CI | `mcpm verify --json` |
| Inspect captured MCP frames without a server | `mcpm guard inspect frames.ndjson --json` |
| Inventory a project | `mcpm scope /path/to/project --json` |
| Inventory fixed VS Code/Copilot sources | `mcpm scope /path/to/project --client vscode --json` |
| Compare local skill snapshots | `mcpm review-artifacts before.tar after.tar --profile agent-skills-2026-11-06 --json` |

`init` scaffolds an empty stack; it does not install curated starter packs. To
share an existing setup, `mcpm export > mcpm.yaml`, review the declaration, then
lock it. Locks distinguish MCP publication versions from actual package versions;
OCI tags remain mutable. See [stack examples and the command index](docs/USAGE.md)
and use `mcpm <command> --help` for flags.

For CI, use the [verification Action](.github/actions/mcpm-verify/README.md).
Pin its source and executed CLI version separately. Verification checks lock
coverage as well as applicable integrity/provenance baselines; unknown or
unenforceable coverage must remain visible. `audit --sarif` provides a separate
report for GitHub code scanning. Exit codes and JSON are documented in
[contracts](docs/CONTRACTS.md).

When a guard block fires, read its signature and remediation. A legitimate upgrade
may need explicit `accept-drift` with the reported hash; a false positive may need
a scoped policy override. Blocks/warnings are recorded in
`~/.mcpm/guard-events.jsonl`. Pause and mute changes are startup snapshots:
restart the affected server to load changes or resume after a pause expires.
See [guard commands](docs/GUARD.md#all-commands) and [policy](docs/POLICY.md).

## Supported clients

| Adapter | Managed configuration scope |
| --- | --- |
| Claude Desktop | Native user configuration |
| Claude Code | User-global `mcpServers` in `~/.claude.json` |
| Cursor | User-global `~/.cursor/mcp.json` |
| VS Code | User MCP configuration, including JSONC comments/trailing commas |
| Windsurf | User-global MCP configuration |
| Gemini CLI | User-global `~/.gemini/settings.json` |

macOS, Linux and Windows paths are supported by the adapters. Run `mcpm doctor`
for detected configurations. Portable/workspace and Copilot Agent Host paths are
not managed by those adapters; the read-only `scope` inventory has its own fixed
coverage. Unreadable configuration is not evidence of an empty or healthy setup.

Adapter support and native proof are separate. Pinned disposable-client runs
cover named VS Code/Claude Code paths, with separate Cursor and Gemini evidence;
they do not establish all clients/platforms or live-model behavior. Cursor/Gemini
disable parks managed definitions for future discovery; it does not stop running
peers or override project-local/native exclusion state. See
[native scope and platform limits](docs/NATIVE-CLIENT-VALIDATION.md),
[Cursor](docs/CURSOR-CLIENT-VALIDATION.md) and [Gemini](docs/GEMINI-CLIENT-VALIDATION.md).

## Agent use

`mcpm serve` exposes search, info, install, list, remove, audit, doctor, setup and
up through stdio MCP. For clients using an `mcpServers` configuration map:

```json
{
  "mcpServers": {
    "mcpm": {
      "command": "npx",
      "args": ["-y", "@getmcpm/cli@0.52.1", "serve"]
    }
  }
}
```

Other clients use their native schema. This pins the executed CLI; review updates
explicitly. Restart your client after adding the configuration, then ask:

> Find filesystem MCP servers. Explain findings, lifecycle status and checks that
> did not run. Show proposed configuration changes before installing.

Prefer versioned structured evidence, retaining unsupported schema versions,
unrun checks and incomplete coverage as unknown. A successful MCP transport is
not proof that every check passed. Served mutation tools retain trust floors;
CLI-only `scope` and `review-artifacts` are separate inspection surfaces.
See [agent workflows](docs/AGENT-WORKFLOW.md) and [contracts](docs/CONTRACTS.md).

The portable [mcpm usage skill](skills/mcpm/SKILL.md) is self-contained. Copy its
folder from a reviewed, pinned repository checkout into your host's skill
directory. npm ships the CLI, not that skill. It adds no hooks, scripts or tool
grants; discovery, permissions and model compliance depend on the host.

Agent lifecycle hooks cover a different boundary from MCP wire inspection.
Command hooks can also be local and deterministic; some host hooks can deny or
modify tool calls, while post-action hooks cannot undo completed effects. See
[relay, confinement and hook comparison](docs/GUARD.md#runtime-relay-confinement-and-agent-hooks)
for host coverage, failure limits and the bounded native experiments.

## Documentation and contribution

Use the [task-oriented docs index](docs/README.md) for security references,
consumer guides, contribution/release workflows and dated evidence. Current
selected work lives in [BACKLOG](docs/BACKLOG.md); older roadmaps retain historical
planning context.

For source setup and appropriate checks, read [CONTRIBUTING](CONTRIBUTING.md).
Contributor instructions/skills are repo-owned and separate from the distributed
usage skill. Security findings should go through
[private vulnerability reporting](https://github.com/getmcpm/cli/security/advisories/new);
scanner false-positive/negative reports can use ordinary GitHub issues.
See [SECURITY](SECURITY.md) for the reporting policy.

[MIT license](LICENSE).
