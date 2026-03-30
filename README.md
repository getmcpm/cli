<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./assets/banner-light.svg">
    <img alt="mcpm - the MCP package manager" src="./assets/banner-light.svg" width="680">
  </picture>
</p>

# mcpm

**MCP package manager -- search, install, and audit MCP servers from your terminal.**

[![npm version](https://img.shields.io/npm/v/@getmcpm/cli)](https://www.npmjs.com/package/@getmcpm/cli)
[![license](https://img.shields.io/github/license/getmcpm/cli)](./LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/getmcpm/cli/ci.yml?label=tests)](https://github.com/getmcpm/cli/actions)
[![Known Vulnerabilities](https://snyk.io/test/github/getmcpm/cli/badge.svg)](https://snyk.io/test/github/getmcpm/cli)

---

66% of MCP servers have security findings ([AgentSeal scan](https://agentseal.com)). Most registries don't tell you that. mcpm runs a trust assessment on every install -- checking for hardcoded secrets, prompt injection patterns, typosquatting, and suspicious argument schemas -- so you know what you're adding to your AI tools before it runs.

<p align="center">
  <img src="./assets/demo.gif" alt="mcpm demo" width="680">
</p>

## Quick start

```bash
npm install -g @getmcpm/cli

mcpm search filesystem
mcpm info io.github.domdomegg/filesystem-mcp
mcpm install io.github.domdomegg/filesystem-mcp
```

## Features

### Search the MCP registry

Query the official MCP Registry and see results with trust indicators.

```
$ mcpm search filesystem

  Name                                              Description                    Score
  io.github.domdomegg/filesystem-mcp                 File system access via MCP     82/100
  io.github.Digital-Defiance/mcp-filesystem           Read-only filesystem server    67/100
  ...
```

### Install with trust assessment

Every install runs a metadata-based trust assessment before writing config.

```
$ mcpm install io.github.domdomegg/filesystem-mcp

  Trust Score: 82/100 (safe)
    Health check:    30/30
    Static scan:     32/40
    External scan:    —  (install mcp-scan for full coverage)
    Registry meta:   10/10

  Install to Claude Desktop? (Y/n)
```

### Audit installed servers

Scan everything you have installed. Get a trust report.

```
$ mcpm audit

  Server                                   Client          Score   Level
  servers-filesystem                        Claude Desktop  82/100  safe
  servers-github                            Cursor          74/100  caution
  some-sketchy-server                       VS Code         31/100  risky
```

### Cross-IDE support

One tool for all your AI clients. mcpm reads and writes the correct config format for each.

```
$ mcpm list

  Claude Desktop (2 servers)
    servers-filesystem
    servers-github

  Cursor (1 server)
    servers-fetch
```

### Doctor: check your MCP setup health

Find misconfigurations, missing runtimes, and broken servers.

```
$ mcpm doctor

  Checking MCP setup...
  [pass] Claude Desktop config found
  [pass] Node.js >= 20.0.0
  [warn] Cursor config not found
  [pass] 3 servers installed, 0 with errors
```

### Starter packs

Get a working MCP setup in one command.

```
$ mcpm init developer

  Installing 'developer' pack: Essential developer tools
    Installing servers-filesystem... done
    Installing servers-git... done
    Installing servers-github... done
  Installed 3/3 servers.
```

Available packs: `developer` (filesystem, git, GitHub), `data` (PostgreSQL, SQLite), `web` (HTTP fetch, Puppeteer).

## Trust score

The trust score is a 0-100 assessment based on publicly available metadata. It is **not** a source code audit.

What it checks:

| Component | Points | What it measures |
|---|---|---|
| Health check | 0-30 | Can the server start and respond to `list_tools`? |
| Static scan | 0-40 | Regex-based detection of hardcoded secrets, prompt injection patterns in tool descriptions, typosquatting in package names, suspicious argument schemas |
| External scanner | 0-20 | Results from [MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) if installed (optional) |
| Registry metadata | 0-10 | Verified publisher, publish date, download count (capped to 0 when critical findings present) |

Levels: **safe** (80+), **caution** (50-79), **risky** (below 50).

Without an external scanner installed, the maximum possible score is 80/100. The static scan catches common patterns but cannot detect all vulnerabilities. Treat the score as a signal, not a guarantee.

## Commands

| Command | Description |
|---|---|
| `mcpm search <query>` | Search the MCP registry for servers |
| `mcpm install <name>` | Install an MCP server from the registry |
| `mcpm info <name>` | Show full details for an MCP server |
| `mcpm list` | List all installed MCP servers across detected AI clients |
| `mcpm remove <name>` | Remove an MCP server from client config(s) |
| `mcpm audit` | Scan all installed servers and produce a trust report |
| `mcpm update` | Check for newer versions and update installed servers |
| `mcpm doctor` | Check MCP setup health and report issues |
| `mcpm init <pack>` | Install a curated starter pack of MCP servers |
| `mcpm import` | Import existing MCP servers from client config files |
| `mcpm serve` | Start mcpm as an MCP server (stdio transport) |

Run `mcpm <command> --help` for options and flags.

## Agent mode

mcpm can run as an MCP server itself, letting AI agents search, install, and audit MCP servers programmatically.

```json
{
  "mcpServers": {
    "mcpm": {
      "command": "npx",
      "args": ["-y", "@getmcpm/cli", "serve"]
    }
  }
}
```

This exposes 8 tools: `mcpm_search`, `mcpm_install`, `mcpm_info`, `mcpm_list`, `mcpm_remove`, `mcpm_audit`, `mcpm_doctor`, and `mcpm_setup`.

The `mcpm_setup` tool takes a natural language description like "filesystem and GitHub" and handles everything: search, trust scoring, install. One tool call to assemble a working MCP toolchain.

**Try it** -- add the config above to your MCP client, restart, then ask your agent:

> You have mcpm tools available (from @getmcpm/cli, the MCP package manager, not the Minecraft one). Use them to find MCP servers for filesystem access and GitHub. Check their trust scores and install anything above 60.

## Supported clients

| Client | Config path (macOS) |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Linux and Windows paths are also supported. See `mcpm doctor` to verify which clients are detected on your system.

## How it works

mcpm is a local-first CLI. There is no mcpm backend or account system.

1. **Search and install** query the [official MCP Registry API](https://registry.modelcontextprotocol.io) (v0.1) maintained by the Model Context Protocol project.
2. **Trust assessment** runs locally using built-in scanners (regex-based pattern detection) and optionally wraps [MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) for deeper analysis.
3. **Config management** reads and writes the native config file for each AI client. All writes use atomic file operations with restricted permissions (0o600 files, 0o700 directories).
4. **Local state** lives in `~/.mcpm/` (installed server registry, scan results, response cache).

No telemetry. No analytics. No account required.

## Contributing

Contributions are welcome.

```bash
git clone https://github.com/getmcpm/cli.git
cd cli
pnpm install
pnpm test
pnpm build
```

Before submitting a PR:

- Run `pnpm test` and ensure all tests pass
- Run `pnpm lint` to check types
- Keep commits focused -- one change per commit
- Follow [conventional commit](https://www.conventionalcommits.org/) format

This project is MIT licensed. See [LICENSE](./LICENSE).

## Security

If you discover a security vulnerability, please use [GitHub's private vulnerability reporting](https://github.com/getmcpm/cli/security/advisories/new) instead of opening a public issue. We will respond within 48 hours.

For trust assessment issues (false positives/negatives in the scanner), regular GitHub issues are fine.

## License

[MIT](./LICENSE)
