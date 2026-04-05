# mcpm — Architecture

## Project Structure

```
mcpm/
├── src/
│   ├── index.ts                    — CLI entry point (Commander)
│   ├── commands/
│   │   ├── index.ts                — command registration
│   │   ├── search.ts               — search the MCP registry
│   │   ├── install.ts              — install a server to client configs
│   │   ├── info.ts                 — show server details
│   │   ├── list.ts                 — list installed servers
│   │   ├── remove.ts               — remove a server from configs
│   │   ├── audit.ts                — trust-scan installed servers
│   │   ├── update.ts               — update installed servers
│   │   ├── doctor.ts               — check MCP setup health
│   │   ├── init.ts                 — install a curated starter pack
│   │   ├── import.ts               — import servers from client config
│   │   ├── serve.ts                — start mcpm as an MCP server
│   │   ├── disable.ts              — disable a server (thin wrapper over toggle)
│   │   ├── enable.ts               — re-enable a disabled server
│   │   ├── toggle.ts               — shared disable/enable logic
│   │   ├── completions.ts          — shell completion scripts (bash/zsh/fish)
│   │   └── alias.ts                — short aliases for server names
│   ├── server/
│   │   ├── index.ts                — MCP server setup (registerTool, stdio transport)
│   │   ├── tools.ts                — Zod input schemas for each tool
│   │   └── handlers.ts             — tool handlers (wraps existing CLI logic)
│   ├── registry/
│   │   ├── client.ts               — RegistryClient (HTTP, injectable fetch)
│   │   ├── schemas.ts              — Zod schemas for API responses
│   │   ├── types.ts                — inferred TypeScript types
│   │   ├── pagination.ts           — async cursor-based pagination
│   │   └── errors.ts               — RegistryError, NotFoundError, NetworkError
│   ├── config/
│   │   ├── paths.ts                — OS-aware config file paths
│   │   ├── detector.ts             — detect installed AI clients
│   │   └── adapters/
│   │       ├── base.ts             — shared adapter logic
│   │       ├── claude-desktop.ts
│   │       ├── cursor.ts
│   │       ├── vscode.ts
│   │       ├── windsurf.ts
│   │       └── factory.ts          — adapter factory by client ID
│   ├── scanner/
│   │   ├── trust-score.ts          — 0-100 composite trust score
│   │   ├── tier1.ts                — metadata-based checks (registry meta)
│   │   ├── tier2.ts                — static pattern scanning
│   │   └── patterns.ts             — regex patterns for secrets, injection, typosquatting
│   ├── store/
│   │   ├── index.ts                — local state manager (~/.mcpm/)
│   │   ├── servers.ts              — installed server registry
│   │   ├── cache.ts                — HTTP response cache
│   │   └── aliases.ts              — server name aliases (~/.mcpm/aliases.json)
│   └── utils/
│       ├── output.ts               — leveled output helpers
│       ├── confirm.ts              — confirmation prompts
│       ├── format-entry.ts         — format MCP server config entries
│       └── format-trust.ts         — format trust score display
├── src/__tests__/
│   ├── commands/                    — 16 command test files
│   ├── config/                      — adapter + detector + paths tests
│   └── store/                       — cache + servers + store tests
├── scripts/
│   └── demo.sh                     — asciinema demo recording script
├── .github/workflows/
│   ├── ci.yml                      — build + test on push/PR (Node 20, 22, 24)
│   └── publish.yml                 — npm publish + GitHub Release on v* tags (Node 24)
├── package.json                    — @getmcpm/cli, bin: mcpm
├── tsconfig.json
├── tsup.config.ts                  — bundler config
└── vitest.config.ts                — test config with coverage thresholds
```

## Modules

| Module | Purpose |
|---|---|
| `commands/` | 15 CLI commands, each a self-contained Commander action |
| `server/` | MCP server (stdio): 8 tools wrapping CLI logic via injectable handlers |
| `registry/` | Typed HTTP client for the official MCP Registry API (v0.1 at registry.modelcontextprotocol.io) |
| `config/` | OS-aware config paths, client detection, and per-client config adapters with atomic writes |
| `scanner/` | Trust scoring engine: tier 1 (metadata), tier 2 (static pattern analysis), composite score |
| `store/` | Local state in `~/.mcpm/` — installed server registry, HTTP response cache, server name aliases |
| `utils/` | Output formatting, confirmation prompts, trust display helpers |

## Commands

| Command | Description |
|---|---|
| `mcpm search <query>` | Search the MCP registry for servers |
| `mcpm install <name>` | Install an MCP server to detected client configs |
| `mcpm info <name>` | Show full details for an MCP server |
| `mcpm list` | List all installed servers across detected AI clients |
| `mcpm remove <name>` | Remove a server from client config(s) |
| `mcpm audit` | Scan all installed servers and produce a trust report |
| `mcpm update` | Check for newer versions and update installed servers |
| `mcpm doctor` | Check MCP setup health (runtimes, configs, servers) |
| `mcpm init <pack>` | Install a curated starter pack of MCP servers |
| `mcpm disable <name>` | Disable a server without removing it from config |
| `mcpm enable <name>` | Re-enable a previously disabled server |
| `mcpm import` | Import existing servers from client config files |
| `mcpm alias` | Create short aliases for long server names |
| `mcpm completions <shell>` | Generate shell completion scripts (bash, zsh, fish) |
| `mcpm serve` | Start mcpm as an MCP server (stdio transport) |

## Data Flow

```
mcpm install io.github.domdomegg/filesystem-mcp
  │
  ▼
RegistryClient.getServer(name)
  │  GET https://registry.modelcontextprotocol.io/v0.1/servers/{name}
  │  Response → Zod parse → typed Server object
  ▼
detectInstalledClients()
  │  Check config file existence for each client on current OS
  ▼
resolveInstallEntry(server, client)
  │  Pick transport: HTTP remote (if client supports) or stdio
  │  stdio: npm → npx, pypi → uvx, oci → docker run
  ▼
scanner.computeTrustScore(server)
  │  Tier 1: registry metadata (verified publisher, age, downloads)
  │  Tier 2: static patterns (secrets, injection, typosquatting)
  │  Optional: MCP-Scan external scanner
  ▼
Prompt for env vars + confirmation
  ▼
adapter.addServer(configPath, name, entry)
  │  Read config → merge → write to .tmp → atomic rename
  ▼
store.recordInstall(name, clients, version)
  │  Write to ~/.mcpm/servers.json
```

## Configuration

### Local state directory

```
~/.mcpm/
├── servers.json       — installed server registry (name, version, clients, install date)
├── aliases.json       — short aliases for server names
└── cache/             — HTTP response cache (TTL-based)
```

### Client config paths (macOS)

| Client | Config path |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Linux and Windows paths are also supported. Config key: `mcpServers` (Claude Desktop, Cursor) or `servers` (VS Code).

All config writes use atomic file operations (write to `.tmp`, then `fs.rename`). Files are written with `mode: 0o600` and directories with `mode: 0o700` to restrict access.

## Testing

- **Framework**: vitest with `@vitest/coverage-v8`
- **Test count**: 739+ tests
- **Coverage thresholds**: lines 80%, branches 75%
- **Test locations**: `src/__tests__/` (command, config, store tests) + colocated `*.test.ts` (registry, scanner)
- **Approach**: injectable `fetchImpl` for registry tests (no network calls), temp directories for config adapter tests

Run tests:

```bash
pnpm test              # run all tests
pnpm test:coverage     # run with coverage report
pnpm test:watch        # watch mode
```

## CI/CD

### CI (`ci.yml`)

Runs on push to `main` and pull requests. Matrix: Node 20, 22, 24. All GitHub Actions are SHA-pinned.

Steps: `pnpm install --frozen-lockfile` → `typecheck` → `build` → `test:coverage`

### Publish (`publish.yml`)

Runs on `v*` tag push. Builds, tests, and publishes to npm as `@getmcpm/cli` with provenance.

