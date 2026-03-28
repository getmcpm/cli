# mcpm MVP — CLI Implementation Plan

## Context

The repo is a greenfield project (only `CLAUDE.md` exists). We are building "npm for MCP servers" — an open-source CLI tool that lets developers search, install, and manage MCP servers across Claude Desktop, Cursor, VS Code, and Windsurf from a single command.

**Decisions confirmed by user:**
- Build the CLI first (not web UI or backend)
- Back it with the official MCP Registry API v0.1 (registry.modelcontextprotocol.io)
- Single package (not monorepo) — registry client as internal module
- npm package: `@getmcpm/cli`, bin command: `mcpm`

**Registry API findings (verified 2026-03-28):**
- Use `/v0.1/servers` (not v0) — v0.1 has `search` and `version` params
- Search: `?search=<name>` — substring match on server name only, NOT full-text
- Pagination: `?cursor=<token>&limit=<n>` (max 100), response has `metadata.nextCursor`
- `environmentVariables` is inside `packages[]`, not top-level
- `_meta.io.modelcontextprotocol.registry/official` has `status`, `publishedAt`, `isLatest`

---

## Repository Structure

```
mcpm/
├── packages/
│   ├── registry-client/   — typed API client for registry.modelcontextprotocol.io
│   │   └── src/
│   │       ├── index.ts
│   │       ├── client.ts        — RegistryClient class
│   │       ├── schemas.ts       — Zod schemas (foundation for all types)
│   │       ├── types.ts         — z.infer'd TypeScript types
│   │       ├── pagination.ts    — async cursor iterator
│   │       └── errors.ts        — RegistryError, NotFoundError, NetworkError
│   └── cli/
│       └── src/
│           ├── index.ts              — Commander entry point, bin: mcpm
│           ├── commands/
│           │   ├── search.ts
│           │   ├── install.ts        — most complex command
│           │   ├── list.ts
│           │   ├── remove.ts
│           │   └── info.ts
│           ├── config/
│           │   ├── paths.ts          — OS-aware config file paths
│           │   ├── detector.ts       — detect installed AI clients
│           │   └── adapters/
│           │       ├── index.ts      — ConfigAdapter interface
│           │       ├── claude-desktop.ts
│           │       ├── cursor.ts
│           │       ├── vscode.ts
│           │       └── windsurf.ts   — behind --experimental flag
│           ├── install/
│           │   ├── resolver.ts       — server → McpServerEntry for client
│           │   ├── npm.ts
│           │   ├── pypi.ts
│           │   ├── docker.ts
│           │   └── http.ts
│           ├── prompt/
│           │   └── env-vars.ts       — readline prompts for required env vars
│           ├── output/
│           │   ├── formatter.ts      — chalk + cli-table3, all formatting here
│           │   ├── spinner.ts        — ora wrapper (respects --quiet)
│           │   └── logger.ts         — leveled output, no console.log elsewhere
│           └── errors/
│               └── handler.ts        — top-level error → exit code mapping
├── package.json          — pnpm workspace root (private: true)
├── pnpm-workspace.yaml
├── tsconfig.base.json    — strict, moduleResolution: bundler, target: ES2022
└── .github/workflows/
    ├── ci.yml
    └── publish.yml
```

---

## Phase 0 — Workspace Scaffolding

Root `package.json`: pnpm workspace, `engines: { node: ">=20.0.0" }`, scripts: `build`, `test`, `lint`, `typecheck`.

`tsconfig.base.json`: strict mode, `moduleResolution: bundler`, `target: ES2022`, `module: NodeNext`.

Both packages: `"type": "module"`, extend base tsconfig, own `vitest.config.ts` with `coverage.thresholds: { lines: 80, branches: 75 }`.

CLI `package.json`: `bin: { mcpm: "./dist/index.js" }`, postbuild script to prepend shebang.

---

## Phase 1 — Registry Client Package

**Foundation**: Zod schemas in `schemas.ts` are the single source of truth for all types.

Key schemas:
- `ServerSchema` — `name` (namespace/server), `description`, `version`, `packages[]`, `remotes[]`, `_meta`
- `PackageSchema` — discriminated union on `registryType`: `npm | pypi | oci`
- `EnvVarSchema` — `name`, `description`, `required`, `default`
- `RemoteSchema` — `type` (streamable-http | sse), `url`, `headers[]`, `variables`
- `SearchResponseSchema` — `servers[]`, `metadata.nextCursor`

`RegistryClient` constructor accepts `{ baseUrl?, fetchImpl?, timeout? }` — `fetchImpl` is injectable for tests (no network calls in tests).

Public methods:
```typescript
searchServers(query: string, limit?: number): Promise<Server[]>
listServers(cursor?: string): Promise<PageResult<Server>>
getServer(name: string): Promise<Server>
getServerVersions(name: string): Promise<ServerVersion[]>
```

Error hierarchy: `RegistryError` → `NetworkError`, `NotFoundError`, `ValidationError`.

`pagination.ts`: `async function* paginate(client, limit)` — wraps cursor loop.

**Tests** (`90%+ coverage`): inject `vi.fn()` as `fetchImpl`, test all error branches, pagination stop condition, Zod parse of all discriminated union variants.

---

## Phase 2 — CLI Config Infrastructure

### Config paths (`config/paths.ts`)
One function per client, platform-aware via `process.platform` + `os.homedir()`:

| Client | macOS path |
|--------|-----------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

### `ConfigAdapter` interface
```typescript
interface ConfigAdapter {
  clientId: ClientId;
  read(configPath: string): Promise<Record<string, McpServerEntry>>;
  addServer(configPath: string, name: string, entry: McpServerEntry): Promise<void>;
  removeServer(configPath: string, name: string): Promise<void>;
  listServers(configPath: string): Promise<Record<string, McpServerEntry>>;
}
```

All adapters use **atomic writes** (write to `.tmp`, then `fs.rename`). Root key differs: Claude Desktop + Cursor use `mcpServers`, VS Code uses `servers`.

`McpServerEntry`: `{ command?, args?, env?, url?, headers? }` — stdio format or HTTP format.

### Install resolver (`install/resolver.ts`)
Decision tree (pure function, no I/O):
1. Cursor + server has HTTP remote → produce `{ url, headers }` entry
2. Otherwise pick from `packages[]`: npm → pypi → oci
3. npm: `{ command: 'npx', args: ['-y', packageName, ...runtimeArgs], env }`
4. pypi: `{ command: 'uvx', args: [packageName, ...runtimeArgs], env }`
5. docker: `{ command: 'docker', args: ['run', '--rm', '-i', image], env }`

Tooling availability (`npx`, `uvx`, `docker`) checked via `which` once per process, cached.

---

## Phase 3 — Five Commands

### `mcpm search <query>`
Spinner → `RegistryClient.searchServers()` → cli-table3 table (Name | Description | Version | Transport | Status). Options: `--limit <n>`, `--json`.

### `mcpm info <name>`
Fetch server → display full details: name, version, repo URL, packages, env vars (required flag, description), transport. Footer: `mcpm install <name>`.

### `mcpm install <name>` ← most complex
1. Fetch server from registry
2. Detect installed clients (`detectInstalledClients()`)
3. If multiple clients: checkbox prompt (all selected by default); skip with `--client <id>`
4. Per client: `resolveInstallEntry()` → prompt for required env vars → show preview JSON → confirm
5. Check if already installed → error unless `--force`
6. `adapter.addServer()` atomically
7. Options: `--client <id>`, `--yes`, `--force`

### `mcpm list`
Read-only — never calls registry. Detect clients → read each config → unified table (Client | Server Name | Command/URL). Options: `--client <id>`, `--json`.

### `mcpm remove <name>`
Find in which clients → checkbox to pick which → confirm → `adapter.removeServer()`. Options: `--yes`.

---

## Phase 4 — Entry Point

`index.ts`: ~30 lines. Commander program, `registerSearch/Install/List/Remove/Info(program)`, `.parseAsync().catch(handleError)`.

`errors/handler.ts`: `NotFoundError` → exit 1, `NetworkError` → exit 2, `ValidationError` → exit 3, unknown → exit 99 (stack only with `--verbose`).

---

## Phase 5 — Tests

**registry-client**: inject `fetchImpl: vi.fn()`, fixture JSON per test. Cover all error branches, pagination, Zod parse of all package type variants. Target: 90%.

**cli unit tests**: mock `fs.access` (detector), mock `fs.readFile/writeFile` (adapters), mock `process.platform` (paths), pure function tests on resolver's 5 branches. Use `memfs` for adapter tests.

**cli command tests**: inject mock `RegistryClient`, use `os.tmpdir()` real temp files for integration. Assert stdout content, exit codes, config file mutations.

Coverage gate: `{ lines: 80, branches: 75 }` enforced in vitest config.

---

## Phase 6 — Packaging & CI

`postbuild`: prepend `#!/usr/bin/env node` to `dist/index.js`.

CI: push/PR → `pnpm install` → `build` → `test` → `lint`.

Publish: tag `v*` → build → test → `pnpm publish` (both packages).

---

## Key Dependencies

| Package | Package | Purpose |
|---------|---------|---------|
| `zod` | registry-client | API schema validation |
| `commander` | cli | CLI framework |
| `chalk` | cli | Terminal colors |
| `ora` | cli | Spinners |
| `cli-table3` | cli | Tables |
| `vitest` + `@vitest/coverage-v8` | both (dev) | Tests |

No `inquirer` — use Node `readline` stdlib for env-var prompts. No bundler — Node 20 native ESM is sufficient for MVP.

---

## Risks

| Risk | Mitigation |
|------|-----------|
| `@mcpm/cli` npm name taken | Publish as `mcp-registry` initially; approach mcp-club for collaboration |
| Windsurf config format unconfirmed | Ship behind `--experimental` flag |
| Official registry schema changes | `zod.safeParse` surfaces errors explicitly; graceful degradation |
| User has no supported runtime (no npx/uvx/docker) | Detect before install, print clear install instructions |

---

## Verification Plan

1. `pnpm install && pnpm build` — clean build, no TypeScript errors
2. `pnpm test` — all tests pass, coverage thresholds met
3. `node packages/cli/dist/index.js search filesystem` — returns table of results
4. `node packages/cli/dist/index.js info io.github.modelcontextprotocol/servers-filesystem` — shows details
5. `node packages/cli/dist/index.js install io.github.modelcontextprotocol/servers-filesystem --yes` — writes correct entry to Claude Desktop config, verify with `cat ~/Library/Application\ Support/Claude/claude_desktop_config.json`
6. `node packages/cli/dist/index.js list` — shows the installed server
7. `node packages/cli/dist/index.js remove servers-filesystem --yes` — removes it, verify config is clean
8. `npm pack` in `packages/cli/` — verify tarball contents, test local install with `npm install -g ./mcp-registry-0.1.0.tgz`

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAR | 5 proposals, 5 accepted, 0 deferred |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR (PLAN) | 7 issues, 1 critical gap |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |

- **UNRESOLVED:** 0
- **VERDICT:** CEO + ENG CLEARED — ready to implement. Resolve P0 blockers in TODOS.md first (API verification, npm name).
