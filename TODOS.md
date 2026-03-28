# TODOS

## Resolved Blockers

### 1. ~~Verify Official MCP Registry API~~ DONE (2026-03-28)
**Resolution:** API verified. Use **v0.1** (not v0). Key findings:
- Search param is `search` (not `q`), substring match on name only
- No full-text search — need client-side description filtering
- `environmentVariables` is inside `packages[]`, not top-level
- Pagination: `cursor` + `limit` (max 100), `metadata.nextCursor`
- `packages[]` confirmed: `registryType` = `npm | pypi | oci`
- `_meta` has `status`, `publishedAt`, `updatedAt`, `isLatest`

### 2. ~~Resolve npm Package Name~~ DONE (2026-03-28)
**Resolution:** npm package name = `mcpm-cli`, bin command = `mcpm`.
- `mcpm` taken (Minecraft Package Manager)
- `mcpx`, `mcp-pm`, `mcp-registry`, `mcpman` all taken
- `mcpm-cli` is available and follows `{tool}-cli` convention

## Pre-launch

### 3. Config Backup-Before-Write
**Priority:** P1
**What:** Before atomic config write, copy existing config to ~/.mcpm/backups/{client}.{timestamp}.json. Keep last 5 backups.
**Why:** If a config write produces malformed JSON, Claude Desktop/Cursor may fail to parse and lose all MCP server configs. Backup enables recovery.
**Depends on:** Config adapter implementation.

### 4. Cross-Platform Config Paths
**Priority:** P1
**What:** Add Linux and Windows paths to config/paths.ts for all supported clients.
**Why:** Plan only specifies macOS paths. Linux devs (large HN audience) will hit errors on launch.
**How:** Linux: `~/.config/Claude/`, `~/.config/Code/User/`. Windows: `%APPDATA%/Claude/`, `%APPDATA%/Code/User/`. Verify Cursor and Windsurf paths on each platform.
**Depends on:** Config adapter implementation.

## Post-V1

### 5. Optional Anonymous Telemetry
**Priority:** P2
**What:** Add opt-in anonymous telemetry (install count, command usage, error types).
**Why:** After V1 launch, you'll want to know adoption patterns. V1 skips this to avoid trust paradox ("security tool that tracks you").
**How:** Simple opt-in on first run. Anonymous counters only. No PII, no server names.
**Depends on:** V1 launch, established trust.
