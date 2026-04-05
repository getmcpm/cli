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
**Resolution:** npm package name = `@getmcpm/cli`, bin command = `mcpm`.
- `mcpm` taken (Minecraft Package Manager)
- `mcpx`, `mcp-pm`, `mcp-registry`, `mcpman` all taken
- `@getmcpm/cli` is available and follows `{tool}-cli` convention

## Pre-launch

### 3. ~~Config Backup-Before-Write~~ DONE (2026-04-06)
**Resolution:** Implemented in BaseAdapter.writeAtomic (base.ts:49). Writes .bak file before every atomic write. mcpm up takes a single .bak snapshot before batch starts (up.ts:223).

### 4. Cross-Platform Config Paths
**Priority:** P1
**What:** Add Linux and Windows paths to config/paths.ts for all supported clients.
**Why:** Plan only specifies macOS paths. Linux devs (large HN audience) will hit errors on launch.
**How:** Linux: `~/.config/Claude/`, `~/.config/Code/User/`. Windows: `%APPDATA%/Claude/`, `%APPDATA%/Code/User/`. Verify Cursor and Windsurf paths on each platform.
**Depends on:** Config adapter implementation.

## Security (from CSO audit 2026-03-29)

### 5. ~~Pin GitHub Actions to SHA hashes~~ DONE (2026-03-30)
**Resolution:** All actions in ci.yml and publish.yml pinned to full SHA hashes with `# v4` comments.

### 6. ~~Add CODEOWNERS for workflow files~~ DONE (2026-03-30)
**Resolution:** Created `.github/CODEOWNERS` requiring `@getmcpm/maintainers` review for `.github/workflows/` changes. Note: branch protection rules must be enabled in GitHub settings for enforcement.

### 7. ~~Set chmod 600 on config files containing secrets~~ DONE (2026-03-30)
**Resolution:** Added `mode: 0o600` to writeFile and `mode: 0o700` to mkdir in BaseAdapter.writeAtomic and store/index.ts.

### 8. ~~Add timeout to external scanner subprocess~~ DONE (2026-03-30)
**Resolution:** Added `timeout: 30_000` to execFileAsync in tier2.ts defaultExec.

### 9. ~~Switch validateRuntimeArgs from blocklist to allowlist~~ DONE (2026-03-30)
**Resolution:** Replaced dangerous-flag blocklist with SAFE_ARG_PATTERNS allowlist. Only known-safe patterns (--port, --host, --transport, --verbose, etc.) are permitted. All unknown flags including --loader, --experimental-loader are now rejected.

### 10. ~~Apply NFKC normalization before scanner pattern matching~~ DONE (2026-03-30)
**Resolution:** Added `text.normalize("NFKC")` to detectSecrets and detectPromptInjection. Extended zero-width char detection to cover `\u202A-\u202F\u2028\u2029`.

### 11. ~~Scan server.title, remote headers, and runtimeArgs for injection~~ DONE (2026-03-30)
**Resolution:** Extended scanTier1 to scan server.title, remote header descriptions, and package runtimeArguments for prompt injection.

### 12. ~~Cap registryMeta trust score when critical findings present~~ DONE (2026-03-30)
**Resolution:** Added `hasCriticalOrHighFindings()` check in computeTrustScore. registryMeta bonus is zeroed when critical or high severity findings are present.

### 13. ~~Tighten server name regex in tier2.ts~~ DONE (2026-03-30)
**Resolution:** Updated SERVER_NAME_RE to require alphanumeric chars at both start and end of each segment (no leading/trailing hyphens or dots).

## Post-V1

### 15. Encrypted Secret Storage for Stack Files
**Priority:** P2
**What:** Investigate alternatives to plaintext env var storage in client config files. Options: OS keychain integration, encrypted .env files, reference-only storage (pointer to secret manager).
**Why:** Stack files scale team-wide. Every `mcpm up` writes secrets as plaintext JSON to client configs. With 5+ servers each needing API keys, that's 5+ plaintext secrets per developer per IDE.
**Context:** Current approach (plaintext + chmod 600) is the npm/pip norm. But mcpm positions as a security tool. Plaintext secrets in 4 config files per machine is inconsistent with that positioning. Not blocking for V1.3 but matters for enterprise adoption.
**Depends on:** V1.3 stack files (shipped).

### 14. Optional Anonymous Telemetry
**Priority:** P2
**What:** Add opt-in anonymous telemetry (install count, command usage, error types).
**Why:** After V1 launch, you'll want to know adoption patterns. V1 skips this to avoid trust paradox ("security tool that tracks you").
**How:** Simple opt-in on first run. Anonymous counters only. No PII, no server names.
**Depends on:** V1 launch, established trust.
