# MCP Registry — Project Context

> This file is automatically read by Claude Code on every session.
> Keep it updated as decisions are made. Last updated: 2026-06-20.

---

## What We're Building

An open-source, CLI-first MCP package manager — **"npm for MCP servers"**.

A registry where developers can search, install, audit, publish, and update MCP servers
across all major clients (Claude Desktop, Cursor, VS Code, Windsurf) from a single tool.

**npm package**: `@getmcpm/cli` (v0.14.0) | **bin command**: `mcpm` | **repo**: github.com/getmcpm/cli | **web UI**: deferred to V1+

---

## The Problem We're Solving

The MCP ecosystem has 5,800+ servers and 185M+ monthly SDK downloads, but:

- Servers are scattered across GitHub, npm, PyPI, and personal blogs
- No standardized validation — you don't know if a server works
- No security signals — 66% of servers have security findings (AgentSeal scan)
- No universal installer — each IDE uses different config formats
- No ratings, reviews, or community quality signals on any existing platform
- Discovery is word-of-mouth or Reddit threads

---

## Validated Market Insights

### Ecosystem Scale (as of March 2026)

- 185M+ combined monthly SDK downloads (Anthropic figure)
- Python SDK: 161.5M monthly downloads on PyPI
- TypeScript SDK: ~24.5M monthly downloads on npm
- 36,864 npm projects depend on the TypeScript SDK
- `modelcontextprotocol/servers` repo: 76,000 GitHub stars
- 5,800+ production-grade servers (873% growth in 8 months)
- Adopted by OpenAI, Microsoft, Google, AWS, Cloudflare, Bloomberg
- MCP donated to Linux Foundation's Agentic AI Foundation (AAIF) in Dec 2025

### Key Security Findings (validate our security scanning angle)

- AgentSeal: 66% of 1,808 scanned servers had security findings
- Astrix: 88% require credentials, 53% use insecure static secrets
- Cornell study: 5.5% of servers had tool-poisoning vulnerabilities
- Docker: 43% had command injection flaws
- Real incidents: Postmark MCP infostealer (1,643 downloads), RCE in `mcp-remote`
  affecting 437,000+ downloads

### Developer Pain (documented evidence)

- GitHub blog: "MCP servers scattered across numerous registries, random repos, buried
  in community threads"
- DEV.to: "Imagine if npm didn't exist... That's where MCP is right now"
- VS Code's Harald Kirschner: "copying around JSON blobs and hard-coding API keys"
- GitHub issues: silent MCP server failures with no helpful error messages

---

## Competitive Landscape

### Direct Competitors

| Player                | Strength                                  | Weakness                                       | Threat Level                       |
| --------------------- | ----------------------------------------- | ---------------------------------------------- | ---------------------------------- |
| Official MCP Registry | Authority, Anthropic-backed               | Intentionally minimal, no UI, no curation      | Low — they want us to build on top |
| Smithery.ai           | CLI, hosted execution, 2,880+ servers     | No security scanning, VC-backed centralization | Medium                             |
| mcp.so                | Volume (19,075 servers)                   | Quality problems, duplicates, no CLI           | Low                                |
| Glama.ai              | Deduplication, basic scanning             | Single-maintainer, no CLI                      | Low                                |
| PulseMCP              | Best metadata enrichment, 12,870+ servers | No install tooling                             | Low                                |
| JFrog MCP Registry    | Enterprise governance, security scanning  | $532M company, enterprise pricing, not OSS     | High (enterprise)                  |
| GitHub MCP Gallery    | VS Code integration, curated              | IDE-locked, Microsoft-controlled               | Medium                             |

### VC-Backed Players to Watch

- **Runlayer** — $11M seed (Khosla + Felicis), MCP security gateway
- **Alpic** — €5.1M pre-seed (Partech), MCP-native cloud platform
- **Manufact** (mcp-use) — $6.3M YC S25, enterprise MCP infra

### Key Insight on Official Registry

The official MCP Registry is **intentionally a meta-registry** — it stores metadata only,
no UI, no curation, and explicitly invites "subregistries" to build on top. This is the
green light we need.

---

## Strategic Positioning

### Our Lane: Developer Experience + Security (Lanes 1 + 2)

Build the **open-source, community-owned npm+npm_audit** for MCP:

- CLI-first (search, install, audit, update, publish)
- Integrated security scanning in the publish pipeline
- Community quality signals (ratings, reviews — missing everywhere)
- Works across Claude Desktop, Cursor, VS Code, Windsurf
- OSS and community-owned — differentiated vs Smithery (VC) and JFrog (enterprise)

### What We Are NOT Building (yet)

- Hosted execution (Smithery's lane)
- Enterprise governance/policy enforcement (JFrog's lane)
- A closed/VC-backed product

### Monetization Path (proven playbook from npm/JFrog/Docker)

1. Free public registry + CLI (loss leader, drives adoption)
2. Private/enterprise registry with SSO + audit logs ($15–50/user/month)
3. Premium security scanning as add-on
4. Hosted MCP server execution (per-invocation billing) — V2

---

## Tech Stack Decisions

### CLI (`mcpm`) — V1 / MVP

- **Runtime**: Node.js (>=22.0.0), TypeScript, ESM
- **npm package**: `@getmcpm/cli` (bin command: `mcpm`)
- **CLI framework**: Commander.js
- **Schema validation**: Zod (single source of truth for all types)
- **Prompts**: @inquirer/prompts (trust score UX, multi-select, confirmations)
- **Output**: chalk + cli-table3
- **Local storage**: JSON files in `~/.mcpm/` (servers.json, aliases.json, cache/)
- **Testing**: Vitest + @vitest/coverage-v8 (80% line, 75% branch thresholds)
- **Build**: tsup (TypeScript → JS)
- **MCP server**: `mcpm serve` exposes 9 tools via `@modelcontextprotocol/sdk` (stdio transport)
- **Commands**: `mcpm search`, `mcpm install`, `mcpm list`, `mcpm remove`, `mcpm info`,
  `mcpm audit`, `mcpm update`, `mcpm outdated`, `mcpm doctor`, `mcpm init`, `mcpm import`, `mcpm serve`,
  `mcpm disable`, `mcpm enable`, `mcpm alias`, `mcpm completions`,
  `mcpm export`, `mcpm lock`, `mcpm up`, `mcpm diff`, `mcpm publish`, `mcpm guard`,
  `mcpm secrets`, `mcpm why`

### Registry API (upstream, not ours)

- **Official MCP Registry**: `registry.modelcontextprotocol.io` — we consume this, not build our own
- **API version**: v0.1 (v0 lacks search and version filter params)
- **Search**: `?search=<name>` — substring match on server name only (no full-text)
- **Pagination**: cursor-based, max 100 per page, `metadata.nextCursor`
- **Key schema**: `packages[]` contains `registryType` (npm/pypi/oci), `environmentVariables[]`
- **Metadata**: `_meta.io.modelcontextprotocol.registry/official` has `status`, `publishedAt`, `isLatest`

### Security / Trust Assessment (V1)

- **Tier 1 (built-in, zero deps)**: Regex-based secrets detection (with NFKC normalization),
  prompt injection patterns in descriptions/titles/headers/runtimeArgs, typosquatting detection,
  exfil-shaped argument schemas, runtime arg allowlist validation
- **Tier 2 (optional)**: Wraps MCP-Scan if installed (`npx @invariantlabs/mcp-scan`)
- **Trust score**: 0-100 (health check 30pts, static scan 40pts, external scanner 20pts,
  registry metadata 10pts, capped to 0 on critical/high findings). Green ≥80, Yellow 50-79, Red <50

### Backend / Registry API (V1+ / deferred)

When community quality signals require a backend (user reviews, aggregated telemetry):
- **Framework**: Fastify
- **Database**: PostgreSQL (SQLite schema designed to ease migration)
- **Cache**: Redis
- **Search**: Typesense
- **Auth**: JWT + OAuth 2.1 for publisher namespaces
- **Artifacts**: S3 + CloudFront
- **Compute**: AWS ECS (Fargate)

### Frontend (registry web UI — V1+ / deferred)

- **Framework**: Next.js
- **Hosting**: Vercel or ECS
- **Design**: Minimal, developer-focused (think registry.npmjs.com)

---

## Product Roadmap

### MVP / V1 (SHIPPED — v0.1.0)

- [x] `mcpm search <query>` — search official MCP Registry, display with trust scores
- [x] `mcpm install <name>` — resolve server, trust assessment, write config for Claude Desktop + Cursor + VS Code
- [x] `mcpm list` — show installed servers across all clients
- [x] `mcpm remove <name>` — remove from client configs
- [x] `mcpm info <name>` — full server details
- [x] `mcpm audit` — scan all installed servers, tabular trust report
- [x] `mcpm update` — check for newer versions, re-scan
- [x] `mcpm doctor` — check MCP setup health (clients, configs, runtimes)
- [x] `mcpm init <pack>` — curated starter packs (developer, data, web)
- [x] Auto-detect and import existing MCP configs on first run
- [x] Metadata-based trust assessment on every install (Tier 1 built-in + Tier 2 MCP-Scan)
- [x] Rich trust score visualization (color bar, breakdown)
- [x] Cross-IDE config management (Claude Desktop, Cursor, VS Code, Windsurf experimental)
- [x] Config backup-before-write for safety
- [x] Cross-platform paths (macOS, Linux, Windows)
- [x] Published to npm as `@getmcpm/cli`, bin command `mcpm`
- [x] CI/CD: Node 20/22/24, SHA-pinned actions, npm provenance, Snyk integration
- [x] Security: NFKC normalization, runtime arg allowlist, file permissions, CODEOWNERS

### V1.1 (agent-native — SHIPPED v0.1.1)

- [x] `mcpm serve` — mcpm as an MCP server over stdio, 8 tools with `registerTool` API
- [x] Tools: `mcpm_search`, `mcpm_install`, `mcpm_info`, `mcpm_list`, `mcpm_remove`,
      `mcpm_audit`, `mcpm_doctor`, `mcpm_setup` (composite NL-to-install)
- [x] MCP tool annotations: `readOnlyHint` on read tools, `destructiveHint` on write tools
- [x] `mcpm_setup` keyword extraction + parallel search + trust-gated install
- [x] Publish mcpm's own MCP server to the official registry (live: io.github.getmcpm/cli)
- [x] Health check tiers (config validation → process start → list_tools verification)
- [x] Demo recording (asciinema: https://asciinema.org/a/Oua80yhXkjz071MP)

### V1.2 (usability — SHIPPED v0.2.0)

- [x] `mcpm disable <name>` — disable a server without removing it from config
- [x] `mcpm enable <name>` — re-enable a previously disabled server
- [x] `mcpm alias` — short aliases for long server names (stored in ~/.mcpm/aliases.json)
- [x] `mcpm completions <shell>` — shell completion scripts for bash, zsh, fish
- [x] `mcpm list` now shows disabled/active status column
- [x] `disabled` field in McpServerEntry + `setServerDisabled` in ConfigAdapter
- [x] Shared toggle handler (deduplicated disable/enable logic)
- [x] Strict alias validation (alphanumeric + hyphens, max 64 chars, prototype pollution guard)
- [x] Client ID validation before unsafe casts
- [x] Security hardening: tool path allowlist, health check sandboxing

### V1.3 (stack files — SHIPPED v0.3.0)

- [x] `mcpm export` — dump installed servers to mcpm.yaml stack file format
- [x] `mcpm lock` — resolve semver ranges from registry, trust assess, write mcpm-lock.yaml
- [x] `mcpm up` — batch install from mcpm.yaml with trust policy enforcement
- [x] `mcpm diff` — compare installed state vs declared state (colored output + --json)
- [x] `mcpm_up` MCP server tool (destructiveHint: true)
- [x] Stack file Zod schemas (mcpm.yaml + mcpm-lock.yaml) with YAML parse/serialize
- [x] Semver version resolution (caret + tilde ranges via `semver` package)
- [x] Trust policy enforcement with normalized percentage comparison
- [x] .env file parser for env var resolution (process.env → .env → default → prompt)
- [x] Parallel registry resolution, sequential config writes
- [x] Single .bak snapshot before batch writes
- [x] Per-server error isolation (failures collected, others continue)
- [x] URL server support (Cursor-only, warn for other clients)
- [x] --dry-run, --ci, --profile, --strict, --yes flags on `mcpm up` (later: `--check-shadowing` [F2], `--frozen` [F3])
- [x] --strict --ci requires --yes for unattended server removal
- [x] Path traversal protection on mcpm_up MCP tool input
- [x] Prototype poisoning protection in .env parser
- [x] Shared isEnoent() utility extracted to src/utils/fs.ts

### V0.5 (runtime defense — SHIPPED v0.5.0)

- [x] `mcpm guard enable / disable / status` — auto-wraps detected client configs (Claude Desktop / Cursor / VS Code / Windsurf) with the inspection relay; per-server scope via `--server`
- [x] `mcpm guard run --inner` — production stdio MITM using SDK framing helpers (OQ1 closed: p99 0.065ms small / 3.1ms large, 78×/8× under budget)
- [x] `mcpm guard demo` — synthetic prompt-injection scenario for the launch screenshot
- [x] Pattern engine (`src/guard/patterns.ts`) — NFKC + zero-width-strip + JSON leaf walk; 4 target types (tool_response / tool_call_args / tool_description / tool_annotations) *(v0.5.0 baseline; expanded to 8 inspected targets in v0.10.0 — see the V0.10 block below)*
- [x] 3 vendored OWASP MCP Top 10 v0.1 signatures (mcp-1 description injection, mcp-2 response injection, mcp-7 path exfil) *(v0.5.0 baseline; 6 signatures as of v0.10.0)*
- [x] Schema pinning + drift detection (rug-pull defense) — install-time + first-session-pin fallback + per-session same-session hash cache, SHA-256 integrity sidecar
- [x] `mcpm guard accept-drift --new-hash` — re-pin after legitimate upgrade (requires explicit hash to close unbounded-window vulnerability)
- [x] `mcpm guard mute / unmute / pause` — policy file editing CLI with auto-expiry, Zod-validated, integrity-sidecar-protected, lockfile-serialized
- [x] `mcpm guard cleanup` — prune orphan pin entries for uninstalled servers
- [x] `mcpm guard list-signatures` — show shipped catalog with OWASP category mapping
- [x] `mcpm guard reset-integrity` — regenerate pins or policy sidecar after manual edits
- [x] Event log `~/.mcpm/guard-events.jsonl` — append-only, parse with jq
- [x] MCPTox-derived deterministic CI fixture eval (25 attack + benign fixtures; closes OQ2 with MCPoison-equivalent rug-pull)
- [x] FP-rate corpus measurement (5-session seed, 0/24 FP; full 20-server capture in TODOS #29)
- [x] 6 rounds of independent security review during development; all CRITICAL + HIGH fixed before commit
- [x] Docs: README "Runtime defense" section + docs/GUARD.md + docs/SIGNATURES.md + docs/POLICY.md

### V0.9 (supply-chain + trust hygiene — SHIPPED v0.9.0)

- [x] F4 — release-age cooldown + install-script-shape awareness (PR #70); fixes the live trust-score inversion bug (a fresh poisoned republish used to score identically to a 29-day-old version)
- [x] Registry-parse fix — accept the real MCP registry Argument shape; `mcpm search` previously rejected named/positional args (#71)

### V0.10 (guard hardening + supply-chain tripwire — SHIPPED v0.10.0 / v0.10.1)

Executed the `docs/SECURITY-HARDENING.md` first-slice plan (see its **Delivery status** table):
- [x] H1 — inspect the unguarded JSON-RPC surface (resources / prompts / `initialize.instructions` / `structuredContent`) + H2 hidden-character presence detector (PR #74)
- [x] H9 — fail-closed deny-by-default for un-guardable (HTTP/SSE) transport + guard-child spawn failure (#76)
- [x] H4 — field-level schema-drift tiering (description-only = warn, schema/annotation = block) + `tools/list_changed` re-validation (#77)
- [x] H7 slice-A — relay block-to-origin seam + sampling/elicitation prompt-injection content-scan; new `sampling_prompt` target (#78)
- [x] H5 — initialize-handshake capability/identity drift, warn-once (#79)
- [x] H11 slice-1 — npm same-version `dist.integrity` drift tripwire (WARN-only) (#81)
- [x] Guard now ships **9 catalog entries over 8 inspected targets** (was 3/4 at v0.5.0): the v0.10.0 six + two `MCP-CREDENTIAL-PHISHING` signatures (F6, v0.11) + the structural `exfil-param-in-schema` detector (F5 — a tools/list property-KEY denylist, empty `patterns`); v0.10.1 = docs-accuracy patch (#85/#86)
- [ ] Deferred with documented reasons: H3 (approval-time pin), H6 (dataflow correlator), H8 (keyed-MAC integrity), H10 (tamper-evident log), H12 (trust-tier + FP budget)

### V0.11–V0.14 (roadmap detector arc — SHIPPED)

Five `docs/ROADMAP.md` features (see its delivery log) + a full dogfood and CI guards, each built ground→critique→TDD→review→dogfood:
- [x] **F6 — credential-phishing elicitation/sampling wedge (v0.11.0)** — two `MCP-CREDENTIAL-PHISHING` signatures on the H7 (#78) server-initiated path; solicitation-anchored, blocks a server that prompts the user (via `elicitation/create` / `sampling/createMessage`) for a wallet seed phrase / private key or card CVV/SSN/PIN. Error routed back to the server. (#88)
- [x] **F2 — cross-server tool-shadowing, name-collision slice (v0.12.0)** — `mcpm up --check-shadowing` / `policy.checkShadowing`; reads pins, flags any tool name owned by ≥2 servers. WARN-tier (override of the ROADMAP's "HIGH-block"), `--ci` blocks; best-effort over already-guarded servers (stack-hygiene aid, not a fresh-install control — loud coverage line). (#90)
- [x] **Dogfood + prevention guards (v0.12.1)** — a 6-cluster full-surface dogfood (102 cmds, 0 crashes) fixed 4 false-success-overclaim / mislabel bugs (`guard reset-integrity`/`accept-drift`, `secrets rm`, `search` "Trust Score"→"Status", stale `init`-pack completions). Then two CI guards so those classes can't recur: a completions↔Commander-program invariant test + a built-binary output-contract smoke matrix. (#92, #94)
- [x] **F3 — `up --frozen` fail-closed integrity BLOCK tier (v0.13.0)** — promotes the H11 WARN tripwire to an enforcing CI gate: pre-install verify of every locked npm server's `dist.integrity`, BLOCK (install nothing, exit nonzero — `npm ci` semantics) on drift / could-not-verify / format-mismatch / suspicious-missing-baseline; benign refuse-to-run for a pre-baseline lock; pypi/oci/url coverage notice. `--frozen` / `policy.frozen`. (#95)
- [x] **F5 — reject exfil-named tool-schema params, DENY-tier list-time (v0.14.0)** — structural `exfil-param-in-schema` detector walks `tools/list` inputSchema property KEYS and blocks a tool declaring an underscore-wrapped context-exfil sigil (`_system_prompt_`, …) before the model sees it; zero-FP deny tier (wrapped form only; `_context_`/`_memory_` framework slots excluded), honest "tripwire not defense" scope, muteable. (#97)
- [ ] **Next up (docs/ROADMAP.md):** F7 (`mcpm sync --check` cross-client drift) · F10 (response-side credential DLP) · the v1.0 bets — F1 `guard --confine` OS-sandbox, F8 `mcpm verify` Sigstore provenance, F9 doctor secret-scan/PATH. Known pre-existing nit: `hidden-chars-in-metadata` is un-muteable (not in the catalog) — the F5 empty-`patterns` fix would clear it.

### V1.5 (community trust)

- [ ] `mcpm publish` — submit to official registry with mandatory security scan gate
- [ ] User ratings and reviews (requires backend)
- [ ] Verified publisher badge
- [ ] Usage stats (installs, active users)
- [ ] Optional anonymous telemetry

### V2 (runtime security + monetization)

- [x] Runtime proxy (mcpm-guard) — shipped in v0.5.0 (see above)
- [ ] Cross-server flow analysis — track exfil chains across tool calls (research-grade)
- [ ] Agent intent contracts — agent declares session intent, guard rejects calls outside the envelope
- [ ] `mcpm guard serve` — expose guard itself as an MCP server (agents can introspect their own security perimeter)
- [ ] LLM-as-judge detection tier (opt-in) — close the verbatim-attack-phrase documentation gap
- [ ] Separate signatures repo + signing (Sigstore / PGP) — when update cadence requires faster releases than @getmcpm/cli's normal cycle
- [ ] HTTP transport guard — currently stdio-only (v0.10.0 H9 #76 made un-guardable HTTP/SSE transports **fail-closed deny-by-default** rather than silently bypassed; a streamable-HTTP MITM relay remains the full fix)
- [ ] Private registry for orgs (SSO, audit logs, policy enforcement)
- [ ] Dependency graph (which servers compose well together)
- [ ] AI-generated docs (Claude reads source → writes human-friendly tool docs)
- [ ] Compatibility matrix (auto-tested)

---

## Key Technical Gaps We're Filling

1. **No universal installer** — each IDE has different config format/location
2. **No `npm audit` equivalent** — no vulnerability DB for MCP servers
3. **No quality signals** — no ratings, reviews, or maturity indicators anywhere
4. **No offline browsability** — tool schemas only discoverable by connecting to server
5. **No signed tool descriptions** — enables rug-pull attacks after user approval
6. **No dependency resolution** — users reference `@latest` and discover breaks manually

---

## Go-To-Market

### Launch sequence

1. GitHub repo — the registry _is_ the OSS project
2. Seed with 100 hand-curated popular servers on day one
3. Submit to Anthropic's MCP repo as a community resource
4. Post: Hacker News, r/ClaudeAI, r/cursor, AI Discord servers
5. Reach out to top 20 MCP server authors for early publisher partnerships

### Narrative

> "We scanned 1,808 MCP servers and found 66% had security issues. We built the registry
> that npm never was for MCP — with security scanning built in from day one."

---

## Dogfood Plan

The **first MCP server we build** is a project context server for this codebase:

```typescript
// mcp-project-context — tools:
get_architecture_doc(); // returns this CLAUDE.md
search_decisions(query); // semantic search over ADR log
add_decision_log(decision); // appends to DECISIONS.md
get_roadmap(); // returns current roadmap state
```

This serves dual purpose: improves our own workflow with Claude Code, and proves
the registry concept end-to-end before we launch publicly.

---

## Architecture Diagram

```
  Developer / AI Agent
     │
     ├── CLI (terminal)              ├── MCP Server (stdio)
     │   mcpm search/install/...     │   mcpm serve
     │                               │   9 tools via JSON-RPC
     ▼                               ▼
  mcpm core (Node.js, npm: @getmcpm/cli, bin: mcpm)
     │
     ├── Registry ─────────► Official MCP Registry API (v0.1)
     │                        registry.modelcontextprotocol.io
     │
     ├── Scanner ──────────► Trust Assessment (0-100)
     │                        ├── Tier 1 (built-in: secrets, injection, typosquatting)
     │                        └── Tier 2 (MCP-Scan, optional)
     │
     ├── Config Adapters ──► Read/write per-client config (atomic + backup)
     │                        ├── Claude Desktop
     │                        ├── Cursor
     │                        ├── VS Code
     │                        └── Windsurf
     │
     └── ~/.mcpm/
           ├── servers.json    (installed server registry)
           ├── aliases.json    (short aliases for server names)
           └── cache/          (registry response cache, 1hr TTL)
```

### mcpm-guard subsystem (v0.5.0)

```
  IDE (Claude Desktop / Cursor / VS Code / Windsurf)
       │
       │  JSON-RPC over stdio
       ▼
  mcpm guard run --inner --server-name <name> -- <orig> [args]
       │
       ├── Pattern engine (src/guard/patterns.ts)
       │   NFKC + zero-width-strip + regex → InspectResult
       │   Signatures: src/guard/signatures.ts (vendored OWASP MCP Top 10)
       │
       ├── Schema-drift inspector (src/guard/drift.ts + run-inner.ts sync path)
       │   SHA-256(description + schema + annotations) vs ~/.mcpm/pins.json
       │   Per-session in-memory cache catches same-session rug-pulls
       │
       ├── Policy filter (run-inner.ts applyPolicy)
       │   ~/.mcpm/guard-policy.yaml → ignore / warn / block / log_only
       │   Or short-circuit pass-through if paused_until in future
       │
       ├── Production relay (src/guard/relay.ts)
       │   SDK ReadBuffer + serializeMessage, 64MB buffer cap,
       │   signal forwarding, child.stdin error swallow
       │
       └── Event log writer (src/guard/event-log.ts)
           Append-only to ~/.mcpm/guard-events.jsonl (parse with jq)
       │
       ▼  inspected JSON-RPC over stdio
  Wrapped MCP server process (e.g. servers-filesystem)

  ~/.mcpm/ (guard files)
    ├── pins.json + pins.json.integrity       (sha256 sidecar, proper-lockfile)
    ├── guard-policy.yaml + .integrity        (sha256 sidecar, proper-lockfile, Zod-validated)
    └── guard-events.jsonl                    (append-only)

  <client config>.guard-{enable,disable}.bak  (per-batch backup, written by orchestrator)
```

The orchestrator (`src/guard/orchestrator.ts`) implements two-phase commit
across detected clients: Phase 1 reads all + computes plans, Phase 2 applies
via `BaseAdapter.replaceServer`. Wrap transformation is centralized in
`src/guard/wrap.ts` and verified-once on `BaseAdapter` (all 4 adapters share
the same entry shape).

---

## Decisions Log

| Date       | Decision                                    | Rationale                                                              |
| ---------- | ------------------------------------------- | ---------------------------------------------------------------------- |
| 2026-03    | CLI-first over web-first                    | Developers live in terminal; npm succeeded this way                    |
| 2026-03    | OSS community-owned, not VC-backed          | Differentiation vs Smithery; trust signal for security tool            |
| 2026-03    | Build on top of official MCP Registry       | They explicitly invite subregistries; no competition                   |
| 2026-03    | Node.js CLI (not Python)                    | TypeScript SDK has 3x more dependents; aligns with npm distribution    |
| 2026-03-28 | npm package: `@getmcpm/cli`, bin: `mcpm`        | `mcpm`, `mcpx`, `mcp-pm`, `mcpman` all taken on npm                   |
| 2026-03-28 | Single package (not monorepo)               | Only one consumer (CLI); extract registry client later if needed       |
| 2026-03-28 | Registry API v0.1 (not v0)                  | v0.1 has `search` param and `version` filter                          |
| 2026-03-28 | JSON files, not SQLite for MVP              | Zero native deps; better-sqlite3 needs node-gyp on some systems       |
| 2026-03-28 | Metadata-based trust assessment (not source scan) | npx downloads at runtime, no pre-install artifact to scan         |
| 2026-03-28 | Install-then-verify flow                    | No code runs pre-confirmation; health check is post-install            |
| 2026-03-28 | Commander.js (not oclif)                    | Lighter, no plugin system needed for V1                                |
| 2026-03-28 | @inquirer/prompts (not readline)            | Security UX needs multi-select, confirm, styled trust score warnings   |
| 2026-03-28 | No telemetry in V1                          | Trust paradox: security tool shouldn't track users at launch           |
| 2026-03-28 | Deferred Typesense/Fastify/PostgreSQL to V1+| MVP is local-first; backend needed only when user reviews require it   |
| 2026-03-30 | `mcpm serve` over stdio (not HTTP)          | Matches how Claude Desktop/Cursor/Claude Code consume MCP servers      |
| 2026-03-30 | `registerTool` API with annotations         | `destructiveHint` on install/remove/setup, `readOnlyHint` on read ops  |
| 2026-03-30 | No LLM in mcpm for `mcpm_setup`             | Calling agent handles NL understanding; mcpm does keyword extraction   |
| 2026-03-30 | CI derives version from git tag             | Single source of truth; no manual package.json version bumps           |
| 2026-03-30 | Auto GitHub Release on publish              | `--generate-notes` from commit history; grouped by label               |
| 2026-05-16 | v0.5.0 mcpm-guard ships as `v0.5.0`, not `v1.6` | Office-hours user-challenge — pre-1.0 honest framing matches mcpm's actual maturity (V1.5 community trust unshipped). Versioning is a contract with users about stability. |
| 2026-05-16 | Distribution > Detection — guard's wedge is bundling into the package manager | Eng-review verified the runtime-guard market is crowded (10+ OSS proxies, Snyk acquired Invariant Labs, Microsoft Agent Governance Toolkit). Detection sophistication commoditizing fast; distribution-as-moat is the structural play. |
| 2026-05-16 | MITM substrate: SDK ReadBuffer/serializeMessage, not full Transport classes | OQ1 spike measured p99 0.065ms small / 3.1ms large with parse+reserialize — 78×/8× under budget. Eng-review caught that `StdioServerTransport` hardcodes process.stdin/stdout; only the framing helpers are reusable. |
| 2026-05-16 | MCP stdio is line-delimited JSON only, not Content-Length | Verified against SDK `ReadBuffer.readMessage` source. Eng-review F2.1's "Content-Length framing" test gap was a false positive for MCP and dropped from the conformance harness. |
| 2026-05-16 | Vendored signatures inside `@getmcpm/cli` for v0.5.0 | Defer separate `getmcpm/signatures` repo + signing (Sigstore/PGP) until update cadence requires faster releases than @getmcpm/cli's normal cycle. Cuts v0.5.0 scope without losing detection coverage. |
| 2026-05-16 | Curated by maintainers, not crowdsourced (signatures) | uBlock-Origin-style community contribution model needs a community we don't have yet (~200 people in the world can write a credible MCP attack signature). v0.5.0 ships curated; community PRs unlocked v0.7+. |
| 2026-05-17 | Pin subprocess uses allowlisted env, not process.env passthrough | Step 5 F4.1 — full env would leak `AWS_*` / `GITHUB_TOKEN` / `OPENAI_API_KEY` to a just-installed server's init handler. Security regression vs current `mcpm install` (which doesn't execute the server at all). |
| 2026-05-17 | `accept-drift` requires explicit `--new-hash sha256:...` | Step 6 F5 — setting `current_hash: null` created an unbounded "accept anything next" window an attacker could race into. User copies hash from block-message remediation. |
| 2026-05-17 | applyPolicy: MAX action across remaining findings (not single downgrade var) | Step 7 F1 CRITICAL — original implementation let `log_only` override on ANY one finding silently downgrade `block` from unrelated critical findings. Dedicated regression suite in `apply-policy.test.ts`. |
| 2026-05-17 | Integrity sidecars on both pins.json AND guard-policy.yaml | Step 7 F4 — a stale/naive edit of these files would otherwise go unnoticed. Sidecar is an UNKEYED SHA-256 stored beside the file with the same perms: it provides INTEGRITY (tamper-evidence vs accidental corruption / cross-machine copies / a different OS-user), NOT authenticity vs a same-user/postinstall attacker, who can recompute the sidecar to match. See revised scope 2026-06-02 (issue #19). |
| 2026-06-02 | Integrity sidecars relabeled integrity-not-authenticity (NOT anti-malware) | Security issue #19 — the 2026-05-17 row + code comments wrongly implied the unkeyed SHA-256 sidecars stop a malicious npm `postinstall` / same-user process. They don't: any process that can write `pins.json` / `guard-policy.yaml` can recompute and rewrite the sidecar (no attacker/writer asymmetry). A keyed scheme (HMAC/signature) needs a secret the writable store lacks — same constraint as the secret store (issue #15) — so the honest fix is relabel-only (docs + comments, no behavior change); true authenticity (OS keychain / signed releases) deferred. `docs/GUARD.md` + `docs/POLICY.md` already stated this correctly; this reconciles `pins.ts`, `policy.ts`, and the Decisions Log. |
| 2026-05-17 | Zod-validated YAML parse with `.catch({})` fallback | Step 7 F2 — `paused_until: 99999999999999` (numeric, not ISO string) would otherwise bypass all inspection because `new Date(numeric)` is year 5138. Fall back to empty policy on any structural mismatch. |
| 2026-05-17 | Same-session "first hash seen" cache | Step 6 F3 — closes the double-`tools/list` bypass where a malicious server delivers benign-then-poisoned schemas before the off-thread pin write commits. |
| 2026-05-17 | FP-rate threshold 2%; effective floor 4% on the 24-message seed | Step 9 — the threshold becomes meaningful at corpus sizes ≥ 50. Documented inline in `fp-rate.test.ts`. Full 20-server capture is TODOS #29. |
| 2026-05-17 | MCPTox attack fixtures hand-authored from public methodology, not vendored | Step 8 closes OQ3 — sidesteps the MCPTox redistribution license question. Hand-authored from Invariant Labs disclosure / MCPoison CVE / Equixly-Pillar audits. License-clean. |
| 2026-06-01 | Secret store keyed by machine id (hostname + username), not a real secret | Zero-native-deps constraint (no keytar). AES-GCM with a machine-derived key protects against casual local inspection, NOT same-account file exfiltration — a copied `secrets.enc.json` decrypts on the same OS account. Runtime notices + docs reworded to drop any exfil-resistance claim. True at-rest resistance (OS keychain / user passphrase) deferred (security issue #15). |
| 2026-06-03 | MCP tool input schemas hardened: bounded `name` (1–256), `client` as `z.enum(CLIENT_IDS)`, `strictObject` | Security issue #31. The bounded fields + client enum live on the per-field schemas, so they propagate to the live MCP boundary through the SDK's `.shape` consumption; the object-level `strict` setting does NOT survive `.shape` (SDK rebuilds a plain `z.object`), so the runtime `validateMcpServerName` / `CLIENT_IDS.includes` guards in `handlers.ts` remain the enforced backstop. `strict` hardens direct `.parse()` of the exported schemas. Dependabot half of #31 (github-actions + npm) already shipped in `.github/dependabot.yml`. |
| 2026-06-03 | Secret store gains real exfiltration resistance via an OS-keychain master key — SUPERSEDES 2026-06-01 deferral | Security issue #15. A random 32-byte master key is held in the OS credential store via **zero-native-dep shell-outs** (macOS `security`, Linux `secret-tool`/libsecret, Windows DPAPI-blob via PowerShell — no keytar, constraint preserved); per-value AES-GCM keys are derived from it with HKDF. Because the master key never lands in `~/.mcpm`, a copied `secrets.enc.json` cannot be decrypted off-machine/-account. New entries are tagged `k1:`; legacy machine-scheme entries stay decryptable and `mcpm secrets migrate` upgrades them. Where no OS keychain exists (headless/CI, or `MCPM_DISABLE_OS_KEYCHAIN=1`) it falls back to the honestly-labelled machine key. `secrets set` now reports which backend actually protected the value. Tests force the fallback via `MCPM_DISABLE_OS_KEYCHAIN=1` (vitest.setup.ts) so the suite never touches a real keychain; `os-keychain.ts` dispatch is unit-tested with mocked `spawn`. CI is ubuntu-only, so the macOS/Windows shell-outs are not exercised in CI — verified locally on darwin. Known tradeoff (security review, MEDIUM): macOS passes the master key in `security` argv (the binary has no reliable non-interactive stdin path), briefly visible to a same-user `ps` during the write; bounded (write-only window; a same-user attacker can already read process memory; read path uses stdout). Linux passes via stdin, Windows via env var. Documented in `os-keychain.ts`. |
| 2026-06-15 | Guard hardening program H1–H12 first slices SHIPPED in v0.10.0; docs reconciled to shipped state | The `docs/SECURITY-HARDENING.md` plan (drafted 2026-06-12 as "proposed") was executed: H1/H2 (#74), H9 (#76), H4 (#77), H7-A (#78), H5 (#79) + H11 supply-chain integrity tripwire slice-1 (#81), all released in **v0.10.0**; v0.10.1 docs patch (#85/#86). H3/H6/H8/H10/H12 deferred with documented reasons. The **Delivery status** table in SECURITY-HARDENING.md is now the per-control source of truth; per-PR design decisions live in commit history. This doc/ROADMAP/README reconcile pass corrected the prior `proposed / v0.8.1 / "nothing built yet"` drift. |
| 2026-06-19 | F2 cross-server tool-shadowing shipped as WARN-tier name-collision slice, NOT the ROADMAP's "HIGH-block" | A grounded design+critique pass overrode the ROADMAP F2 spec on two points: (1) **WARN/advisory, not HIGH-block** — legit stacks routinely share tool names (two filesystem servers → `read_file`; same package under two names; generic verbs), so an unconditional block would drive users to disable the check (H12 consent-fatigue); `--ci` is the only blocking mode. (2) **Best-effort over already-guarded servers, exact-name only** — the inventory source is `pins.json`, which the *relay* TOFU-populates, so a never-guarded server contributes no names: v1 is a stack-hygiene / re-audit aid, **not** a fresh-install control, and it does NOT catch the description-reference confused-deputy (the Problem example, different tool names) nor a homoglyph evasion. The code surfaces the blind spot loudly (a coverage line). `origin-index.json` persistence + the text-reference heuristic + relay-time integration are the deferred fast-follow. `mcpm up --check-shadowing` / `policy.checkShadowing`; pure detector in `src/guard/shadow.ts`, zero new deps. |

---

## Context for Claude Code

When helping with this project:

- We are building `mcpm` — an open-source MCP package manager (npm: `@getmcpm/cli`)
- Trust assessment is a core feature, not an afterthought
- We are OSS-first — avoid design decisions that require proprietary lock-in
- Check `docs/ARCHITECTURE.md` for the detailed implementation plan
- Check `TODOS.md` for blockers and deferred work
- The official MCP Registry API v0.1 is at `registry.modelcontextprotocol.io`
- V1 is local-first: no server infrastructure, JSON files in `~/.mcpm/`
- Immutable data patterns: always return new objects, never mutate
- All config writes use atomic write-then-rename with backup-before-write
- Existing competitors: mcpm.sh, mcp-get, mcpman — we differentiate on trust assessment

---

## gstack

Use the `/browse` skill from gstack for all web browsing. Never use `mcp__claude-in-chrome__*` tools.

Available gstack skills:
`/office-hours`, `/plan-ceo-review`, `/plan-eng-review`, `/plan-design-review`,
`/design-consultation`, `/review`, `/ship`, `/land-and-deploy`, `/canary`,
`/benchmark`, `/browse`, `/qa`, `/qa-only`, `/design-review`,
`/setup-browser-cookies`, `/setup-deploy`, `/retro`, `/investigate`,
`/document-release`, `/codex`, `/cso`, `/careful`, `/freeze`, `/guard`,
`/unfreeze`, `/gstack-upgrade`

If gstack skills aren't working, run `cd .claude/skills/gstack && ./setup` to build the binary and register skills.
