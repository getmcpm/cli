# MCP Registry — Project Context

> This file is automatically read by Claude Code on every session.
> Keep it updated as decisions are made. Last updated: 2026-03-28.

---

## What We're Building

An open-source, CLI-first MCP package manager — **"npm for MCP servers"**.

A registry where developers can search, install, audit, publish, and update MCP servers
across all major clients (Claude Desktop, Cursor, VS Code, Windsurf) from a single tool.

**npm package**: `@getmcpm/cli` | **bin command**: `mcpm` | **repo**: github.com/getmcpm/cli | **web UI**: deferred to V1+

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

- **Runtime**: Node.js (>=20.0.0), TypeScript, ESM
- **npm package**: `@getmcpm/cli` (bin command: `mcpm`)
- **CLI framework**: Commander.js
- **Schema validation**: Zod (single source of truth for all types)
- **Prompts**: @inquirer/prompts (trust score UX, multi-select, confirmations)
- **Output**: chalk + cli-table3
- **Local storage**: JSON files in `~/.mcpm/` (servers.json, scans.json, cache/)
- **Testing**: Vitest + @vitest/coverage-v8 (80% line, 75% branch thresholds)
- **Build**: tsup (TypeScript → JS)
- **MCP server**: `mcpm serve` exposes 8 tools via `@modelcontextprotocol/sdk` (stdio transport)
- **Commands**: `mcpm search`, `mcpm install`, `mcpm list`, `mcpm remove`, `mcpm info`,
  `mcpm audit`, `mcpm update`, `mcpm doctor`, `mcpm init`, `mcpm import`, `mcpm serve`

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

### V1.5 (community trust)

- [ ] `mcpm publish` — submit to official registry with mandatory security scan gate
- [ ] User ratings and reviews (requires backend)
- [ ] Verified publisher badge
- [ ] Usage stats (installs, active users)
- [ ] Optional anonymous telemetry

### V2 (runtime security + monetization)

- [ ] Runtime proxy (mcpm-guard) — intercept tool calls, behavioral trust scores
- [ ] Private registry for orgs (SSO, audit logs, policy enforcement)
- [ ] Dependency graph (which servers compose well together)
- [ ] AI-generated docs (Claude reads source → writes human-friendly tool docs)
- [ ] Compatibility matrix (auto-tested)
- [ ] Semver-aware version resolution + lock files

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
     │                               │   8 tools via JSON-RPC
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
           └── cache/          (registry response cache, 1hr TTL)
```

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
