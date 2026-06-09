# TODOS

> **Forward roadmap (post-v0.8.1):** the next security + DevX feature plan — themes,
> prioritized buckets, per-feature designs, and the "ship this slice first" guidance —
> lives in [`docs/ROADMAP.md`](./docs/ROADMAP.md). The items below remain the granular
> backlog; the roadmap is the strategic layer on top of them.

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

### 4. ~~Cross-Platform Config Paths~~ DONE (2026-04-06)
**Resolution:** All three platforms (macOS, Linux, Windows) handled in config/paths.ts.
Claude Desktop + VS Code use `appDataDir()` which resolves to `~/Library/Application Support` (macOS), `~/.config` (Linux), `%APPDATA%` (Windows).
Cursor and Windsurf are home-relative on ALL platforms (`~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`) — they do NOT use APPDATA on Windows. Previous code incorrectly routed them through APPDATA on Windows; fixed.

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

### 15. ~~Encrypted Secret Storage for Stack Files~~ DONE (v0.7.0–v0.8.1)
**Resolution:** All three investigated alternatives shipped (opt-in via `--secrets keychain` on `install`/`up`; plaintext + chmod 600 remains the default for back-compat):
- **OS keychain integration:** `store/os-keychain.ts` stores a random 32-byte master key in the native credential store (macOS `security`, Linux `secret-tool`, Windows DPAPI) with zero native deps.
- **Encrypted at rest:** `store/keychain.ts` AES-GCM-encrypts each secret into `~/.mcpm/secrets.enc.json` under an HKDF-derived subkey (PBKDF2 machine-key fallback for headless/CI).
- **Reference-only storage:** config files store `mcpm:keychain:server/KEY` placeholders that `guard/run-inner.ts:226` resolves into the child env at launch.

The original grievance ("every `mcpm up` writes secrets as plaintext") is resolved: `applyKeychainSecrets` (`store/keychain.ts:509`) is the single no-plaintext enforcement point, wired into `up.ts:571` and `install.ts:503`. Full `mcpm secrets set/list/get/rm/migrate` command (`commands/secrets.ts`). 73 tests across 6 files (install→guard round-trip, master-key exfil-resistance, `--ci` rejection).

### 14. Optional Anonymous Telemetry
**Priority:** P2
**What:** Add opt-in anonymous telemetry (install count, command usage, error types).
**Why:** After V1 launch, you'll want to know adoption patterns. V1 skips this to avoid trust paradox ("security tool that tracks you").
**How:** Simple opt-in on first run. Anonymous counters only. No PII, no server names.
**Depends on:** V1 launch, established trust.

## v0.5.0 mcpm-guard — Deferred Security Findings

These came out of the security-reviewer agent's audit of the v0.5.0 guard subsystem (2026-05-16). Critical and high findings were fixed in commit; these are deferred with rationale.

### 16. Add tool_annotations signatures (security review F12)
**Priority:** P1 — v0.5.0.1
**What:** The pattern engine's `tool_annotations` target is wired (patterns.ts routes to `result.tools[*].annotations`) but no shipped signature uses it. Add an annotation-injection signature mapped to OWASP-MCP-1.
**Why:** Annotations are an MCP extension surface that tool-poisoning attacks specifically exploit (Invariant Labs disclosure). Custom annotation fields can carry injection text that bypasses description-only checks.
**Effort:** ~30 min (one signature entry + tests).

### 17. Credential-content detection in tool responses (security review F4)
**Priority:** P1 — v0.5.0.1
**What:** Add `tool_response` signatures matching PEM private keys, AWS credentials block, JWT tokens, etc. Current guard catches the path in tool_call_args (warn) but not the resulting key material in the response (no signature).
**Why:** Real exfil chain is: poisoned description → tool call with path (warned, forwarded) → server returns key contents in response (no signature fires). Closes the chain.
**Effort:** ~1 hr (3-5 signature entries + tests).

### 18. Base64 / URL-encoded payload decoding pass (security review F13)
**Priority:** P2 — v0.5.1
**What:** Preprocess string leaves: detect ≥20-char base64 / URL-encoded blobs, decode, re-run inspection on decoded content.
**Why:** Naive regex evasion. Attackers can base64-encode "ignore previous instructions" and slip past the engine.
**Effort:** ~2 hrs (decoder + recursion guard + tests).

### 19. ~~Homoglyph normalization (Unicode TR39 skeleton)~~ DONE (v0.8.0, #30 guard + #51 scanner)
**Resolution:** `foldConfusables` (a TR39-skeleton-modeled Cyrillic/Greek→ASCII confusables map, `guard/patterns.ts:153`) is integrated into `normalizeForMatch` (`guard/patterns.ts:198`) after NFKC + zero-width strip, and runs on the live guard relay (`inspectMessage`→`inspectAgainstSignatures`) as well as the scanner (`scanner/patterns.ts` reuses it). 5 guard tests assert homoglyph injections block (verified the TODO's own `ignоre previоus instructiоns` Cyrillic-о example → `action: block`) while legitimate Cyrillic prose stays FP-safe. Scope is a deliberate Cyrillic/Greek allowlist (FP-safety) rather than the full ICU `confusables.txt` table — the original ask explicitly offered "TR39 skeleton OR a confusables library".

### 20. Direct test for ReadBuffer 64MB cap (security review F6 follow-up)
**Priority:** P2 — v0.5.1
**What:** The cap is implemented in `wireDirection`; tested only by inspection. Add a subprocess test that withholds the newline delimiter and verifies the relay closes the child + emits the DoS event.
**Effort:** ~30 min.

### 21. Document `tool_response` target scope precisely (security review F10)
**Priority:** P3 — docs
**What:** Add an inline comment in patterns.ts:targetSubtree explaining that `tool_response` matches any JSON-RPC `result.content`, regardless of which method prompted it. This is intentional (broader detection coverage) but should be documented so it's not "fixed" away.
**Effort:** ~5 min docs.

### 22. ~~Track `fast-uri` CVE remediation~~ DONE (2026-05-17, v0.5.0 ship gate)
**Resolution:** Added `pnpm overrides` entry `fast-uri: ^3.1.2` (and bumped `hono: ^4.12.18`, `postcss: ^8.5.10`, added `ip-address: ^10.1.1` for completeness). All transitive SDK CVEs cleared. `pnpm audit` reports "No known vulnerabilities found." Tests + typecheck + build all pass post-override. The fast-uri 3.1.0 → 3.1.2 jump was a pure security fix with no API surface change; SDK functions unchanged.

### 23. Zod-validate McpServerEntry shape in BaseAdapter.read() (security review F8, Next Step 5 audit)
**Priority:** P2 — v0.5.1
**What:** `BaseAdapter.read()` does an unchecked cast: `servers as Record<string, McpServerEntry>`. A malformed config (e.g., `args: "bad"` instead of `args: ["bad"]`) silently corrupts the wrap transform (spreading a string produces single-character args). Validate each entry through a Zod schema before returning; skip-with-warning on malformed entries.
**Effort:** ~1 hr (schema + tests).

### 24. Single-atomic-write for pins.json + integrity (security F8, Step 6 audit)
**Priority:** P1 — v0.5.1 (raised from P2; see audit note)
**What:** `writePins` currently does two atomic renames (pins.json then pins.json.integrity). A concurrent reader between the two sees new content + old hash and fires `PinsIntegrityError`. With Step 6's fail-closed F1 fix, that brief window blocks all traffic transiently. Reformat to a single file where the integrity hash is embedded as the first line, or retry once on read-side mismatch before raising.
**Audit note (2026-06-09):** Still OPEN and confirmed at `guard/pins.ts:276-277` (two sequential `writeFileAtomic` renames) + `guard/pins.ts:205-214` (throws on first sidecar mismatch, no retry). The proper-lockfile added by #52/#54 is acquired only by `writePins` (writer-vs-writer); `readPins` takes no lock, so the reader-vs-writer interleave is unmitigated. The #52/#54 fail-closed `readPins` change makes the transient block *worse*, not better — hence priority raised to P1.
**Effort:** ~1.5 hrs (refactor + tests for race).

### 25. Add strict hash-format regex to PinsFileSchema (remainder of security F10)
**Priority:** P3 — v0.5.1 (PARTIAL — schema-on-read half shipped in #54)
**What:** The Zod-validate-on-read mechanism shipped: `readPins` now runs `PinsFileSchema.safeParse` and rejects structurally-malformed files (e.g. `current_hash: 42`) with a clear "invalid structure" error (`guard/pins.ts:222-247`). **Remaining:** `current_hash` is still plain `z.string().nullable()` and `previous_hashes` is `z.array(z.string())`, so a structurally-valid-but-garbage hash (`"sha256:x"`, `"garbage"`) passes. Wire the strict `/^sha256:[0-9a-f]{64}$/` regex — already present at `guard/drift.ts:225` but not referenced by the pins schema — into `PinEntrySchema` (`guard/pins.ts:69`), and add a malformed-hash-string rejection test (current `pins.test.ts` only rejects entries for *missing sibling fields*, not bad hash format).
**Effort:** ~20 min.

### 26. NFC normalize before hashing tool definitions (security F12, Step 6 audit)
**Priority:** P3 — v0.5.1
**What:** `hashToolDefinition` hashes raw bytes. Legitimate server upgrades that change Unicode normalization form (e.g., NFD → NFC, U+212B Angstrom → U+00C5 Å) produce different hashes and false-positive as drift. Apply `string.normalize("NFC")` to description strings before hashing. This is a breaking change to existing pins — bump PINS_FORMAT_VERSION and add a migration that re-pins on first read.
**Effort:** ~1 hr (incl. migration).

### 27. Buffer first-session tools/list until off-thread pin write commits (security F3 hardening)
**Priority:** P3 — v0.5.1
**What:** Step 6 closed F3 with a per-session in-memory "first hash seen" map, which catches double-tools/list in the same session. A stricter close is: don't forward the first tools/list response until the off-thread pin write completes (one round-trip delay; once-per-session-per-server). Higher latency but eliminates any same-session unprotected window.
**Effort:** ~2 hrs (refactor sync inspect → async with await on the off-thread).

### 28. `pause --for --off` flag conflict declaration (security review Step 7 F9)
**Priority:** P3 — v0.5.1
**What:** `mcpm guard pause --for 5m --off` currently lets `--off` win silently. Add a `.conflicts("for")` on `--off` (Commander supports this) so users get a clear error rather than implicit precedence.
**Effort:** ~5 min.

### 29. Expand FP-rate corpus from 5 seed sessions to 20 real-server captures (Step 9 follow-up)
**Priority:** P2 — ongoing maintainer task
**What:** v0.5.0 ships with 5 synthetic-but-realistic session fixtures (filesystem/github/slack/postgres/fetch) totaling 24 messages. Per design doc Success Criterion, the full FP-rate measurement target is "top-20 servers by GitHub stars under modelcontextprotocol/servers" — captured as 5-minute record-replay sessions.
**How:** Build `scripts/capture-fp-session.ts` that tees stdio through `mcpm guard run --inner` and writes JSONL. Run against the top 20 servers; vendor under `src/guard/__tests__/fixtures/legitimate-corpus/`. CI publishes the aggregate FP rate per release in the release notes.
**Refresh cadence:** quarterly (servers update, signature set changes, regex tuning).
**Effort:** ~3 hrs initial (one-time capture session) + ~30 min/quarter (refresh).

### 30. LLM-as-judge context-aware detection for verbatim attack-phrase docs (Step 9 FP limitation)
**Priority:** P3 — v0.5.1+
**What:** The seed corpus discovered that a documentation page containing the **verbatim** trigger phrase ("disregard prior instructions" exactly) false-positives. Regex can't distinguish meta-discussion from instruction. An opt-in LLM-as-judge tier could resolve borderline cases by reading the surrounding context.
**Why deferred:** v0.5.0 ships deterministic-only (no model API calls). This is the V2-roadmap LLM tier.
**Effort:** ~5 hrs (signature schema extension + judge prompt + tests).
