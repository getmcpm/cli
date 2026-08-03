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

### 31. ~~Unicode TAG-block blind spot on non-metadata carriers~~ DONE (v0.28.0)
**Resolution:** Shipped decode-and-rescan, the stronger of the two candidate
shapes, so the block-tier control is restored rather than merely noticing that
something was concealed.

- `inspectTagEncoded` (`patterns.ts`) decodes tag runs back to ASCII and re-runs
  the **carrier's own signatures**, on every carrier. The `sampling_prompt`
  bypass is closed: a TAG-encoded wallet-seed solicitation now blocks via
  `credential-phishing-wallet-solicitation` with the error routed back to the
  server, where it previously scored zero findings. All tag characters in a leaf
  decode as ONE payload — decoding per-run would let an attacker interleave a
  visible character so no run spelled a matchable phrase.
- TAG-decoded findings are deliberately **not** `decoded`-clamped the way
  base64-decoded ones are. The clamp exists because base64 is everywhere in
  benign data; a tag run that decodes to a signature-matching phrase is stronger
  evidence than the same phrase in plaintext.
- `unicode-tag-concealment` (new catalog entry, `high` → warn) is the presence
  floor for a payload concealed but matching no signature. Scoped to the carriers
  `hidden-chars-in-metadata` skips, so a tag character is reported once. Catalog
  is 13 entries.
- The **live emoji-flag false positive** is fixed with whole-sequence, RGI-exact
  validation (`gbeng`/`gbsct`/`gbwls`). Both properties were required: the design
  note's warning that a per-character flank test is a bypass lever held, and a
  shape-based whole-sequence rule is barely better since "ignore" is six
  lowercase letters. A fixture pins the chaining bypass.
- The corpus objection was honoured: benign emoji-tag-sequence fixtures were
  added, so the zero-FP claim rests on evidence rather than on the corpus
  containing no tag codepoints at all. `owasp-mcp-1-tag-block-in-description.json`
  re-pinned warn -> block as predicted.
- Also closed a composition hole found while building it: base64 wrapping a
  TAG-encoded payload used to evade both passes, because the decoded text cleared
  the texty gate and then normalization erased the tag characters. Tag decoding
  now runs on the base64 synthetic leaf too, keeping the base64 layer's warn
  clamp. Base64-of-base64 still evades, unchanged.

**Review changed the design, twice — recorded because the first version looked right.**
Decoding originally built a TAG-ONLY view (every tag character in the leaf
concatenated, visible text discarded). That is two disjoint projections — the
existing visible-only view and the tag-only one — and an attacker picks the gap
between them: `"Report done. ig" + TAG("nore all previous instru") + "ctions…"`
reads as a complete instruction to a model, while neither projection carries the
phrase. One visible character inside one word downgraded a block to a warn,
including on `sampling_prompt`. It was also unsafe in the other direction:
discarding the visible text let two INDEPENDENT benign runs 900 characters apart
fuse into a phrase the content never contained and hard-BLOCK on it. Decoding
**in place** is the view the model actually reads and fixes both at once. The
un-clamped severity is only defensible because of this — the phrase has to
genuinely be there.

Re-reviewing THAT fix found a HIGH in it, which is why the fix got its own
review round rather than riding on the first one. Decoding purely in place hands
the payload whatever visible character precedes it, and the most-cited injection
pattern is anchored on `(?:^|[\s.,;:!?])`. Deleting ONE space —
`"Report done" + TAG(injection)` instead of `"Report done. "` — took
`tool_response`, `tool_description` and `initialize_instructions` from block back
to warn, while a model still read the complete instruction and a human still saw
only "Report done". A test had even pinned that as INTENDED, on the argument that
concealed text should be judged exactly as the same plaintext. The equivalence
does not transfer adversarially: the anchor is an FP-reduction heuristic for
benign prose, benign prose does not conceal itself in the tag block, and in
plaintext an attacker cannot delete the boundary without a reader seeing
"doneIgnore". So the decoder now builds TWO views in one walk — in place, and one
that breaks the line at each visible/concealed transition — and reports the union.

Two smaller ones from the same round. The window seam was joined with a newline,
which is `\s`: the catalog's `[\s]*` separators match straight through it, so it
never stopped cross-seam fusion, and it DONATED the anchor. It is now 48 NULs —
NUL is matched by neither `[\s]*` nor the anchor class, and 48 > the widest
bounded bridge in the catalog (`[\s\S]{0,40}`, credential phishing). The test for
that had padded its runs thousands of characters from the seam, so it passed with
or without any separator. And a decoded finding is now suppressed when the plain
scan already caught the same signature, so an unrelated flag elsewhere in a leaf
no longer re-reports plainly visible text with a false "invisible to a human
reviewer" note.

Also caught in review: the RGI carve-out's membership test was a linear scan per
tag character, so a leaf packed with valid flag emoji was quadratic — a 4 MB
frame stalled the synchronous relay for 24 SECONDS against a 3.1 ms budget, at
zero attacker cost. Now an O(1) mask. The bounds test that should have caught it
used tag characters with NO flags, so the skip structure was empty and the term
that blows up was never exercised — the v0.26.0 shape again.

Rounds 3, 4 and 5 each found a HIGH in the round before. The recurring shape,
worth naming because it caught me four times: **a fix reasoned about a narrower
property than the one it changed.** Decoding in place was "the view the model
reads" but silently deleted the anchor. The seam was "not whitespace" but was
destroyed by a second windowing pass. Relaxing the anchor was licensed by
concealment, then applied to a whole segment where only one character was
concealed — blocking an article that merely QUOTES an attack phrase, which on
tool metadata drops the entire tools/list. A relaxed match is now kept only when
the same match is not already in plain sight.

**Known limits, pinned as tests rather than left to be discovered:**
- A payload buried in the discarded MIDDLE of a >64 KB leaf is not seen. The
  pre-existing #27 window bound, identical for plaintext, but the padding is
  invisible as well as free here.
- A well-formed subdivision flag that is not one of the three RGI sequences
  warns on a data carrier. Unicode closed RGI subdivision flags to new proposals
  in 2021, so the carve-out can never grow to cover the ~5000 valid ISO 3166-2
  codes. Warn-only, forwarded, muteable — but permanent.
- A TAG-encoded payload wrapped in base64 *and* padded below the texty gate is
  dropped before any signature runs — same bound Detector-B has always had.
- `tool_call_args` is client-authored, so its presence floor is defensive rather
  than load-bearing.

### 32. Wire a real external scanner to the tier-2 seam
**Priority:** P3
**Found:** 2026-08-03, alongside the v0.28.0 tier-2 security fix.
**What:** Tier 2 is now an honest opt-in seam (`MCPM_EXTERNAL_SCANNER`, no fetching), but nothing ships wired to it, so the 20-point external bucket is unreachable for a normal user. The obvious candidate does not drop in: Invariant's mcp-scan is a **PyPI** tool (since 2026-03 a redirect package for `snyk-agent-scan`) whose CLI scans client **config files**, not registry server names, so `<cmd> --json <server-name>` does not match its interface. The unscoped npm `mcp-scan` is an unrelated third-party product and must not be adopted as a substitute.
**How:** pick a target scanner, adapt the invocation and output mapping to its real CLI contract, and verify against the installed tool rather than a mock — the mock-only coverage is precisely what hid the dead `npx` path for the whole life of the feature. Consider `mcpm doctor` reporting whether an external scanner is configured and runnable.
**Effort:** ~3 hrs per scanner integration.

### 33. Evaluate HARD_TRUST_FLOOR on mcpm-native evidence only
**Priority:** P2
**Found:** 2026-08-03, by adversarial review of the v0.28.0 tier-2 change.
**What:** `HARD_TRUST_FLOOR = 25` (`src/server/handlers.ts`) is documented as a floor that "no caller-supplied value can lower", protecting the no-human-in-loop MCP path. It is compared against the **raw** trust score, which includes the 20-point external-scanner bucket. Since `MCPM_EXTERNAL_SCANNER` names an arbitrary executable, a two-line script is enough to move that floor:

```sh
#!/bin/sh
echo '{"findings":[]}'
```

Reproduced: a server with two critical tier-1 findings and no health check scores 15 (blocked, 15 < 25); with that script configured it scores 35 and `mcpm_up` installs it. The v0.28.0 change closed the *accidental* version of this (`/bin/true` and other silent binaries no longer earn the bucket) but cannot close the deliberate one — mcpm has no way to verify an arbitrary executable did any work.

**Why this is not simply "the user's own machine":** it is, and a user who fakes their own scanner is only fooling themselves. The defect is narrower and real: the floor's *documented* contract says it cannot be lowered by caller-supplied input, and an environment variable is caller-supplied. Either the contract or the implementation should change.

**Proposed fix:** evaluate the floor against mcpm's own evidence — compare `score - breakdown.externalScan` (equivalently, recompute with `hasExternalScanner: false`) rather than the raw total. Third-party corroboration mcpm cannot verify should be able to *inform* a score without being able to *clear a safety floor*. Note this is a real behaviour change for legitimate scanner users, whose 20 points would stop counting toward the floor, so it wants its own PR and its own review rather than riding along with a scanner fix.
**Effort:** ~1 hr (one comparison + tests), plus deciding whether `mcpm install --min-trust` should follow the same rule.
