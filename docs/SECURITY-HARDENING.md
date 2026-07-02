# mcpm Security Hardening Plan — Supply Chain + Agent Tool-Call Defense

> Status: **in delivery** (see *Delivery status* below) · Baseline: **v0.10.1** · Drafted: 2026-06-12 · Reconciled to shipped state: 2026-06-15
>
> **How this was produced:** a grounded multi-agent pass — (1) a file-and-function map of
> mcpm's *current* protections and extension seams (`guard/`, `scanner/`, `stack/`,
> `store/`, `registry/`); (2) a research catalogue of attacks that target agent tool-calls
> in MCP clients (Claude Desktop/Code, Cursor, Windsurf); (3) a synthesized 10-item
> roadmap; (4) an **adversarial critique** of every item through three lenses —
> bypassability, false-positive/UX cost, and completeness. The critique demoted several
> draft "block" controls to warn/observability and surfaced five missing controls. The
> supply-chain research lane was filtered by automated policy mid-run, so §6 (install-time)
> is drafted from first principles; all controls here are **defensive**.
>
> **This began as a design-of-record; the first slices have since shipped** (see *Delivery
> status* below). The §5 control bodies preserve the original design narrative — consult the
> status table for what is live versus still proposed.

---

## Delivery status (reconciled to v0.10.1, 2026-06-15)

The recommended first slices (§7) shipped in **v0.10.0**. Status per control — the §5 bodies below
retain the original design narrative, so cross-reference this table for what is actually built:

| Control | Status | Shipped | PR |
|---|---|---|---|
| H1 · inspect the unguarded JSON-RPC surface | ✅ shipped | v0.10.0 | #74 |
| H2 · hidden-character presence detector | ✅ shipped | v0.10.0 | #74 |
| H4 · field-level drift tiering + `list_changed` re-validation | ✅ shipped | v0.10.0 | #77 |
| H5 · initialize-handshake capability/grant drift | ✅ shipped | v0.10.0 | #79 |
| H7 · sampling/elicitation prompt-injection scan (slice A) | ◑ slice shipped | v0.10.0 | #78 |
| H7 · credential-phishing elicitation/sampling wedge (ROADMAP F6) | ✅ shipped | unreleased | — |
| H9 · fail-closed deny-by-default for un-guardable transport | ✅ shipped | v0.10.0 | #76 |
| H11 · supply-chain integrity tripwire (npm same-version, slice 1) | ◑ slice shipped | v0.10.0 | #81 |
| H11 · `up --frozen` fail-closed integrity BLOCK tier (ROADMAP F3) | ✅ shipped | unreleased | — |
| H3 · approval-time pinning | ○ deferred (value-thin vs first-session pin) | — | — |
| H6 · cross-origin dataflow correlator | ○ deferred (observability-first once FP measured) | — | — |
| H8 · keyed-MAC integrity for pins/policy | ○ deferred | — | — |
| H10 · tamper-evident MAC-chained event log | ○ deferred | — | — |
| H12 · per-server trust tier + FP budget | ○ deferred (build when consent-fatigue appears) | — | — |

H7 now also blocks **credential-phishing** elicitation/sampling prompts (ROADMAP F6 — two
`MCP-CREDENTIAL-PHISHING` signatures on the same server-initiated scan path). H7's remaining scope
(quota / consent-gating / hard credential-field block) and H11's remaining scope (multi-registry,
digest **BLOCK** / `--frozen`, Sigstore provenance) stay deferred — see §6 and ROADMAP F3/F8.

**Runtime containment now has an implementation.** Every H1–H12 control here is *detection*
(reasoning about JSON-RPC bytes); ROADMAP **F1 `guard --confine`** (a separate track — see
`docs/ROADMAP.md`) adds the first *enforcement* primitive by wrapping the relayed stdio child in an
OS sandbox (macOS Seatbelt/`sandbox-exec` in v1) so it physically cannot read secret files or
persist, regardless of the traffic it emits — complementary to frame detection (contain vs watch).
Shipped across #108/#109/#110/#111, macOS-only, opt-in, **unreleased (next minor)**.

---

## 0. The six principles (these govern every control below)

The adversarial pass showed that the *obvious* version of half these controls is security
theater or actively counterproductive. Every item in §5–§7 must obey:

1. **Never let server-declared metadata *lower* scrutiny.** Tool names, `readOnlyHint` /
   `destructiveHint`, declared OAuth scopes — all attacker-controlled. A control keyed on
   labels (dataflow sink detection, shadowing, risk-tiering, scope policy) is blinded by a
   server that lies in its labels. **Key on content and arg-shape; a self-declared hint may
   only *escalate* risk, never downgrade or auto-allow.**

2. **A control users turn off protects nothing.** Default-DENY on `sampling`/`elicitation`,
   and hard-BLOCK on resource-content scans, make *legitimate* servers fail with opaque
   JSON-RPC errors the client renders as "broken under mcpm" — and the user's remedy is to
   uninstall mcpm. The secure default must never make the secure path look broken.
   **Prefer prompt-on-first-use + persistent per-server allow over default-deny/block.
   Budget the *aggregate* noise across all controls in one session — not each control's FP
   rate in isolation.**

3. **Seeing the frame ≠ detecting the payload.** Extending inspection to a new carrier only
   means the (porous, 3-regex) scanner *runs* there. Regex cannot catch paraphrase. **Lean
   on phrasing-independent structural signals** (hidden-unicode presence; imperative +
   second-person + references-to-other-tools/`~/.ssh`; cross-origin data movement) over
   keyword packs.

4. **Probe ≠ runtime — and divergence *is* the attack.** Any install/health-check probe is
   fingerprintable; a server returns benign defs to the prober and malicious defs to the
   real session. **Pin under runtime-equivalent env, and treat first-runtime ≠ install-pin
   as a high-signal alarm, not a false positive to smooth over.**

5. **Fail closed.** A chokepoint with no fail-closed default is skippable by *degrading* it
   (crash the guard child, corrupt `pins.json`, route through an HTTP-transport server the
   relay never sees). **Integrity failure / guard error / un-guardable transport → DENY by
   default**, with an explicit downgrade flag.

6. **State boundaries; don't imply coverage.** Out of a stdio relay's reach by construction:
   downstream HTTP the server itself makes; *behavioral* rug-pull (identical schema,
   different behavior); the model re-typing a secret from its own context; a same-user
   postinstall that already executed code. Name these — a silent "covered" is worse than an
   admitted gap.

---

## 1. The two surfaces

| Surface | When | mcpm chokepoint | Coverage today |
|---|---|---|---|
| **Supply chain** — compromised package, malicious postinstall, maintainer takeover, mirror tampering | install-time | `scanner/` (metadata-only, no source download) + `stack/` lockfile | heuristic trust score + release-age cooldown; **no provenance/signature verification** |
| **Agent tool-calls** — poisoning, line-jumping, rug-pull, shadowing, result-injection, cross-server exfil, sampling abuse, consent fatigue | runtime | `guard/` stdio JSON-RPC MITM relay (sees both directions) | 4 inspected targets + structural drift pin |

The relay already has the two highest-leverage runtime seams **half-built** — the 4-target
signature inspector (`patterns.ts`) and the structural drift pin (`drift.ts` / `pins.ts`).
Most of this plan is *extension of existing seams*, not new architecture.

---

## 2. Threat catalogue

### Agent tool-call threats (runtime — what the relay can see)

| ID | Threat | Carrier frame(s) the relay sees |
|----|--------|----------------------------------|
| **T1** | Tool poisoning — malicious instructions hidden in tool `description`/`inputSchema`/`title` | `tools/list` result |
| **T2** | Line-jumping via `initialize` — `result.instructions` / `serverInfo` read into context before any call | `initialize` result |
| **T3** | Rug pull — definitions mutate *after* approval, via reconnect **or** `notifications/tools/list_changed` | `tools/list` result + the notification frame |
| **T4** | Tool shadowing / cross-server name collision / confused-deputy by reference | `tools/list` result (cross-server) |
| **T5** | Indirect injection via **results** — payload in `content[]`, `structuredContent`, or `isError`/error (ATPA, toxic triad) | `tools/call` result |
| **T6** | Cross-server exfil — data from server A smuggled into `tools/call` args to server B (GitHub-MCP, WhatsApp PoCs) | paired `tools/call` result → request |
| **T7** | Token over-scope / passthrough / OAuth consent-replay | install/config + (downstream HTTP — **not** on stdio) |
| **T8** | Sampling/elicitation abuse — injection via `sampling/createMessage` prompt, elicitation phishing, **compute/quota theft** | server→client `sampling/createMessage`, `elicitation/create` requests |
| **T9** | Consent / approval fatigue — defeating the human in the loop | meta (affects all approval gates) |

### Supply-chain threats (install-time — the relay cannot see these)

| ID | Threat | Lever |
|----|--------|-------|
| **S1** | Malicious postinstall / lifecycle script | `npx -y` / install auto-runs scripts |
| **S2** | Maintainer account takeover / token theft → trojaned version | published artifact differs from source |
| **S3** | Typosquatting / dependency confusion | name proximity to a trusted server |
| **S4** | Compromised registry/mirror returns forged metadata | `publishedAt` / `isVerifiedPublisher` / `downloadCount` are attacker-controlled |
| **S5** | Package-level rug pull — benign package turns malicious in a later version | trust established, then abused on update |
| **S6** | Self-propagating worm (credential-stealing) | combination of S1 + S2 at ecosystem scale |

---

## 3. What exists today (the seams to build on)

- **Relay (`relay.ts`):** spawns the real child, `wireDirection()` parses newline-framed
  JSON-RPC both ways; `action === "block"` drops the frame and synthesizes a `-32099
  BLOCKED` error (preserving id; notifications dropped silently). 64 MB/direction buffer cap.
- **Inspection (`patterns.ts inspectMessage` + `targetSubtree`):** exactly **4**
  `SignatureTarget`s — `tool_response`, `tool_call_args`, `tool_description`,
  `tool_annotations`. Each string leaf is `normalizeForMatch`-folded (NFKC + zero-width/bidi
  strip + confusable fold, ReDoS-bounded) then tested against **3** signatures in
  `signatures.ts` (`OWASP_MCP_TOP_10`). Severity → action: critical = block, high = warn.
- **Drift (`drift.ts` + `pins.ts`):** `hashToolDefinition` (canonical SHA-256 of
  description + schema + annotations) vs `~/.mcpm/pins.json`; mismatch = critical block.
  Per-session second-`tools/list` race guard (F3). **Capture is `first-session` only** — the
  `captured_via:'install'` path is typed but unused.
- **Policy (`run-inner.ts applyPolicy` + `policy.ts`):** `~/.mcpm/guard-policy.yaml`
  per-id overrides + `paused_until`; `applyPolicy` takes MAX action across all findings.
- **Secrets (`store/keychain.ts`):** per-server scoped secrets, ambient
  `OPENAI/AWS/GITHUB` tokens **not** forwarded; OS-keychain master key exists.
- **Scanner (`scanner/`):** install-time, metadata-only — `detectSecrets`,
  `detectPromptInjection`, `detectTyposquatting`, `detectExfilArgs`,
  `detectInstallScriptShape`; optional Tier-2 `mcp-scan`; release-age cooldown (split
  semantics: fail-open scoring, fail-closed armed gates).

### Confirmed gaps (from the code map)

| Gap | Detail |
|---|---|
| **G1** | `resources/*`, `prompts/*`, `sampling/*`, `elicitation/*`, `initialize.instructions`, `structuredContent` are **never inspected** |
| **G2** | HTTP/SSE-transport servers run with **zero** runtime inspection (relay only wraps stdio); silently skipped on Cursor |
| **G3** | No install-time pin capture → first run is **trust-on-first-use**; a born-poisoned server self-blesses its baseline |
| **G4** | `pins.json` / `guard-policy.yaml` integrity sidecars are **unkeyed SHA-256** — tamper-evidence, not authenticity; a same-user/postinstall process recomputes them |
| **G5** | `pause` / `mute` persist in that same user-writable file → relay silently neuterable |
| **G6** | 3 inline signatures, regex-only, vendored (not user-extensible); no semantic/behavioral detection |
| **G7** | No supply-chain provenance/signature verification; registry reads unauthenticated → forged metadata inflates trust |
| **G8** | Drift hash is **structural only** — behavioral rug-pull (same schema, different behavior) leaves no trace |
| **G9** | Inspection is **post-effect** — blocks the *result* reaching the model, not the server-side side effect already performed |
| **G10** | macOS key passed in argv (`ps` window); no-keychain fallback = machine-key, no file-exfil resistance |
| **G11** | `health-check.ts` forwards live secrets to the untrusted server during the post-install probe, before any `tools/list` is seen |

---

## 4. Honest boundaries (what mcpm cannot do — say it out loud)

- **Downstream egress** the server makes over its own HTTP is off the stdio channel (T7).
- **Behavioral rug-pull** (G8) — identical schema, different behavior — is invisible to a structural pin.
- **Model re-types the secret from context** instead of passing tainted bytes → no taint match can fire (T6 hard limit).
- **Same-user postinstall** that already ran code can often read the unlocked keychain / scrape the key from a running process → integrity (H8) raises cost, not a wall.
- **HTTP/SSE servers** (G2) get no relay coverage until a streamable-HTTP MITM relay exists (large, deferred). Until then: **deny-by-default with explicit downgrade**, not silent bypass.
- **The approval UI lives in the client** (Claude Desktop/Cursor), not mcpm — mcpm can annotate/sanitize frames and its own prompts, but cannot force scoped re-prompting in the client.

---

## 5. Hardening roadmap (critique-corrected)

> **Status note:** H1/H2/H4/H5/H7-A/H9/H11 below are **SHIPPED in v0.10.0** — see the *Delivery
> status* table at the top. The control bodies here are the original design narrative; they are not
> updated per-PR, so treat the table as the source of truth for what is live.

Impact ratings are **post-critique**: several draft "block" controls are demoted to
warn/observability until their FP rate is measured. Ordered by impact-to-effort.

### Tier 1 — close carrier blind spots (cheap, high-value, low-FP if done right)

#### H1 · Inspect the unguarded JSON-RPC surface  · `guard` · effort M · **impact High**
- **Seam:** `patterns.ts targetSubtree()` + `SignatureTarget` union (`types.ts`); wire through `run-inner.ts mergeInspect`.
- **Mechanism:** add inspected targets for `resources/read` content, `prompts/get` messages, `initialize.result.instructions`, and `result.structuredContent` (recursive string leaves); intercept `notifications/tools/list_changed` (→ H4). Reuse `normalizeForMatch` + `stringLeaves`.
- **Mitigates:** T1, T2, T3 (list_changed), T5 (structuredContent), T8 carriers.
- **Critique fix (load-bearing):** `initialize.instructions` and tool descriptions are *pre-invocation context* → may block on critical. **Resource/prompt content is retrieved *data* → warn-and-forward only.** Block-on-critical over a README / email / log / source file is a data-corruption generator. Gate "high-confidence" to markers co-occurring with imperative model-directed phrasing in short metadata fields, not anywhere in a multi-KB body.
- **Bypass / boundary:** novel paraphrase still passes (detection gap, not carrier gap — see H2 + principle 3). HTTP servers unseen (H9).

#### H2 · Hidden-character *presence* detector  · `guard`+`scanner` · effort S · **impact High**
- **Seam:** new check in `patterns.ts` / `signatures.ts`, run **before** `normalizeForMatch` strips them.
- **Mechanism:** flag the mere presence of zero-width / bidi-override / non-printable / ANSI-escape characters in any tool `description`, `inputSchema`, annotation, or `initialize.instructions` as a **high** finding.
- **Mitigates:** T1, T2. Phrasing-independent; today normalization *erases this signal silently*.
- **Critique note:** highest impact-to-effort in the set; near-zero FP. Both T1 and T2 name hidden-char presence as a standalone malice indicator that nothing currently flags.

### Tier 2 — rug-pull / drift (the F-series, hardened)

#### H3 · Approval-time pinning — kill trust-on-first-use  · `guard` · effort M · **impact High**
- **Seam:** `install.ts` (after the trust gate) + `up.ts processServer` → new `capturePinsFromListing()` → `pins.ts upsertToolPin` with `captured_via:'install'`; `drift.ts inspectForDrift`.
- **Mechanism:** capture a pin at install/approval, so a born-poisoned server's first runtime `tools/list` is compared to the install-time baseline instead of self-blessing.
- **Mitigates:** T3, T1. Closes G3.
- **Critique fix:** capture under **runtime-equivalent env/secrets/sandbox** (hard requirement, not a mitigation — the probe must be indistinguishable from a real session). **Treat probe-vs-runtime divergence as a high-signal ALARM, not an additive false positive** (benign-to-prober / malicious-to-client is *the* attack). Principle 4.

#### H4 · Field-level drift diff + in-flow re-consent + `list_changed` re-validation  · `guard` · effort M · **impact High**
- **Seam:** `drift.ts diffToolDefinition(old,new)`; `commands/guard.ts`; `notifications/tools/list_changed` handler.
- **Mechanism:** on `liveHash ≠ pinned`, emit a structured field-level diff (which of description/title/schema/annotations changed) and require re-consent. On `tools/list_changed`, force a fresh re-inspection against install pins **before forwarding** the notification.
- **Mitigates:** T3 (both reconnect and push channels).
- **Critique fix:** separate *cosmetic* drift (description wording → **warn + auto-reconcile + re-pin**) from *security-relevant* drift (type/required/destructive-hint/schema → **block**) — otherwise every legit server upgrade hard-fails. **Re-consent must be in-flow**, not a `mcpm guard approve-drift` terminal ceremony (the context-switch is the friction that gets guard disabled). Tolerate env-variant tool surfaces via additive-pin symmetry.

#### H5 · Pin the capability grants, not just tool defs  · `guard` · effort M · **impact Medium**
- **Seam:** `policy.ts` + `drift.ts`.
- **Mechanism:** pin a hash of approved `initialize.instructions` and of each per-server grant flag (`allow_sampling`, `allow_instructions`, `allow_unguarded`). A change on a later `initialize` = drift event requiring re-consent.
- **Mitigates:** T3 applied to grants, T8, T2.
- **Critique fix (missing-control):** tool-def pinning does **not** cover "behave benignly → earn the opt-in → mutate the capability later." Opt-in toggles are persistent grants and need the same drift treatment.

### Tier 3 — dataflow & sampling (reframe honestly)

#### H6 · Cross-origin dataflow correlator  · `guard` · effort L · **impact Medium (observability first)**
- **Seam:** stateful `InspectFn` on `relay.ts inspectParentRequest`/`inspectChildResponse`, session state in the `run-inner.ts` closure (in-memory, no backend, no disk).
- **Mechanism:** record fingerprints of cross-origin `tools/call` *result* content; on a later `tools/call` *request* into a different origin / egress-shaped sink, flag the chain (source tool → sink tool) to `guard-events.jsonl`.
- **Mitigates:** T5, T6.
- **Critique fix (major):** **Ship WARN-only / observability for the first release — do not block on dataflow until FP is measured.** "read file then post it" is the single most common agent action and over-fires. Key on the **cross-origin sequence + sink egress *shape*** (a *new* outbound URL/email/host in args after a cross-origin read) — **not** secret-pattern matching (misses plain-text private-source exfil, the flagship GitHub-MCP PoC), **not** entropy/base64 (UUIDs/JWTs/SHAs are benign), **not** attacker labels. Persistent cheap per-(source,sink) allow.
- **Boundary:** model-retypes-from-context and chunked/encoded exfil defeat byte-matching — **raises cost / catches known PoCs, not a complete IFC system.** State it.

#### H7 · Sampling/elicitation: prompt-on-first-use + scan-always + per-server quota  · `guard` · effort M · **impact Medium**
- **Seam:** `run-inner.ts inspectChild` (server→client requests); `policy.ts`.
- **Mechanism:** detect declared `sampling`/`elicitation` capability in the `initialize` handshake and prompt **once, up front**; scan every server-supplied sampling prompt regardless of opt-in; **rate-limit / quota per server even when opted-in**; hard-block elicitation forms requesting credential-shaped fields.
- **Mitigates:** T8 (all three sub-vectors, incl. compute/quota theft, which nothing else covers).
- **Critique fix:** **Not default-deny** (principle 2 — sampling is the canonical agentic mechanism; a synthesized error reads as "server broken under mcpm"). Surface the opt-in at connect-time, not as a runtime error.

### Tier 4 — defend the guard itself (integrity + fail-closed)

#### H8 · Keyed-MAC integrity for pins & policy  · `store` · effort M · **impact Medium**
- **Seam:** `pins.ts` / `policy.ts` integrity paths; `store/keychain.ts getOrCreateMasterKey`.
- **Mechanism:** replace unkeyed SHA sidecars with `HMAC(masterKey, fileBytes)`. Cap `paused_until` blast radius; a `mute` on a critical signature requires the keyed sidecar to take effect.
- **Mitigates:** protects the H1–H6 controls from being silently muted (G4, G5).
- **Critique fix / boundary:** raises bar "recompute a public hash" → "extract the keychain key" — but a same-user postinstall can often read the unlocked keychain (principle 6). On no-keychain fallback (CI/headless) authenticity downgrades to tamper-evidence → **surface it loudly and fail closed (H9), never silently degrade.** Make `pause` UX humane (single notice + quiet persistent indicator, not a per-session klaxon — that just trains banner-blindness).

#### H9 · Fail-closed posture  · `stack`+`guard` · effort S–M · **impact Medium**
- **Seam:** `run-inner.ts` startup; `wrap.ts` / `orchestrator.ts` / `install.ts resolveInstallEntry`; `stack` `allowUrlServers`.
- **Mechanism:** on pin-integrity failure, guard-child error, or un-guardable transport → **DENY** by default. Convert the silent HTTP/SSE bypass (G2) into **"unguarded = denied"** with an explicit `--allow-unguarded` downgrade, recorded per-server in the lockfile.
- **Mitigates:** meta — stops every detector from being skipped by inducing relay degradation.
- **Critique fix:** warn **once** at allow-time, then suppress unless the unguarded set *changes* (re-warning every `up` is fatigue → rubber-stamp). Mark unguarded servers visibly in status.

#### H10 · Tamper-evident event log  · `guard` · effort S · **impact Low–Medium**
- **Seam:** `event-log.ts`.
- **Mechanism:** append-only rolling MAC chain (each line MACs the prior line + master key) so truncation/rewrite of `guard-events.jsonl` is detectable.
- **Critique fix (missing-control):** H4/H6/H9 all rely on this log as durable forensic output, yet a same-user/postinstall attacker can erase it today.

### Tier 5 — install-time / supply-chain (the surface the relay can't reach)

#### H11 · Provenance + digest-pinning + postinstall policy  · `scanner`+`stack`+`registry` · effort M–L · **impact High**
- **Seam:** registry client; `lock.ts`; `scanner detectInstallScriptShape`; `stack/schema.ts` PolicySchema + `policy.ts checkTrustPolicy`.
- **Mechanism (four parts):**
  1. **Provenance verification** — verify npm/sigstore SLSA attestation at install; warn (or block under policy) on unsigned/unattested packages. *(mcpm already publishes itself with provenance as of v0.9.0 — consume the same on the install side.)*
  2. **Digest-pinned lockfile (F3)** — pin the resolved tarball integrity hash; re-verify on `mcpm up`; block on mismatch. The real defense against mirror-swap / post-publish tamper (S4) that forged metadata (G7) otherwise defeats.
  3. **Postinstall-script policy** — promote the existing `install-script` finding to a policy gate (block/quarantine servers whose install runs lifecycle scripts; prefer no-script invocation).
  4. **Publisher-change alarm** — flag "maintainer/publisher changed since last lock" (S2/S5 takeover signal), alongside the existing release-age cooldown.
- **Mitigates:** S1–S6.
- **Boundary:** an obfuscated payload inside a script you *do* run is not statically defendable — provenance + pinning + "prefer no-install-script servers" is the lever, not deeper regex.

### Cross-cutting (the two things the whole roadmap was missing)

#### H12 · Per-server trust tier + false-positive budget  · `stack` + test harness · effort M · **impact High (enabler)**
- **Mechanism:** a "trusted once" per-server tier that suppresses redundant re-consent (drift, dataflow, instruction, collision) for a vetted server; plus a measured benign-corpus FP rate per control, with a threshold above which a control ships **warn-only**.
- **Why it's load-bearing:** without a coherent trust model, every control re-litigates trust independently and the *aggregate* prompt load — H1+H4+H6+H9 firing in one legit multi-server session — is what drives a user to disable the guard. This gates the safety of everything else.

---

## 6. Deferred / explicitly out of scope (for now)

| Item | Why deferred |
|---|---|
| Streamable-HTTP MITM relay | large; the only true fix for G2. Until then, H9 makes the gap *visible*, not closed. |
| Behavioral (non-schema) rug-pull detection | requires runtime-invariant observation; partially bridged by H6, otherwise out of relay scope (G8). |
| OAuth consent-replay / static-`client_id` proxy handling (T7-ii) | mcpm injects static secrets and does not broker OAuth flows — **scope out explicitly**, don't mark T7 "covered." |
| Tool name-qualification rewrite (`server__tool`) | breaks clients that hardcode bare names; keep opt-in. The cross-server-*reference* scan on **normalized** names (catches homoglyph/whitespace shadowing) is the useful half. |
| Semantic/LLM-based injection detection | needs a backend; violates local-first. Structural signals (H2) are the local-first substitute. |

---

## 7. Recommended first slice

Build **H1 + H2 + the probe-divergence alarm of H3**, with **H9 (fail-closed)** landing
*before* any new blocking control so degradation can't silently skip everything:

1. **H2** (hidden-char presence) — smallest, highest impact-to-effort, near-zero FP.
2. **H1** (carrier surface, warn-only on retrieved data) — closes the biggest blind spot (G1) without UX landmines.
3. **H9** (fail-closed + unguarded-visible) — the keystone; makes the chokepoint actually a chokepoint.
4. **H3/H4** (approval-time pin + field-level drift, in-flow re-consent) — completes the rug-pull story you started with the F-series.

Defer H6 (dataflow) until it can ship as labeled observability with a measured FP rate, and
do **H12** (trust tier) alongside the first blocking control, not after.

> Each slice should go through the same design → build (TDD) → review → dogfood loop used for
> F4 (PR #70). Every control ships with its benign-corpus FP rate measured and its bypass /
> boundary documented inline — no control claims to "close" a threat it only raises the cost of.
