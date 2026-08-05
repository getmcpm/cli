# mcpm-guard signature reference (v0.5.0)

The shipped signature catalog + how to add one. See `docs/GUARD.md` for the runtime model.

## Currently shipped (13 catalog entries)

| id | category | severity | target | description |
|---|---|---|---|---|
| `owasp-mcp-2-instruction-injection-in-response` | OWASP-MCP-2 | critical | tool_response | Imperative instructions in tool response content (Ignore previous / Disregard prior / Forget all / You are now in developer mode / `<\|system\|>`) |
| `owasp-mcp-7-path-exfil-in-args` | OWASP-MCP-7 | high | tool_call_args | Sensitive file paths in tool arguments (.ssh / .aws/credentials / .env / id_rsa / .gnupg / .kube/config) |
| `owasp-mcp-1-tool-description-injection` | OWASP-MCP-1 | critical | tool_description | Instruction-shaped text in tool descriptions (poisoning / rug-pull patterns) |
| `owasp-mcp-2-instruction-injection-in-resource` | OWASP-MCP-2 | critical | resource_content | Imperative instructions in retrieved `resources/read` content (warn-and-forward — retrieved data) |
| `owasp-mcp-2-instruction-injection-in-prompt` | OWASP-MCP-2 | critical | prompt_content | Imperative instructions in a server-provided `prompts/get` template (warn-and-forward — retrieved data) |
| `owasp-mcp-1-initialize-instruction-injection` | OWASP-MCP-1 | critical | initialize_instructions | Instruction-shaped text in `initialize` instructions / serverInfo (line-jumping, block-capable pre-invocation context) |
| `credential-phishing-wallet-solicitation` | MCP-CREDENTIAL-PHISHING | critical | prompt_content | Server-initiated prompt soliciting a crypto-wallet seed/recovery phrase, mnemonic, or wallet private key (drainer phishing) |
| `credential-phishing-financial-solicitation` | MCP-CREDENTIAL-PHISHING | critical | prompt_content | Server-initiated prompt soliciting a card CVV/CVC, SSN, or card/bank PIN (financial phishing) |
| `exfil-param-in-schema` | OWASP-MCP-1 | critical | tool_description | **Structural** (no regex): a `tools/list` tool declares an input-schema parameter named with the context-exfil sigil convention (`_system_prompt_`, `_conversation_history_`, `_chain_of_thought_`, `_reasoning_trace_`, `_context_window_`, `_exfil*`) — the model auto-fills it, leaking context. Blocks the server's tool list at advertisement time. Emitted by `detectExfilParams` (a property-KEY walker), not the regex engine — the catalog entry carries empty `patterns` so the id is muteable/listable. |
| `credential-egress-in-response` | MCP-CREDENTIAL-EXFIL | high (→ warn) | tool_response | **F10 credential DLP.** High-confidence, prefix-anchored credential material in a tool response (PEM private key, GitHub classic + fine-grained PAT, GitLab, OpenAI, Anthropic, Stripe, Google, npm, Slack token, AWS access-key id) — a data-loss / credential-egress signal. WARN-tier (forwarded, not blocked): a secrets-manager/auth tool legitimately returns credentials → promote-to-block per policy. Only STRUCTURAL shapes (no prose FP); AWS's docs `AKIAIOSFODNN7EXAMPLE` excluded; generic Bearer/bare-JWT/40-char-base64 deferred to the suspect tier. `redact: true` keeps the caught secret out of the event log and message. |

Plus three entries that carry **no patterns** — they are emitted by dedicated passes
rather than by a content regex, and exist in the catalog so their ids are
recognized by `guard mute`, `guard list-signatures`, and policy overrides:

- `hidden-chars-in-metadata` (OWASP-MCP-1; tool_description / tool_annotations /
  initialize_instructions) — the H2 presence detector: zero-width, bidi, C0/C1
  controls, ANSI ESC, and the Unicode tag block. Scoped to metadata on purpose —
  an invisible character in a fetched log, source file, or email is common and
  benign, so scanning retrieved data for the whole class would be an FP factory.
- `unicode-tag-concealment` (OWASP-MCP-1; the carriers H2 skips — tool_response /
  tool_call_args / resource_content / prompt_content, and sampling_prompt by
  re-tagging) — the **tag-block-only** presence floor. The tag block is the one
  part of the hidden-character class that is safe to scan in retrieved data,
  because it differs in FREQUENCY: outside an emoji subdivision flag it does not
  occur in real text. (Note the frequency argument, not a deprecation one —
  U+E0020–U+E007F were *un*-deprecated in Unicode 9.0 to carry emoji tag
  sequences; only U+E0001 LANGUAGE TAG remains deprecated.) `high` → warn, so on
  retrieved data it annotates and forwards. Disjoint from
  `hidden-chars-in-metadata` by carrier, so a tag character is reported once.
- `guard-inspection-truncated` (MCP-GUARD-INTEGRITY; emitted on whichever carrier
  was truncated) — raised when the leaf-walk budget is exhausted, i.e. the guard
  did **not** finish reading the frame. `critical`, so it rides the normal carrier
  policy: blocks on block-capable carriers, clamps to warn on retrieved-data ones.
  Budget exhaustion used to fail **open** (a silent return), which was a complete
  detection bypass — ~73 KB of junk padding hid a critical injection. Fixed in
  v0.26.0; this entry is the visible half of that fix.

> **Note on Unicode tag-block concealment ("ASCII smuggling").** U+E0020–U+E007E are a shadow copy of printable ASCII, so a payload written in them renders as nothing while a model that decodes tag codepoints reads it plainly ([arXiv 2607.05744](https://arxiv.org/abs/2607.05744), which reported the technique beating string-matching sanitizers in 4 of 8 tests). The guard handles it in **two passes with different jobs**. (1) `inspectTagEncoded` decodes the tag characters back to ASCII and re-runs the *carrier's own signatures*, so a concealed payload is judged by what it SAYS — this is what keeps `sampling_prompt` block-tier: a TAG-encoded wallet-seed solicitation reaches `credential-phishing-wallet-solicitation` and is blocked with a reply to the server. All tag characters in a leaf decode as ONE payload, because decoding each run separately would let an attacker interleave a visible character so no single run spelled a matchable phrase. (2) `unicode-tag-concealment` is the floor beneath it, for a payload that is concealed but matches no signature. Unlike the base64 pass, tag-decoded findings are **not** clamped to warn: base64 is everywhere in benign data, which makes a decoded match weak evidence, whereas a tag run that decodes to a signature-matching phrase is *stronger* evidence than the same phrase in plaintext — concealment is not something benign content does. The two passes compose (base64 wrapping a tag-encoded payload is caught, at the base64 layer's warn tier); base64-of-base64 still evades, unchanged. Before v0.28.0 this class was a detection HOLE and not merely an FP risk: `PATTERN_BREAKERS` strips tag characters *before* matching, so a fully encoded phrase was erased rather than revealed, and presence detection ran on metadata only — every other carrier scored zero findings.
>
> **How the decoded pass avoids re-reporting text you can already read (TODOS #34).** Pass (1) must not block an article that merely *quotes* an attack phrase, so a decoded finding is dropped when the same finding is visible without decoding. That comparison was originally keyed on the match's **rendered text**, and both sides of it are attacker-written: a visible phrase preceded by any character outside `[\s.,;:!?]` matches the relaxed pattern without being reported itself, and cancelled the concealed payload -- `block` became `warn`. It is now an **occurrence count** against a masked copy of the same segment (each concealed character replaced by NUL): a match whose literals came from concealed text is absent from the masked view and survives as surplus, while a visible phrase appears in both views and cancels itself however often it is repeated. Decoys cannot inflate the masked side, because each one adds to both. Counting also sidesteps a trap that killed two earlier designs -- a positional comparison needs the two views to share a coordinate space, and NFKC can compose a decoded character with a following combining mark, shrinking one view and not the other. Occurrences are counted exactly. An earlier version stopped at 256 matches per pattern and had to interpret the cap, which has no answer that is right in both directions: treating it as concealed fabricated a `block` on a benign prompt-injection dataset, and treating it as visible let 256 decoys suppress a real payload. Counting costs one map operation per match and the scanned string is already bounded by the 64 KB head+tail window, so the bound bought nothing; what remains is an unreachable runaway backstop for a hypothetical future pattern short enough to match tens of thousands of times.

> **Note on the emoji subdivision flag carve-out.** 🏴󠁧󠁢󠁳󠁣󠁴󠁿 is built from tag characters, so before v0.28.0 any server whose description carried an England/Scotland/Wales flag raised a poisoning warning on every `tools/list` — a live false positive in a zero-FP detector. The carve-out validates the **whole sequence** and is **RGI-exact** (`gbeng` / `gbsct` / `gbwls` only). Both properties are load-bearing. A per-character flank test — the shape of the existing ZWJ carve-out — would let an attacker write 🏴 + TAG(payload) and suppress detection wholesale; a shape-based whole-sequence rule is barely better, since "ignore" is six lowercase letters, so 🏴+TAG("ignore")+CANCEL is well-formed and such sequences chain to spell anything. Nothing legitimate is lost: a non-RGI sequence renders as a bare black banner. Fixtures pin both the FP and the chaining bypass, and benign emoji-tag-sequence fixtures had to be **added** for the zero-FP claim to mean anything — the prior corpus contained no tag codepoints at all, so a tag-block detector would have scored 0 FP against it by vacuity.

> **Note on `exfil-param-in-schema` (F5).** Deny-tier and **zero-FP by design**: only the underscore-*wrapped* sigil form is matched (`_system_prompt_`), because a block on a `tools/list` frame disables the server's **entire** tool surface — so a false positive would brick a legit server. Bare names a real tool may use (`system_prompt`, `messages`, `reasoning`) and agent-framework runtime slots (`_context_`, `_memory_`, `_thinking_`) are **excluded**. It is a tripwire for the documented HiddenLayer/CyberArk convention — a **renamed** parameter (`systemPrompt`, `sys_prompt`, `context_dump`) evades it; the broader description-cross-check and bare-name SUSPECT tier are deferred (FP-laden). Keys are normalized (NFKC + confusable-fold + separator/camelCase canonicalization) before matching, so homoglyph/zero-width/`_systemPrompt_` variants still match.

> **Note on the two `MCP-CREDENTIAL-PHISHING` signatures.** They target `prompt_content` but their real value is on the **server-initiated** path: `inspectServerInitiated` (run-inner.ts) wraps a `sampling/createMessage` or `elicitation/create` request into a synthetic `prompts/get` frame, scans it, and **re-tags** any finding to the block-capable `sampling_prompt` carrier — so a credential-phishing *prompt* is blocked (error routed back to the server), while the same string in a passive retrieved `prompts/get` template stays warn-only. Both patterns are **solicitation-anchored** (an imperative verb + the credential noun) so a benign mention in replayed conversation history or field-name prose does not fire, and `[\s-]*` separators keep a zero-width-split evasion (`seed​phrase`) matching after `PATTERN_BREAKERS` strips the separator. Generic api-key/password/token solicitation is intentionally out of scope (a server collecting its own config secret is the common legitimate case); OTP/verification-code is deferred (self-pairing is indistinguishable from relay-phishing without provenance).

Plus the runtime drift detectors (`schema-drift`, `schema-drift-cosmetic`, `schema-drift-in-session`) — emitted by the relay, not by the signature engine. Drift is classified per changed field (H4): a **description-only** change is `schema-drift-cosmetic` (severity high → warn, forwarded — the parallel `tool_description` pattern scan still blocks any regex-detectable injection on the same frame, since the relay takes the MAX action); a **schema or annotations** change — or any pre-H4 pin with no stored field hashes — is `schema-drift` (critical → block). A server→client `notifications/tools/list_changed` arms a single-shot re-validation so an *announced* upgrade is classified against the pin rather than tripping the same-session guard. Cosmetic warn is bounded by the pattern-engine regex floor (a paraphrased poison the regexes miss degrades to a forwarded warn — the opt-in LLM-judge tier is the V2 answer, not the drift tier).

> **Not signatures: confine + orig-hash spawn events.** The `--confine` OS-sandbox primitive (F1, released in v0.16.0) adds **no OWASP signatures** — the catalog above is unchanged by confine (13 entries over 8 inspected targets). It emits relay/spawn **events** (not detection signatures) to `guard-events.jsonl`: category `CONFINE` — `confine-applied`, `confine-hash-mismatch`, `confine-marker-stripped`, `confine-profile-missing`, `confine-backend-missing`, `confine-marker-malformed`; plus category `RELAY` — `orig-hash-mismatch` (the wrap marker's `--orig-hash` verified at spawn, #108). These reason about spawn-time enrollment/integrity, not JSON-RPC frame content, so they are outside the signature engine.

## Action mapping

- **critical → block** by default
- **high → warn** by default (forwards traffic; promote to block via policy)
- **medium / low → log_only**

Policy overrides in `~/.mcpm/guard-policy.yaml` can promote, demote, or mute any signature per-id. See `docs/POLICY.md`.

## Inspection model

For every JSON-RPC message:

1. Extract the subtree matching each signature's `target`:
   - `tool_response` → `result.content`, `result.structuredContent`, and JSON-RPC error objects (only when present) — errors are scanned to prevent injection evasion via error messages
   - `tool_call_args` → `params.arguments` of `tools/call`
   - `tool_description` → `result.tools[*].description`, `result.tools[*].title`, and full `result.tools[*].inputSchema` including nested property descriptions/enums (only when present) — inputSchema is scanned because poison can hide in parameter descriptions
   - `tool_annotations` → `result.tools[*].annotations`
2. Walk every string leaf in the subtree (depth-bounded at 32).
3. NFKC-normalize the leaf + strip zero-width / bidi / Unicode-tag control chars (anti-evasion).
4. Test each signature's regex patterns against the normalized leaf.
5. First match per signature wins (no double-counting).
6. **Decode-and-rescan (F10 Detector-B)** — on the server-returned-data carriers (`tool_response`, `resource_content`, `prompt_content`) only, each leaf's bounded base64/base64url runs are decoded and the SAME carrier's signatures re-run on the decoded text, so an encoded injection or credential can't hide behind an encoding. Every finding recovered this way is tagged `decoded` and is **WARN-only** (never block — the decode is heuristic), so Detector-B is strictly additive (pass→warn). Guardrails: only runs that decode to **printable text** are rescanned (binary blobs — images/audio/gzip/hashes — are dropped, preserving the deferred-blob decision); ≤64 decode attempts/leaf (the `Buffer.from` bound), of which ≤8 texty decodes are rescanned, all bounded to the 64 KB head+tail window; no hidden-char scan on decoded bytes. **Blind spots (by design):** double/nested encoding is not re-decoded (one round only); an attacker who controls a response can still hide a payload behind ≥8 base64 blobs that themselves decode to text, or past the 64th candidate (non-texty/binary padding does not work); percent- and hex-encoding are deferred (URL/hash candidate volume is huge and the in-response carrier is rare); non-Latin UTF-8 payloads fall below the printable-ASCII gate. A `catalog` caveat: the decoded path stays FP-free **only** while signatures remain prefix/phrase-anchored — do NOT add a loose generic-secret or entropy rule (it would false-positive on decoded benign text).

## Signature shape (TypeScript)

```typescript
interface Signature {
  readonly id: string;                    // "owasp-mcp-N-short-name"
  readonly category: string;              // "OWASP-MCP-N"
  readonly severity: "critical" | "high" | "medium" | "low";
  readonly description: string;           // human-readable
  readonly target:                        // see src/guard/types.ts SignatureTarget
    | "tool_response" | "tool_call_args" | "tool_description" | "tool_annotations"
    | "resource_content" | "prompt_content" | "initialize_instructions" | "sampling_prompt";
  readonly patterns: readonly RegExp[];   // NFKC-tolerant regexes; whitespace via [\s-]* (zero-width-evasion safe)
  readonly remediation: string;           // actionable string; shown to user on block
}
```

## Anti-evasion checklist for new patterns

When you write a new regex, validate it against these evasion shapes:

1. **NFKC fold:** does `pattern.test("string".normalize("NFKC"))` match for full-width Latin variants?
2. **Zero-width insertion:** does the pattern still match with U+200B / U+200C / U+200D between key words? (Guard strips these before matching, so the answer should always be yes.)
3. **Whitespace alternation:** use `[\s]+` for word separators — literal spaces are bypassed by newline / tab / multi-space.
4. **Vocabulary synonyms:** include "ignore", "disregard", "forget" (or whichever set is canonical for the attack class).
5. **ReDoS safety:** no nested quantifiers (`(.*ignore.*)+` is a footgun). Test against a 100KB pathological input — should complete in < 1ms.

## Adding a signature (PR template)

```markdown
## Signature: <id>

**Category:** OWASP-MCP-N (or a descriptive class, e.g. MCP-CREDENTIAL-PHISHING, when the OWASP v0.1 numbering doesn't cleanly map)
**Severity:** critical | high | medium | low
**Target:** tool_response | tool_call_args | tool_description | tool_annotations | resource_content | prompt_content | initialize_instructions | sampling_prompt

**Attack vector:** <one paragraph; cite public disclosure URL if applicable>

**Regex patterns:**
```
/regex-1/i
/regex-2/i
```

**Remediation text shown on block:**
> <copy of the remediation string>

**Fixture coverage:**
- `src/guard/__tests__/fixtures/mcptox/attacks/<name>.json` — must trigger
- `src/guard/__tests__/fixtures/mcptox/benign/<adjacent-benign>.json` — must NOT trigger (or extend the corpus to cover the FP risk)

**Anti-evasion checklist:** (paste each item with ✓/✗)
1. NFKC fold:
2. Zero-width:
3. Whitespace alternation:
4. Vocabulary synonyms:
5. ReDoS safety:
```

## When NOT to add a signature

- **The attack class is already covered.** Extend an existing pattern instead.
- **The attack is too specific to one server.** Use a policy override per-server in user docs.
- **The pattern would false-positive on benign content.** Validate against the FP-rate corpus (`src/guard/__tests__/fixtures/legitimate-corpus/`).
- **The pattern requires LLM-as-judge to disambiguate.** Defer to the V2 opt-in LLM-as-judge tier — flag in TODOS.

## Signature versioning

The shipped set is vendored at `src/guard/signatures.ts`. Each pin in `~/.mcpm/pins.json` records the `signature_list_version` active at capture time (`owasp-mcp-top-10@v0.5.0`). Bumping the version is a normal release operation; users see signature changes in the CHANGELOG.

Separate signature repo + signature signing infrastructure are deferred (V2 / until update cadence requires faster releases than @getmcpm/cli's normal cycle).
