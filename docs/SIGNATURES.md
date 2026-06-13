# mcpm-guard signature reference (v0.5.0)

The shipped signature catalog + how to add one. See `docs/GUARD.md` for the runtime model.

## Currently shipped (3 signatures)

| id | category | severity | target | description |
|---|---|---|---|---|
| `owasp-mcp-2-instruction-injection-in-response` | OWASP-MCP-2 | critical | tool_response | Imperative instructions in tool response content (Ignore previous / Disregard prior / Forget all / You are now in developer mode / `<\|system\|>`) |
| `owasp-mcp-7-path-exfil-in-args` | OWASP-MCP-7 | high | tool_call_args | Sensitive file paths in tool arguments (.ssh / .aws/credentials / .env / id_rsa / .gnupg / .kube/config) |
| `owasp-mcp-1-tool-description-injection` | OWASP-MCP-1 | critical | tool_description | Instruction-shaped text in tool descriptions (poisoning / rug-pull patterns) |

Plus the runtime drift detectors (`schema-drift`, `schema-drift-cosmetic`, `schema-drift-in-session`) — emitted by the relay, not by the signature engine. Drift is classified per changed field (H4): a **description-only** change is `schema-drift-cosmetic` (severity high → warn, forwarded — the parallel `tool_description` pattern scan still blocks any regex-detectable injection on the same frame, since the relay takes the MAX action); a **schema or annotations** change — or any pre-H4 pin with no stored field hashes — is `schema-drift` (critical → block). A server→client `notifications/tools/list_changed` arms a single-shot re-validation so an *announced* upgrade is classified against the pin rather than tripping the same-session guard. Cosmetic warn is bounded by the pattern-engine regex floor (a paraphrased poison the regexes miss degrades to a forwarded warn — the opt-in LLM-judge tier is the V2 answer, not the drift tier).

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

## Signature shape (TypeScript)

```typescript
interface Signature {
  readonly id: string;                    // "owasp-mcp-N-short-name"
  readonly category: string;              // "OWASP-MCP-N"
  readonly severity: "critical" | "high" | "medium" | "low";
  readonly description: string;           // human-readable
  readonly target: "tool_response" | "tool_call_args" | "tool_description" | "tool_annotations";
  readonly patterns: readonly RegExp[];   // NFKC-tolerant regexes; whitespace via [\s]+
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

**Category:** OWASP-MCP-N
**Severity:** critical | high | medium | low
**Target:** tool_response | tool_call_args | tool_description | tool_annotations

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
- **The pattern requires LLM-as-judge to disambiguate.** Defer to the v0.5.1+ judge tier — flag in TODOS.

## Signature versioning

The shipped set is vendored at `src/guard/signatures.ts`. Each pin in `~/.mcpm/pins.json` records the `signature_list_version` active at capture time (`owasp-mcp-top-10@v0.5.0`). Bumping the version is a normal release operation; users see signature changes in the CHANGELOG.

Separate signature repo + signature signing infrastructure are deferred to v0.7 (TODOS).
