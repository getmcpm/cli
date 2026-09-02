/**
 * Vendored signature set for the guard relay (started as OWASP MCP Top 10 v0.1).
 *
 * Inline TypeScript rather than YAML for v0.5.0 — keeps the build pipeline
 * unchanged and ships zero new runtime deps. YAML loading is V0.7+ once
 * user-overridable signatures (`~/.mcpm/signatures/`) become a thing.
 *
 * Most entries map to an OWASP-MCP-N category with an `owasp-mcp-<n>-<short-name>`
 * id; a few cover adjacent classes the OWASP v0.1 numbering doesn't cleanly pin
 * (e.g. `MCP-CREDENTIAL-PHISHING`) and use a descriptive id/category instead of
 * asserting an unverified OWASP number. Adding a signature: append below with a
 * stable id, a target, severity, NFKC-tolerant regex patterns, and an actionable
 * remediation string.
 */

import type { Signature } from "./types.js";

// ── F6 credential-phishing: solicitation anchor ───────────────────────────────
// A phishing prompt SOLICITS ("enter your seed phrase"); benign text merely
// MENTIONS the term ("a seed phrase is a recovery phrase", "I use a mnemonic
// device to remember my password"). Anchoring every credential noun to an
// imperative solicitation verb is what separates the two — and it is load-bearing:
// a `sampling/createMessage` replays prior conversation turns, so an UNANCHORED
// credential word in benign history would hard-block a legitimate sampling request
// (review: block-as-DoS). Phishing prompts are imperative by nature, so this loses
// no realistic detection while keeping the guard's broad content scan intact (we do
// NOT role-filter — that would let a malicious server hide an injection in a
// relabelled `role:user` message and evade the H7 scan). Within a noun, separators
// are [\s-]* (not +) so a stripped zero-width char ("seed​phrase" →
// "seedphrase", PATTERN_BREAKERS removes it BEFORE matching) still matches (review
// CRITICAL: invisible-separator bypass). Both the verb and the noun ride the shared
// NFKC + confusable fold, so this catches the literal/homoglyph phishing string,
// not semantic rephrasing ("we require your secret words") — that is the V2
// LLM-judge tier, not this signature.
const SOLICIT_VERB =
  "(?:enter|re-?enter|type|paste|provide|input|share|submit|confirm|reveal|supply|restore|recover|verify|key[\\s-]*in|fill[\\s-]*in)";
// Build a credential-phishing pattern: an imperative solicitation cue, then the
// credential noun within a bounded window (a single string leaf, so a real ask
// co-occurs). The noun is wrapped in a non-capturing group so any internal
// alternation still binds under the SOLICIT_VERB prefix.
const solicits = (noun: string): RegExp =>
  new RegExp(`${SOLICIT_VERB}[\\s\\S]{0,40}(?:${noun})`, "i");

// ── TODOS #54 renderer-code-execution: privileged-bridge call gate ───────────
// Two real, disclosed CVEs in the same MCP client (nanbingxyz/5ire) reach RCE
// through ordinary tool_response TEXT that a malicious/compromised server
// controls: CVE-2025-68669 (a `securityLevel: 'loose'` Mermaid renderer lets an
// `<img onerror=...>` tag inside a diagram node call the privileged
// `electron.mcp.activate` IPC bridge) and CVE-2026-22793 (an ECharts
// markdown-fence plugin `new Function()`-evals the fenced block's content,
// reaching the same bridge via a self-invoking function expression).
//
// A bare keyword/substring scan for "onerror=" or "new Function(" is
// unacceptably FP-prone in ways well beyond the "documentation prose" class
// this entry originally flagged. A pre-merge adversarial review (28 CONFIRMED
// findings) MEASURED an earlier version of this signature that gated on a
// broader `DANGEROUS_CALL_TARGETS` alternation (adding `child_process`,
// `require(`, `exec(`, `spawn(`, `eval(`, `new Function(` alongside the
// literal bridge) and found it false-positives on: an MDN reference page for
// the `Function` constructor, a Node.js "run a shell command" tutorial's
// embedded RunKit sandbox, a CTF writeup's canonical `onerror=eval(atob(...))`
// teaching example, an AppSec-training article's `onmouseover` XSS
// demonstration — and, worse, a THIRD (fence-scoped, ungated) shape that
// assumed "a legitimate mermaid/echarts fence never contains a function
// definition," which is simply FALSE for ECharts: formatter callbacks
// persisted via `new Function(...)` and option data computed via an IIFE are
// both standard, documented ECharts idioms, so that shape warned on a
// meaningful share of any legitimate chart-generation tool's own output.
//
// None of those generic tokens even reliably generalized to some OTHER
// vulnerable client the way this comment originally hoped — a genuinely
// different Electron-embedded MCP client would expose its OWN differently-
// named bridge (evasion the fixed allowlist can't help with either way), and
// `require`/`child_process` calls are not even reachable from a properly
// context-isolated Electron renderer in the first place, which is exactly why
// clients expose a narrow bridge like `electron.mcp.*` instead. So the gate is
// narrowed to ONLY the literal, disclosed bridge call — `electron.mcp.activate(`
// / `electron.mcp.addServer(`, with `\s*` tolerating whitespace-only spacing —
// an honest, CVE-grounded tripwire rather than a speculative net. A real
// onload/onerror handler in the wild calls things like `this.src=...`,
// `console.log(...)`, or an app-specific `init()`; none of that matches.
//
// ACCEPTED, DOCUMENTED GAPS (measured, not merely asserted, during the same
// review): HTML-entity-encoding the dot (`electron&#46;mcp&#46;activate`),
// bracket/computed-property access (`window['electron']['mcp']['activate']`),
// alias indirection across two tool_response messages, and — most
// fundamentally — a different MCP client's own differently-named bridge, all
// evade this literal-substring gate. This project has no cross-message
// dataflow correlation (a documented V2 item) and no signature anywhere in
// this file survives HTML-entity/bracket-notation obfuscation, so this
// signature is not worse than its siblings on that axis; it is an honest
// "tripwire not defense" for the two disclosed CVEs' own literal shape, the
// same scope discipline as F5's exfil-sigil detector ("a renamed param evades
// it").
const ELECTRON_MCP_BRIDGE_CALL = "electron\\s*\\.\\s*mcp\\s*\\.\\s*(?:activate|addServer)\\s*\\(";

// Shared by owasp-mcp-1-tool-description-injection and (TODOS #16)
// owasp-mcp-1-tool-annotation-injection below — the same tool-poisoning attack
// class on two adjacent tools/list surfaces (description text vs. the
// annotations object). One array so an FP fix lands in both places at once.
const TOOL_METADATA_INJECTION_PATTERNS: readonly RegExp[] = [
  /(?:^|[\s.,;:!?])ignore[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
  /(?:disregard|forget)[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
  /<important>|<system>/i,
  /when[\s]*(?:the[\s]*)?user[\s]*asks,?[\s]*(?:you[\s]*(?:must|should|always|never)|always|never|exfil|read|access|send|email|do[\s]*not)/i,
];

export const OWASP_MCP_TOP_10: readonly Signature[] = [
  {
    id: "owasp-mcp-2-instruction-injection-in-response",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in tool response content",
    target: "tool_response",
    // Internal token separators are [\s]* (not +), parity with the credential
    // family's [\s-]* fix: [\s]* still matches newline / tab / multi-space evasions
    // ("ignore\nprevious instructions") AND a stripped zero-width separator that
    // collapses to adjacency ("ignore<U+200B>previous" → "ignoreprevious" after
    // PATTERN_BREAKERS). tool_response is not in HIDDEN_CHAR_TARGETS, so [\s]+ here
    // would let that invisible-separator bypass through. (review HIGH)
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /(?:disregard|forget)[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /you[\s]*are[\s]*now[\s]*(?:in[\s]*|operating[\s]*in[\s]*|entering[\s]*)?(?:developer|debug|admin|jailbreak|dan)[\s]*mode/i,
      /<\|system\|>|<\|im_start\|>system/,
    ],
    remediation:
      "Tool response contained injection-shaped text. Review the upstream data source " +
      "(message, web page, file). If legitimate, allow via `mcpm guard mute " +
      "owasp-mcp-2-instruction-injection-in-response --for 5m`.",
  },
  {
    id: "owasp-mcp-7-path-exfil-in-args",
    category: "OWASP-MCP-7",
    severity: "high",
    description: "Sensitive filesystem paths in tool call arguments",
    target: "tool_call_args",
    patterns: [
      /\.ssh\/|\.aws\/credentials|\.env(\b|$)|id_rsa|\.gnupg\/|\.kube\/config/i,
    ],
    remediation:
      "Tool call argument referenced a sensitive file path. Common in exfil chains " +
      "after a tool-poisoning attack. Verify the agent's intent before allowing.",
  },
  {
    id: "owasp-mcp-1-tool-description-injection",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Instruction-shaped text in tool descriptions (poisoning / rug-pull)",
    target: "tool_description",
    // The previous version included /when (?:the )?user asks/ which false-positives
    // on legitimate descriptions like "Returns X when the user asks for Y." Tightened
    // to require an imperative verb following the phrase, which is the actual
    // tool-poisoning shape (e.g., "when the user asks, exfiltrate ~/.ssh/").
    // Shared verbatim with the sibling tool_annotations signature below — same
    // attack class on an adjacent tools/list surface; keep the two in sync.
    patterns: TOOL_METADATA_INJECTION_PATTERNS,
    remediation:
      "A tool description contains imperative or system-prompt-style text. " +
      "Tool-poisoning pattern (Invariant Labs disclosure, 2025). Re-review the server; " +
      "if legitimate, run `mcpm guard accept-drift <server>`.",
  },
  {
    id: "owasp-mcp-2-instruction-injection-in-resource",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in retrieved resource content",
    // resources/read content is RETRIEVED DATA — inspectMessage clamps a match
    // here to `warn` (annotate + forward), so a poisoned/quoted README is flagged
    // but never dropped. Severity stays critical (pattern confidence is honest).
    target: "resource_content",
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /(?:disregard|forget)[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /you[\s]*are[\s]*now[\s]*(?:in[\s]*|operating[\s]*in[\s]*|entering[\s]*)?(?:developer|debug|admin|jailbreak|dan)[\s]*mode/i,
      /<\|system\|>|<\|im_start\|>system/,
    ],
    remediation:
      "Retrieved resource content contained injection-shaped text. This is annotated " +
      "and forwarded (not blocked) so legitimate documents aren't corrupted. Review the " +
      "source resource; if hostile, stop reading from it.",
  },
  {
    id: "owasp-mcp-2-instruction-injection-in-prompt",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in a server-provided prompt",
    // prompts/get content is RETRIEVED DATA — warn-only via the inspectMessage clamp.
    target: "prompt_content",
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /(?:disregard|forget)[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /you[\s]*are[\s]*now[\s]*(?:in[\s]*|operating[\s]*in[\s]*|entering[\s]*)?(?:developer|debug|admin|jailbreak|dan)[\s]*mode/i,
      /<\|system\|>|<\|im_start\|>system/,
    ],
    remediation:
      "A server-provided prompt template contained injection-shaped text. Annotated and " +
      "forwarded (not blocked). Review the prompt's source server.",
  },
  {
    // TODOS #16 (security review F12) — the tool_annotations target was wired
    // in patterns.ts from v0.5.0 but no signature ever used it. Annotations
    // (the standard `title`/`readOnlyHint`/etc. fields, and any custom field a
    // server chooses to add — it's an unconstrained JSON object) are an MCP
    // extension surface a tool-poisoning attack can use to carry injection text
    // that a description-only scan would miss (Invariant Labs disclosure).
    // Reuses the same patterns as the sibling tool_description signature —
    // same attack class, same block-capable pre-invocation carrier.
    id: "owasp-mcp-1-tool-annotation-injection",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Instruction-shaped text in tool annotations (title or a custom annotation field)",
    target: "tool_annotations",
    patterns: TOOL_METADATA_INJECTION_PATTERNS,
    remediation:
      "A tool's annotations (title or a custom annotation field) contain imperative or " +
      "system-prompt-style text. Tool-poisoning pattern (Invariant Labs disclosure, 2025), " +
      "carried via the annotations extension surface instead of the description. Re-review " +
      "the server; if legitimate, run `mcpm guard accept-drift <server>`.",
  },
  {
    id: "owasp-mcp-1-initialize-instruction-injection",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Instruction-shaped text in initialize instructions / serverInfo (line-jumping)",
    // initialize instructions + serverInfo are PRE-INVOCATION CONTEXT injected
    // into the agent before any tool call — block-capable (T2 line-jumping).
    target: "initialize_instructions",
    // Use genuine prompt-delimiter tokens (<|system|>, <|im_start|>system) like the
    // resource/prompt signatures — NOT a bare `<important>`/`<system>` tag. This
    // carrier is block-capable, so a loose emphasis tag in legitimate instruction
    // prose would hard-fail the server connection with an opaque JSON-RPC error.
    // (security: FP-2 over-block)
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /(?:disregard|forget)[\s]*(?:all[\s]*|any[\s]*|the[\s]*)?(?:previous|prior|above)[\s]*instructions?/i,
      /<\|system\|>|<\|im_start\|>system/,
      /you[\s]*are[\s]*now[\s]*(?:in[\s]*|operating[\s]*in[\s]*|entering[\s]*)?(?:developer|debug|admin|jailbreak|dan)[\s]*mode/i,
    ],
    remediation:
      "A server's initialize instructions/serverInfo contain imperative or system-prompt-" +
      "style text — a line-jumping attack that injects context before any tool runs. " +
      "Re-review the server; if legitimate, run `mcpm guard accept-drift <server>`.",
  },
  {
    // F6 credential-phishing wedge. Targets `prompt_content` so it rides the
    // existing server-initiated scan path (run-inner.ts inspectServerInitiated
    // wraps a sampling/elicitation request into a synthetic prompts/get frame and
    // RE-TAGS findings to the block-capable `sampling_prompt` carrier). Net effect:
    // a server that PROMPTS the user (via elicitation/create or sampling) to enter a
    // wallet secret is BLOCKED with the error routed back to the server; the same
    // string in a passive prompts/get template is warn-only (retrieved data).
    //
    // Every pattern is built with solicits() (imperative cue + credential noun) — see
    // the SOLICIT_VERB note above for why mention-vs-ask anchoring is load-bearing.
    //
    // FP discipline: only credential types no legitimate MCP server ever solicits are
    // in the block tier. Generic api-key / password / token / access-token /
    // client-secret / bearer are DELIBERATELY EXCLUDED — a server asking for ITS OWN
    // config secret during first-run setup is the single most common (and
    // spec-intended) elicitation, so hard-blocking it would break the feature.
    // "private key" is additionally anchored to crypto-wallet co-occurrence so an
    // SSH/cert/GPG key-manager that elicits "paste your private key" to import a key
    // is NOT blocked (bare "private key" never matches). "mnemonic" requires crypto
    // context too (an assembly/flashcard server legitimately says "enter the
    // mnemonic"). The confusable fold is partial (CONFUSABLES covers s/e/d/o/p/c…
    // but not every anchor letter, e.g. m), so this catches the literal/homoglyph
    // string, not semantic rephrasing (V2 LLM-judge). OTP / verification-code is
    // intentionally NOT here: a legit device-flow / email-verification server
    // elicits "enter the code we sent you" during its own pairing and the relay
    // can't tell self-pairing from a third-party-login relay without provenance.
    id: "credential-phishing-wallet-solicitation",
    category: "MCP-CREDENTIAL-PHISHING",
    severity: "critical",
    description:
      "Server-initiated prompt soliciting a crypto-wallet seed/recovery phrase, mnemonic, or wallet private key (drainer phishing)",
    target: "prompt_content",
    patterns: [
      solicits("seed[\\s-]*(?:phrase|words)"),
      solicits("recovery[\\s-]*(?:phrase|seed|words)"),
      solicits("\\bbip[\\s-]?0?39\\b"),
      // mnemonic must ALSO carry crypto/wallet/phrase context (either order) — bare
      // "mnemonic" is legitimate (assembly opcode, memory aid, flashcard). (review HIGH)
      solicits("(?:wallet|crypto|seed|recovery|metamask|ledger|trezor)[\\s\\S]{0,25}mnemonic"),
      solicits("mnemonic[\\s\\S]{0,25}(?:phrase|words?|seed|recovery|wallet|crypto)"),
      // "private key" ONLY with a crypto-wallet cue within a bounded window (either
      // order). Bare "private key" (SSH / TLS cert / GPG / JWT signing) never matches
      // — those are legitimate key-import elicitations. (critique CRITICAL #1)
      solicits(
        "(?:wallet|crypto(?:currency)?|seed|mnemonic|recovery|metamask|ledger|trezor|bitcoin|ethereum|solana|phantom)[\\s\\S]{0,40}private[\\s-]*key",
      ),
      solicits(
        "private[\\s-]*key[\\s\\S]{0,40}(?:wallet|crypto(?:currency)?|seed|mnemonic|recovery|metamask|ledger|trezor|bitcoin|ethereum|solana|phantom)",
      ),
    ],
    remediation:
      "A server prompted the user to enter a crypto-wallet seed/recovery phrase, " +
      "mnemonic, or wallet private key. No legitimate MCP server asks for these — it is " +
      "a wallet-drainer phishing pattern. The request was blocked and a JSON-RPC error " +
      "returned to the server. If you are certain this is legitimate, mute via " +
      "`mcpm guard mute credential-phishing-wallet-solicitation`.",
  },
  {
    // F6 financial-secret tier — same solicits() anchoring + prompt_content/
    // sampling_prompt path as the wallet signature above. Block tier = card CVV/CVC,
    // a solicited SSN, and a card/bank/ATM PIN. PIN REQUIRES a financial qualifier
    // (card/bank/atm/debit/credit) so "pin this message" never matches (critique
    // MAJOR #3); CVC requires a card cue so a bare acronym ("CVC Capital") doesn't
    // fire. The SSN acronym is gated by solicits() so "map the ssn field" / "the SSN
    // column" — common field-name prose — does NOT block; only an actual ask does
    // (review HIGH). SSN is the one block-tier item a narrow set of legitimate
    // servers (tax / payroll / healthcare intake) may genuinely need, so the
    // remediation points those users at the mute path.
    id: "credential-phishing-financial-solicitation",
    category: "MCP-CREDENTIAL-PHISHING",
    severity: "critical",
    description:
      "Server-initiated prompt soliciting a card CVV/CVC, SSN, or card/bank PIN (financial phishing)",
    target: "prompt_content",
    patterns: [
      solicits("\\bcvv2?\\b"),
      solicits("\\bcvc\\b[\\s\\S]{0,20}card|card[\\s\\S]{0,20}\\bcvc\\b"),
      solicits("card[\\s-]*(?:security|verification)[\\s-]*(?:code|value|number)"),
      solicits("social[\\s-]*security[\\s-]*number"),
      solicits("\\bssn\\b"),
      solicits("(?:card|bank|atm|debit|credit)[\\s-]*(?:card[\\s-]*)?pin\\b"),
    ],
    remediation:
      "A server prompted the user to enter a card CVV/CVC, Social Security Number, or " +
      "card/bank PIN. Almost no legitimate MCP server solicits these via a prompt — it " +
      "is a phishing pattern. The request was blocked and a JSON-RPC error returned to " +
      "the server. Tax-filing, payroll, or healthcare-intake servers are the rare " +
      "exception that may legitimately elicit an SSN; if you trust such a server, mute " +
      "via `mcpm guard mute credential-phishing-financial-solicitation`.",
  },
  {
    // F10 credential-egress DLP. A high-confidence credential appearing in a TOOL
    // RESPONSE is a data-loss signal — a compromised/buggy server leaking secrets,
    // or a tool returning a .env / key file through its output.
    //
    // WARN-tier (severity high → forward + log, NOT block): a secrets-manager or
    // auth tool legitimately returns credentials, and tools returning docs/code
    // carry EXAMPLE keys — so blocking would break legit flows. Promote-to-block is
    // opt-in per-server via policy. (This overrides the ROADMAP's "deny-tier only"
    // on the same benign-corpus evidence that a full-registry sweep gave the Tier-1
    // scanner: match real shapes, warn don't break.)
    //
    // FP discipline (the 2026-07 "Bearer token" phrase lesson applies directly):
    // ONLY prefix-anchored STRUCTURAL credential shapes are here — they cannot
    // match prose. AWS's literal docs key (AKIAIOSFODNN7EXAMPLE) is excluded.
    // Generic Bearer is now covered separately by `generic-bearer-token-disclosure`
    // below (TODOS #53). Bare JWT / 40-char base64 (no distinctive prefix at all,
    // not even a "Bearer " anchor) remain the SUSPECT tier and are still DEFERRED —
    // they false-positive on legitimate auth tools that return a token the user
    // asked for. `redact: true` keeps the caught secret out of the event log and
    // the warning message.
    id: "credential-egress-in-response",
    category: "MCP-CREDENTIAL-EXFIL",
    severity: "high",
    description:
      "High-confidence credential material in a tool response (credential egress / DLP)",
    target: "tool_response",
    redact: true,
    patterns: [
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
      /\bgh[pousr]_[A-Za-z0-9]{30,}/,
      // GitHub fine-grained PAT — a distinct `github_pat_` prefix the `gh[pousr]_`
      // pattern does not cover (gh + p/o/u/s/r, not "github").
      /\bgithub_pat_[A-Za-z0-9_]{40,}/,
      // GitLab personal/project/group access token = `glpat-` + exactly 20
      // base64url chars. Exact length + a trailing non-token assertion (not `{20,}`)
      // so a `glpat-`-prefixed multi-word kebab slug in prose can't match — while
      // still accepting the `-`/`_` a real 20-char token body may contain.
      /\bglpat-[A-Za-z0-9_-]{20}(?![A-Za-z0-9_-])/,
      /\bsk-ant-[A-Za-z0-9_-]{80,}/,
      /\bsk-(?:proj-)?[A-Za-z0-9]{40,}/,
      // Stripe live/test secret + restricted keys (underscore prefix, so the
      // hyphen-anchored sk- above does not match them).
      /\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}/,
      /\bxox[baprs]-[0-9A-Za-z-]{10,}/,
      /\bnpm_[A-Za-z0-9]{36}\b/,
      /\bAIza[0-9A-Za-z_-]{35}\b/,
      // AWS access key id — exclude AWS's documentation example keys (there are
      // several, all AKIA + a 16-char body ending in EXAMPLE, e.g.
      // AKIAIOSFODNN7EXAMPLE / AKIAI44QH8DHBEXAMPLE) so a tool returning AWS
      // docs/tutorials doesn't warn. A real key ending in "EXAMPLE" is ~2^-93.
      /\bAKIA(?![0-9A-Z]{9}EXAMPLE\b)[0-9A-Z]{16}\b/,
    ],
    remediation:
      "A tool response contained high-confidence credential material (private key, cloud/API " +
      "token). This is a credential-egress (DLP) signal — a server may be leaking secrets " +
      "through tool output. The response was forwarded with a warning and the secret is redacted " +
      "in the log. If this tool legitimately returns credentials (e.g. a secrets manager), " +
      "promote-to-block is opt-in per policy, or mute via " +
      "`mcpm guard mute credential-egress-in-response`.",
  },
  {
    // TODOS #53 — the deferred "suspect tier" from the comment above, now
    // motivated by a real CVE: CVE-2026-25650 (smn2gnt/MCP-Salesforce
    // `get_record`) passes a caller-supplied `object_name` into
    // `getattr(sf_client.sf, object_name)` unchecked; `object_name="headers"`
    // returns the live Salesforce client's `Authorization: Bearer <session
    // token>` header dict verbatim in the tool's own response text (CVSS 7.5).
    // Verified against shipped 0.30.0: scored `pass`, no findings.
    //
    // A generic "Bearer <token>" shape has no distinctive prefix (unlike the
    // sibling entry's gh_/sk-/AKIA patterns), so it is lower-confidence and
    // gets its OWN signature id — muteable independently of the always-safe
    // prefix-anchored patterns above. Severity stays `high` (→ warn, same
    // "forward + log, don't block" tier), because this is exactly the shape
    // that produced the 2026-07 registry sweep's 164 CRITICAL "Bearer token"
    // false positives on documentation prose (see scanner/patterns.ts's
    // `SECRET_PATTERNS` "Bearer token" entry, src/scanner/patterns.test.ts's
    // "sweep 2026-07" suite). Pattern reused VERBATIM from that
    // already-corpus-validated fix rather than reinvented: it requires a
    // real-looking credential after "Bearer " — >=20 token chars AND at least
    // one digit — which the English phrase "Bearer token" / "Bearer
    // credential" (short, no digits) and multi-word prose (spaces break the
    // token) cannot satisfy, while a real JWT or opaque session token can.
    //
    // Deliberately NOT extended to bare JWTs or generic 40-char base64 with no
    // "Bearer " anchor — the CVE's own PoC only needs the Bearer-prefixed
    // shape, and those two carry meaningfully higher FP risk (base64 blobs are
    // common in ordinary responses) with no concrete CVE motivating them yet.
    //
    // KNOWN, ACCEPTED GAP: the CVE's own PoC token is a real Salesforce session
    // id, shaped `<15-char org id>!<signature>`. An earlier version of this
    // pattern added `!` to the reused character class specifically to match
    // that literal shape. A pre-merge adversarial review measured that
    // widening (not just read it) and found it FALSE-POSITIVES on real benign
    // text the un-widened, registry-sweep-validated pattern never matched:
    // webpack's loader-chaining syntax (`Bearer style-loader!css-loader!v2`),
    // a PEP-440-style version string immediately after the word "Bearer", and
    // — the closest parallel to the sibling signature's own AWS
    // `AKIAIOSFODNN7EXAMPLE` carve-out — Salesforce's OWN documentation
    // explaining the `<org-id>!<signature>` token FORMAT with an example
    // token, which is prose about a shape, not a leaked secret. None of these
    // are in the tiny 6-7 phrase benign corpus this signature was tested
    // against, which is exactly the "corpus tests the wrong slice of the
    // input space" lesson TODOS #52's own review already logged for this
    // detector family. The `!` was REMOVED rather than patched around it (same
    // choice as TODOS #56/#57: prefer a narrower, unmodified, already-validated
    // pattern over an unmeasured widening). Accepted cost, stated plainly: the
    // CVE's own literal PoC token (with `!`) now scores `pass` against this
    // signature — see TODOS #53's writeup. The signature still generalizes to
    // any OTHER Bearer-disclosed JWT or opaque session token, which is the
    // majority shape this class of vulnerability takes outside Salesforce's
    // own token format.
    //
    // Overlap, not a bug: a vendor-prefixed token disclosed with a literal
    // "Bearer " prefix (e.g. `Bearer ghp_...`) matches BOTH this signature and
    // the sibling `credential-egress-in-response` above — two findings for one
    // secret. Both are correctly redacted and both resolve to the same `warn`
    // action, so this is redundant signal (two remediation lines instead of
    // one), not incorrect signal. Not scoped away deliberately: doing so would
    // require this signature to hardcode (and keep in sync with) every vendor
    // prefix the sibling signature knows about, which is more state than the
    // noise it would save.
    id: "generic-bearer-token-disclosure",
    category: "MCP-CREDENTIAL-EXFIL",
    severity: "high",
    description:
      "A generic Bearer-prefixed credential (typically no distinctive vendor prefix) in a tool response",
    target: "tool_response",
    redact: true,
    patterns: [/Bearer\s+(?=[A-Za-z0-9._~+/=-]{20,})[A-Za-z0-9._~+/=-]*[0-9][A-Za-z0-9._~+/=-]*/],
    remediation:
      "A tool response contained a generic `Bearer <token>` credential (e.g. an OAuth session " +
      "token or API bearer token, typically with no distinctive vendor prefix). CVE-2026-25650 " +
      "(MCP-Salesforce `get_record`) reaches this general shape: an unchecked argument lets a " +
      "caller read the live client's own `Authorization` header back through the tool's " +
      "response. This is a lower-confidence heuristic than the prefix-anchored credential " +
      "signature above — it was forwarded with a warning and the secret is redacted in the " +
      "log. If this tool legitimately returns bearer tokens (e.g. an OAuth helper), mute via " +
      "`mcpm guard mute generic-bearer-token-disclosure`.",
  },
  {
    // F5 — STRUCTURAL exfil-param detector. The finding is emitted by
    // detectExfilParams (a property-KEY walker over tools/list inputSchemas, NOT a
    // content regex), so this catalog entry carries NO patterns. It exists only so
    // the id is recognized by `guard mute exfil-param-in-schema`, `guard
    // list-signatures`, and policy signature_overrides — all of which enumerate
    // OWASP_MCP_TOP_10 ids. `inspectAgainstSignatures` safely no-ops on an empty
    // patterns array (its inner pattern loop never runs). (The
    // hidden-chars-in-metadata entry below uses this same empty-patterns pattern.)
    id: "exfil-param-in-schema",
    category: "OWASP-MCP-1",
    severity: "critical",
    description:
      "Tool input schema declares a context-exfiltration sigil parameter (e.g. _system_prompt_) the model auto-fills",
    target: "tool_description",
    patterns: [],
    remediation:
      "A tool's input schema declares a parameter named like a context-exfiltration sigil " +
      "(e.g. `_system_prompt_`) that the model would silently auto-fill — a zero-interaction " +
      "prompt leak. No legitimate tool names a parameter this way. The server's whole tools/list " +
      "was blocked. Tripwire for the documented underscore-sigil convention; a renamed param " +
      "evades it. If trusted, mute via `mcpm guard mute exfil-param-in-schema`.",
  },
  {
    // guard-inspection-truncated — emitted by inspectMessage when stringLeaves
    // hits MAX_LEAF_WALK_NODES on a carrier, i.e. the guard did NOT finish
    // reading that frame. Synthesized from a walk-budget signal, not a content
    // regex, so like the two entries above it carries NO patterns. The entry
    // exists so the id is recognized by `guard mute guard-inspection-truncated`
    // (which refuses ids outside this catalog — F7), `guard list-signatures`,
    // and policy signature_overrides.
    //
    // `critical` is deliberate: it rides the normal carrier policy, so it BLOCKS
    // on block-capable carriers (an uninspected payload would otherwise reach
    // the model pre-invocation) and defaultActionForFinding clamps it to warn on
    // retrieved-data carriers. Budget exhaustion used to fail OPEN, which was a
    // complete detection bypass — ~73 KB of junk padding hid a critical
    // injection. (security 2026-07-25)
    id: "guard-inspection-truncated",
    category: "MCP-GUARD-INTEGRITY",
    severity: "critical",
    description:
      "The frame exceeded the inspection walk budget, so part of it was never scanned (padding is a known way to hide a payload)",
    target: "tool_response",
    patterns: [],
    remediation:
      "The frame was too large to inspect completely, so the guard cannot vouch for it — " +
      "padding a response with junk nodes is a known way to hide a payload behind the " +
      "budget. Inspect the server's output by hand. If this server legitimately emits " +
      "frames this large, mute via `mcpm guard mute guard-inspection-truncated`.",
  },
  {
    // hidden-chars-in-metadata — the H2 PRESENCE detector (detectHiddenChars in
    // patterns.ts) emits this finding INLINE from a codepoint scan of raw metadata
    // leaves, NOT a content regex, so like exfil-param-in-schema above it carries NO
    // patterns. The entry exists only so the id is recognized by `guard mute
    // hidden-chars-in-metadata` (the block message instructs exactly that),
    // `guard list-signatures`, and policy signature_overrides — all of which
    // enumerate OWASP_MCP_TOP_10 ids. `inspectAgainstSignatures` no-ops on the empty
    // patterns array. Keep `patterns: []`: a regex here would double-fire alongside
    // the detectHiddenChars emission.
    id: "hidden-chars-in-metadata",
    category: "OWASP-MCP-1",
    severity: "high",
    description:
      "Invisible/control characters in tool metadata (description, title, inputSchema text, annotations) that hide content from human review",
    target: "tool_description",
    patterns: [],
    remediation:
      "Tool metadata contains invisible/control characters that hide content from " +
      "human review (tool-poisoning indicator). Inspect the server's source; if " +
      "legitimate (rare), mute via `mcpm guard mute hidden-chars-in-metadata`.",
  },
  {
    // TODOS #50 — shell-metachar-in-identifier-arg. STRUCTURAL key+value
    // detector (detectShellMetacharArgs in shell-metachar-args.ts), NOT a
    // content regex — like exfil-param-in-schema and guard-inspection-truncated
    // above, this entry carries NO patterns and exists only so the id is
    // recognized by `guard mute shell-metachar-in-identifier-arg`, `guard
    // list-signatures`, and policy signature_overrides. `inspectAgainstSignatures`
    // no-ops on the empty patterns array.
    id: "shell-metachar-in-identifier-arg",
    category: "MCP-COMMAND-INJECTION",
    severity: "critical",
    description:
      "A tools/call argument named like a bare identifier or path contains shell-metacharacter / command-substitution syntax (CVE-2025-53818, CVE-2026-25546 shape)",
    target: "tool_call_args",
    patterns: [],
    remediation:
      "A tool call argument named like a bare identifier or filesystem path (an id, " +
      "number, path, slug, uuid, or namespace field) contains shell-metacharacter or " +
      "command-substitution syntax ($(...), a backtick, ;, or &&). " +
      "Two real, disclosed CVEs reach command injection through exactly this shape — the " +
      "value is spliced unescaped into a shell command. The call was blocked. If this " +
      "tool legitimately accepts shell syntax in this field, mute via " +
      "`mcpm guard mute shell-metachar-in-identifier-arg`.",
  },
  {
    // TODOS #51 — query-control-syntax-in-identifier-arg. STRUCTURAL key+value
    // detector (detectQueryControlArgs in query-control-args.ts), same shape
    // as shell-metachar-in-identifier-arg above — this entry carries NO
    // patterns and exists only so the id is recognized by `guard mute
    // query-control-syntax-in-identifier-arg`, `guard list-signatures`, and
    // policy signature_overrides.
    id: "query-control-syntax-in-identifier-arg",
    category: "MCP-QUERY-INJECTION",
    severity: "critical",
    description:
      "A tools/call argument named like a bare table/column/database name contains query-language control syntax (CVE-2026-33980 shape)",
    target: "tool_call_args",
    patterns: [],
    remediation:
      "A tool call argument named like a bare table, column, database, schema, or resource " +
      "identifier contains query-control syntax (a pipe re-scoping operator, a statement " +
      "separator before a DDL/DML keyword, a `.drop` management command, or a line-comment " +
      "token). A real, disclosed CVE reaches data exfiltration and destructive table drops " +
      "through exactly this shape. If this tool legitimately accepts query syntax in this " +
      "field, mute via `mcpm guard mute query-control-syntax-in-identifier-arg`.",
  },
  {
    // TODOS #52 — cli-flag-injection-in-identifier-arg. STRUCTURAL key+value
    // detector (detectCliFlagInjectionArgs in cli-flag-injection-args.ts), same
    // shape as shell-metachar-in-identifier-arg / query-control-syntax-in-
    // identifier-arg above — this entry carries NO patterns and exists only so
    // the id is recognized by `guard mute cli-flag-injection-in-identifier-arg`,
    // `guard list-signatures`, and policy signature_overrides.
    id: "cli-flag-injection-in-identifier-arg",
    category: "MCP-ARGUMENT-INJECTION",
    severity: "critical",
    description:
      "A tools/call argument named like a bare namespace or opaque identifier contains an embedded `--`-prefixed CLI flag token (CVE-2026-39884 shape)",
    target: "tool_call_args",
    patterns: [],
    remediation:
      "A tool call argument named like a bare namespace or opaque identifier " +
      "contains a `--`-prefixed CLI flag token (e.g. `--address=0.0.0.0`). A real, " +
      "disclosed CVE reaches this shape when the argument is whitespace-split into a " +
      "shell command, letting the embedded flag override intended behavior. If this " +
      "tool legitimately accepts flag-shaped text in this field, mute via " +
      "`mcpm guard mute cli-flag-injection-in-identifier-arg`.",
  },
  {
    // tool-name-confusable-duplicate / tool-name-deceptive-characters — emitted by
    // detectConfusableToolNames (tool-name-confusable.ts) from a NAME comparison,
    // not the regex engine, so like the structural entries above these carry NO
    // patterns and exist so the ids are recognized by `guard mute`,
    // `guard list-signatures`, and policy signature_overrides.
    id: "tool-name-confusable-duplicate",
    category: "OWASP-MCP-1",
    severity: "high",
    description:
      "One tools/list advertises two tools whose names are visually indistinguishable after Unicode normalization (TODOS #58 look-alike residual)",
    target: "tool_description",
    patterns: [],
    remediation:
      "This server advertises two tools whose names differ only by case, an " +
      "invisible character, or a homoglyph — the shape used to smuggle a poisoned " +
      "definition past a same-session drift check by making it look like a brand-new " +
      "tool. Confirm with the publisher that BOTH tools are intended; if not, remove " +
      "the server. If this server legitimately ships such a pair, mute via " +
      "`mcpm guard mute tool-name-confusable-duplicate`.",
  },
  {
    id: "tool-name-deceptive-characters",
    category: "OWASP-MCP-1",
    severity: "high",
    description:
      "A tool name contains an invisible character, or mixes Latin with another script — the out-of-table homoglyph class the confusable table cannot fold",
    target: "tool_description",
    patterns: [],
    remediation:
      "A tool name contains an invisible character (zero-width, bidi, Unicode TAG), " +
      "or mixes Latin letters with letters from another script. Both are ways to build " +
      "a name that looks identical to a trusted tool's, and neither is folded by the " +
      "guard's scoped confusable table. A name written wholly in one non-Latin script " +
      "impersonates nothing and is NOT flagged. Report it to the server's publisher. " +
      "If this server legitimately uses such names, mute via " +
      "`mcpm guard mute tool-name-deceptive-characters`.",
  },
  {
    // unicode-tag-concealment — the tag-block PRESENCE floor on the carriers H2
    // deliberately skips (tool_response / tool_call_args / retrieved data, and
    // sampling_prompt by re-tagging). Emitted inline by detectTagConcealment from
    // a codepoint scan, so like the entries above it carries NO patterns.
    //
    // Disjoint from hidden-chars-in-metadata by carrier, so a tag character is
    // reported once, under whichever id matches where it was found. `high` → warn:
    // this is the floor that fires when a payload is concealed but matches no
    // signature. When it DOES match, inspectTagEncoded recovers the payload and the
    // real signature decides the action at its own severity. (TODOS #31)
    id: "unicode-tag-concealment",
    category: "OWASP-MCP-1",
    severity: "high",
    description:
      "Unicode tag-block characters (U+E0000–U+E007F) outside an emoji subdivision flag — invisible text a model can still read ('ASCII smuggling')",
    target: "tool_response",
    patterns: [],
    remediation:
      "Content contains Unicode tag-block characters (U+E0000–U+E007F), which render as " +
      "nothing but are readable by a model — the documented 'ASCII smuggling' concealment " +
      "technique. Outside an emoji subdivision flag these do not occur in real text. " +
      "Inspect the server's output; if legitimate (rare), mute via " +
      "`mcpm guard mute unicode-tag-concealment`.",
  },
  {
    // TODOS #54 — renderer-code-execution-in-response. See the
    // ELECTRON_MCP_BRIDGE_CALL comment above for the full CVE grounding, the
    // pre-merge adversarial review's 28 findings, and why this gate is
    // narrower than an earlier draft. Three structural shapes share one
    // signature id, all requiring the SAME literal bridge-call gate:
    //
    //  1. An HTML tag with an inline event-handler attribute (a generic
    //     `\son[a-z]+\s*=`, not an enumerated handler list — HTML has no
    //     non-event `on*` attribute, and this closes a review-found gap where
    //     `onmouseout`/`onblur`/etc. weren't on the original enumerated list)
    //     whose VALUE contains the bridge call — the CVE-2025-68669 shape.
    //     Value-scoped via a lookahead so the token must be INSIDE the
    //     attribute's own value; the bare/unquoted branch additionally
    //     requires `(?!["'])` so it cannot fall through past a real quoted
    //     value into an ADJACENT attribute when the two abut with no
    //     separating whitespace (review-found regex-correctness bug).
    //  2. A <script>...</script> block whose body (bounded to 2000 chars,
    //     never crossing a closing </script>) contains the bridge call. The
    //     tag-open matcher is quote-aware (`(?:"[^"]*"|'[^']*'|[^>"'])*`) so a
    //     literal `>` inside a quoted attribute value can't be mistaken for
    //     the tag's own close and misalign where the 2000-char body budget
    //     starts counting from (review-found: this could push a real call
    //     just past the budget, causing a missed detection).
    //  3. A markdown code fence tagged `mermaid` or `echarts` (the two plugin
    //     types both disclosed CVEs abuse) containing the bridge call
    //     ANYWHERE in the fence body — the CVE-2026-22793 shape. An earlier
    //     draft instead matched `new Function(`/IIFE syntax with NO call
    //     gate, on the premise that legitimate diagram/option content never
    //     contains a function definition; the review found that premise FALSE
    //     for ECharts specifically (formatter callbacks persisted via
    //     `new Function(...)`, option data computed via an IIFE, are both
    //     standard documented idioms) and, independently, that requiring
    //     IIFE/`new Function(` syntax at all was unnecessarily narrow: the
    //     vulnerable `parseOption` wraps the ENTIRE fence body in
    //     `new Function('return {' + body + '}')()`, so a bridge call placed
    //     directly as an object-literal property value (no wrapper at all)
    //     executes identically. Requiring only the bridge call is both safer
    //     (fixes the ECharts false-positive class) and strictly more complete.
    //
    // All three regexes use bounded lazy quantifiers ({0,4000}?/{0,2000}?)
    // with a `(?!` "does not cross a fence/tag-close boundary" guard rather
    // than an unbounded `[\s\S]*` scan — measured against multi-hundred-KB
    // adversarial padding (including many non-matching `electron.mcp.`-prefixed
    // near-misses) with no backtracking blowup (sub-millisecond).
    //
    // Severity is `high` (→ warn, forward + log, never block on its own): a
    // documentation/CVE-lookup tool can legitimately return prose QUOTING this
    // exact literal call (a GHSA/NVD advisory explaining the vulnerability) —
    // an accepted, low-frequency residual the review confirmed and this
    // signature does not try to special-case away, the same "ambiguous but
    // real" tier as credential-egress-in-response, and the project's own
    // repeated lesson that a wrong BLOCK on a block-capable carrier is the
    // worse failure direction (v0.29.0 / v0.31.0).
    //
    // `redact: true` — a review finding (not merely FP/evasion) caught that
    // shapes 2-3's lazily-bounded match can capture arbitrary attacker-placed
    // text between the tag/fence open and the bridge call verbatim into the
    // excerpt (e.g. a secret the injected script reads before exfiltrating
    // it), which would otherwise land unredacted in guard-events.jsonl and the
    // public `guard inspect` seam even while a co-firing credential signature
    // on the SAME leaf correctly redacts it — silently defeating the
    // redaction guarantee tool_response carries elsewhere in this file.
    id: "renderer-code-execution-in-response",
    category: "MCP-RENDERER-CODE-EXECUTION",
    severity: "high",
    redact: true,
    description:
      "HTML/script content in a tool response calling the electron.mcp privileged IPC bridge (CVE-2025-68669, CVE-2026-22793 shape)",
    target: "tool_response",
    patterns: [
      new RegExp(
        "<[a-zA-Z][\\w-]*\\b[^<>]*?\\son[a-z]+\\s*=\\s*" +
          `(?:"(?=[^"]*(?:${ELECTRON_MCP_BRIDGE_CALL}))[^"]*"` +
          `|'(?=[^']*(?:${ELECTRON_MCP_BRIDGE_CALL}))[^']*'` +
          `|(?!["'])(?=[^\\s>]*(?:${ELECTRON_MCP_BRIDGE_CALL}))[^\\s>]*)` +
          "[^<>]*>",
        "i",
      ),
      new RegExp(
        `<script\\b(?:"[^"]*"|'[^']*'|[^>"'])*>(?:(?!</script>)[\\s\\S]){0,2000}?(?:${ELECTRON_MCP_BRIDGE_CALL})`,
        "i",
      ),
      new RegExp(
        "```\\s*(?:mermaid|echarts)\\b(?:(?!```)[\\s\\S]){0,4000}?(?:" + ELECTRON_MCP_BRIDGE_CALL + ")",
        "i",
      ),
    ],
    remediation:
      "A tool response contained HTML/script content calling the electron.mcp privileged IPC " +
      "bridge (electron.mcp.activate(...) / electron.mcp.addServer(...)) — either from an " +
      "inline HTML event-handler attribute, a <script> body, or a mermaid/echarts diagram " +
      "fence. Two real, disclosed CVEs (CVE-2025-68669, CVE-2026-22793) reach RCE this way in " +
      "a vulnerable client renderer. This was forwarded with a warning, not blocked, because a " +
      "documentation or CVE-lookup tool can legitimately return prose quoting this exact call. " +
      "If this tool legitimately returns such content, mute via " +
      "`mcpm guard mute renderer-code-execution-in-response`.",
  },
];
