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

export const OWASP_MCP_TOP_10: readonly Signature[] = [
  {
    id: "owasp-mcp-2-instruction-injection-in-response",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in tool response content",
    target: "tool_response",
    // [\s]+ instead of literal space catches newline / tab / multi-space evasions
    // (an attacker inserting "ignore\nprevious instructions" otherwise bypasses).
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
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
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /<important>|<system>/i,
      /when[\s]+(?:the[\s]+)?user[\s]+asks,?[\s]+(?:you[\s]+(?:must|should|always|never)|always|never|exfil|read|access|send|email|do[\s]+not)/i,
    ],
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
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
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
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
      /<\|system\|>|<\|im_start\|>system/,
    ],
    remediation:
      "A server-provided prompt template contained injection-shaped text. Annotated and " +
      "forwarded (not blocked). Review the prompt's source server.",
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
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /<\|system\|>|<\|im_start\|>system/,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
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
    // Generic Bearer / bare JWT / 40-char base64 (no distinctive prefix) are the
    // SUSPECT tier and are DEFERRED — they false-positive on legitimate auth tools
    // that return a token the user asked for. `redact: true` keeps the caught
    // secret out of the event log and the warning message.
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
      // GitLab personal/project/group access token.
      /\bglpat-[A-Za-z0-9_-]{20,}/,
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
];
