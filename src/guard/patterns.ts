/**
 * Pattern engine for mcpm-guard (v0.5.0).
 *
 * Pure, deterministic detection. NFKC-normalize each string leaf reachable
 * from a target subtree of a JSON-RPC message, then regex-test against each
 * signature's pattern list. No LLM, no network. See v0.5.0 design doc
 * "Signature format (YAML)" -> Inspection model.
 *
 * Note on NFKC: zero-width chars and full-width Latin variants
 * (e.g. "ｉｇｎｏｒｅ") normalize to "ignore", defeating naive substring evasion.
 * NFKC is the right form because it folds compatibility characters; NFC alone
 * misses width / circle / parenthesized variants.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type {
  InspectFinding,
  InspectResult,
  Severity,
  Signature,
  SignatureTarget,
} from "./types.js";

// ---------------------------------------------------------------------------
// JSON leaf walk
// ---------------------------------------------------------------------------

/**
 * Yields every string leaf in a JSON-ish value. Non-string leaves (number,
 * boolean, null) are skipped. Recurses into objects + arrays. Bounded by
 * depth to avoid pathological nesting; cycles are not possible in JSON.
 */
function* stringLeaves(node: unknown, depth = 0, maxDepth = 32): Iterable<string> {
  if (depth > maxDepth) return;
  if (typeof node === "string") {
    yield node;
    return;
  }
  if (Array.isArray(node)) {
    for (const child of node) yield* stringLeaves(child, depth + 1, maxDepth);
    return;
  }
  if (node !== null && typeof node === "object") {
    for (const value of Object.values(node)) yield* stringLeaves(value, depth + 1, maxDepth);
  }
}

/**
 * Returns the subtree of the JSON-RPC message corresponding to the given
 * inspection target, or null if the message doesn't carry that target.
 *
 * Each target is narrowed to a specific JSON path so signatures stay
 * cleanly scoped — a `tool_response` signature won't accidentally fire
 * against a `tools/list` description leaf and vice versa.
 */
function targetSubtree(msg: JSONRPCMessage, target: SignatureTarget): unknown {
  if (target === "tool_response") {
    // tools/call response → result.content, result.structuredContent, AND the
    // JSON-RPC error object. Injection placed in structuredContent or an error
    // message would otherwise evade every tool_response signature. (security #16)
    const error = (msg as { error?: unknown }).error ?? null;
    if ("result" in msg) {
      const result = (msg as { result?: { content?: unknown; structuredContent?: unknown } }).result;
      return [result?.content ?? null, result?.structuredContent ?? null, error];
    }
    return error;
  }
  if (target === "tool_call_args") {
    // tools/call request → params.arguments
    if ("method" in msg && msg.method === "tools/call" && "params" in msg) {
      const params = (msg as { params?: { arguments?: unknown } }).params;
      return params?.arguments ?? null;
    }
    return null;
  }
  if (target === "tool_description") {
    // tools/list response → per tool: description + title + the FULL inputSchema.
    // Poison in inputSchema.properties.*.description / enum / title is a known
    // tool-poisoning vector that scanning only `description` would miss. (#16)
    if ("result" in msg) {
      const result = (msg as {
        result?: { tools?: Array<{ description?: unknown; title?: unknown; inputSchema?: unknown }> };
      }).result;
      const tools = result?.tools;
      if (!tools) return null;
      return tools.map((t) => [t.description ?? "", t.title ?? "", t.inputSchema ?? null]);
    }
    return null;
  }
  if (target === "tool_annotations") {
    // tools/list response → result.tools[*].annotations
    if ("result" in msg) {
      const result = (msg as { result?: { tools?: Array<{ annotations?: unknown }> } }).result;
      const tools = result?.tools;
      if (!tools) return null;
      return tools.map((t) => t.annotations ?? null);
    }
    return null;
  }
  if (target === "resource_content") {
    // resources/read response → result.contents[*].text. Text-only for the first
    // slice: base64 `blob` decoding is deferred (binary blobs are noise + an FP /
    // perf risk). Retrieved DATA carrier — the warn-only clamp in inspectMessage
    // degrades a match here to `warn` so a poisoned README is annotated, not dropped.
    if ("result" in msg) {
      const result = (msg as { result?: { contents?: Array<{ text?: unknown }> } }).result;
      const contents = result?.contents;
      if (!Array.isArray(contents)) return null;
      return contents.map((c) => c.text ?? null);
    }
    return null;
  }
  if (target === "prompt_content") {
    // prompts/get response → result.messages[*].content. Return the whole
    // `content` and let stringLeaves recurse it: content may be a single
    // `{type:"text", text:"…"}` object OR an ARRAY of such blocks. Extracting
    // only `content.text` would yield null for the array shape, silently
    // bypassing inspection of a server-provided prompt. stringLeaves skips the
    // non-string base64 image/audio `data` leaves on its own (they're strings,
    // but only injection-shaped text matches a signature; the perf cost is
    // bounded by normalizeForMatch's cap). Retrieved DATA carrier — warn-only
    // via the inspectMessage clamp. (security: H1 array-content bypass)
    if ("result" in msg) {
      const result = (msg as { result?: { messages?: Array<{ content?: unknown }> } }).result;
      const messages = result?.messages;
      if (!Array.isArray(messages)) return null;
      return messages.map((m) => m.content ?? null);
    }
    return null;
  }
  if (target === "initialize_instructions") {
    // initialize response → result.instructions + result.serverInfo. Pre-invocation
    // CONTEXT (block-capable). Gated on result.protocolVersion (the reliable
    // initialize discriminator) so a stray `instructions` key in a tools/call
    // result is NOT mislabeled as block-capable context. (security: H1 #1)
    if ("result" in msg) {
      const result = (msg as {
        result?: { protocolVersion?: unknown; instructions?: unknown; serverInfo?: unknown };
      }).result;
      if (typeof result?.protocolVersion !== "string") return null;
      return [result.instructions ?? null, result.serverInfo ?? null];
    }
    return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const MAX_EXCERPT = 200;

function truncate(s: string): string {
  return s.length > MAX_EXCERPT ? `${s.slice(0, MAX_EXCERPT)}…` : s;
}

/**
 * NFKC-normalize + strip evasion characters + fold confusable homoglyphs
 * before pattern matching.
 *
 * NFKC folds compatibility characters (full-width Latin "ｉｇｎｏｒｅ" → "ignore")
 * but does NOT strip zero-width spaces, soft hyphens, or bidi controls, which
 * an attacker can insert between word characters to defeat a regex. PATTERN_BREAKERS
 * captures those classes after normalization.
 *
 * NFKC also does NOT fold visually-confusable homoglyphs from other scripts —
 * e.g. Cyrillic "о" (U+043E) or Greek "ο" (U+03BF) for Latin "o". So
 * "ignоre previous instructions" (Cyrillic "о") stays visually identical to a
 * human/LLM but evades the ASCII-anchored signatures. foldConfusables maps the
 * Cyrillic/Greek look-alikes most used for Latin-evasion down to ASCII, modeled
 * on the TR39 confusables skeleton (scoped to the ranges that matter). (security #30)
 *
 * Match input is bounded to a head + tail window (64 KB total) regardless of
 * leaf size: the regex engine never scans more than that, so a pathological
 * future signature with ambiguous quantifiers cannot turn a 1 MB attacker leaf
 * into a multi-second synchronous stall on the relay hot path. For oversized
 * leaves we scan a bounded head + tail so an injection an attacker pads with
 * garbage at either end is still caught; slicing happens BEFORE normalize() so
 * we never pay the O(n) copy on a huge benign payload. (security #27)
 */

// Hard cap on the characters fed to the regex engine per leaf (32 KB head +
// 32 KB tail = 64 KB scanned). Far below the relay's 1 MB leaf ceiling, so any
// single match is bounded-cost even if a future signature is ReDoS-prone. (#27)
const MATCH_SEGMENT_CAP = 32 * 1_024; // 32 KB

// Zero-width chars, bidi overrides, ZWJ/ZWNJ, byte-order mark, Unicode tag block.
// Stripping these post-NFKC closes a class of "invisible separator" evasions where
// an attacker inserts U+200B between "ignore" and "previous" to break the regex.
const PATTERN_BREAKERS = /[­​-‏‪-‮⁠-⁯﻿]|[\u{E0000}-\u{E007F}]/gu;

// Targeted confusable → ASCII-Latin fold (TR39 skeleton, Cyrillic + Greek scope).
// Only single-codepoint look-alikes that map cleanly to an ASCII letter/digit and
// that appear in the injection signatures' alphabet. Kept as an explicit allowlist
// (not a broad "non-ASCII → strip") so we never corrupt legitimate non-Latin text
// in a way that fabricates a match. (security #30)
const CONFUSABLES: Readonly<Record<string, string>> = {
  // ── Cyrillic → Latin ──
  "а": "a", "А": "A", // а А
  "е": "e", "Е": "E", // е Е
  "о": "o", "О": "O", // о О
  "р": "p", "Р": "P", // р Р
  "с": "c", "С": "C", // с С
  "у": "y", "У": "Y", // у У
  "х": "x", "Х": "X", // х Х
  "і": "i", "І": "I", // і І
  "ј": "j", "Ј": "J", // ј Ј
  "ԁ": "d",                 // ԁ
  "ԛ": "q",                 // ԛ
  "ѕ": "s", "Ѕ": "S", // ѕ Ѕ
  "һ": "h",                 // һ
  // ── Greek → Latin ──
  "ο": "o", "Ο": "O", // ο Ο
  "α": "a", "Α": "A", // α Α
  "ε": "e", "Ε": "E", // ε Ε
  "ι": "i", "Ι": "I", // ι Ι
  "ν": "v", "Ν": "N", // ν Ν
  "ρ": "p", "Ρ": "P", // ρ Ρ
  "τ": "t", "Τ": "T", // τ Τ
  "υ": "u", "Υ": "Y", // υ Υ
  "χ": "x", "Χ": "X", // χ Χ
  "κ": "k", "Κ": "K", // κ Κ
  "η": "n", "Η": "H", // η Η
};

function foldConfusables(s: string): string {
  let out = "";
  for (const ch of s) out += CONFUSABLES[ch] ?? ch;
  return out;
}

function normalizeSegment(segment: string): string {
  return foldConfusables(segment.normalize("NFKC").replace(PATTERN_BREAKERS, ""));
}

/**
 * Exported for reuse by other detectors (e.g. the scanner's secret detection)
 * that need the same NFKC + evasion-strip + confusable-fold pipeline. Keeping a
 * single implementation here means cross-script homoglyph evasion is defeated
 * consistently everywhere, not just on the guard relay path. (security #30)
 */
export function normalizeForMatch(leaf: string): string {
  if (leaf.length <= MATCH_SEGMENT_CAP) {
    return normalizeSegment(leaf);
  }
  // Bound the regex input to a head + tail window. Slice before normalize() so a
  // 1 MB benign leaf never pays a full-length NFKC copy, and the engine never
  // scans more than ~64 KB. The newline join keeps a padded-middle injection from
  // matching across the boundary. (security #27)
  const head = normalizeSegment(leaf.slice(0, MATCH_SEGMENT_CAP));
  const tail = normalizeSegment(leaf.slice(-MATCH_SEGMENT_CAP));
  return `${head}\n${tail}`;
}

function inspectAgainstSignatures(
  leaf: string,
  signatures: readonly Signature[],
  target: SignatureTarget,
): InspectFinding[] {
  const normalized = normalizeForMatch(leaf);
  const findings: InspectFinding[] = [];
  for (const sig of signatures) {
    if (sig.target !== target) continue;
    for (const pattern of sig.patterns) {
      pattern.lastIndex = 0; // reset stateful global regex
      const match = pattern.exec(normalized);
      if (match) {
        findings.push({
          signature_id: sig.id,
          category: sig.category,
          severity: sig.severity,
          target: sig.target,
          matched_text_excerpt: truncate(match[0]),
          remediation: sig.remediation,
        });
        break; // one finding per signature per leaf is enough
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// H2 — hidden-character PRESENCE detector (tool-poisoning malice indicator)
// ---------------------------------------------------------------------------

/**
 * Targets H2 inspects. METADATA carriers only: a hidden/control char in a tool
 * description / title / inputSchema text / annotations hides content from human
 * review (OWASP-MCP-1 tool poisoning). H2 deliberately does NOT run on
 * tool_response / retrieved data — an invisible char in a fetched log, source
 * file, or email is common and benign, so scanning there is an FP generator.
 * Explicit allowlist so the scope can't silently expand.
 */
const HIDDEN_CHAR_TARGETS: ReadonlySet<SignatureTarget> = new Set<SignatureTarget>([
  "tool_description",
  "tool_annotations",
  // initialize.instructions is block-capable PRE-INVOCATION context (H1). An
  // invisible separator embedded there to obfuscate keywords would otherwise go
  // unreported, so it's in scope. resource_content / prompt_content stay OUT of
  // scope — invisible chars in fetched files/emails are common and benign. (H2)
  "initialize_instructions",
]);

/**
 * Dangerous invisible / control characters. Distinct from PATTERN_BREAKERS:
 * H2 must also catch C0/C1 controls and ANSI ESC, which PATTERN_BREAKERS omits.
 *
 * Matches: zero-width (ZWSP/ZWNJ/ZWJ/word-joiner/BOM), bidi overrides &
 * embeddings (U+202A–U+202E, U+2066–U+2069), soft hyphen, C0 controls EXCEPT
 * tab/newline/CR plus DEL, C1 controls, and the Unicode tag block.
 *
 * Deliberately enumerated (no broad \p{Cf}) so legitimate non-Latin metadata —
 * e.g. an Arabic tool description carrying U+0600-class format chars — does not
 * false-positive. Broaden only if an attack fixture demonstrates a gap. The
 * \t \n \r whitespace bytes (0x09/0x0A/0x0D) are intentionally excluded.
 */
const HIDDEN_CHAR_CLASS =
  /[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u202a-\u202e\u2066-\u2069]|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]|[\u0080-\u009f]|[\u{E0000}-\u{E007F}]/gu;

// Human-readable classification per matched codepoint. Never echoes the raw
// (invisible) char into the excerpt — that would be unreadable in logs and
// could carry the payload forward. Reports the codepoint by hex + class name.
function classifyHiddenChar(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  const hex = `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
  let kind: string;
  if (cp === 0x1b) kind = "ANSI-ESC";
  else if (cp === 0xfeff || cp === 0x2060) kind = "zero-width";
  else if (cp === 0x200b || cp === 0x200c || cp === 0x200d) kind = "zero-width";
  else if (cp >= 0x2061 && cp <= 0x2064) kind = "invisible-math";
  else if (cp === 0x00ad) kind = "soft-hyphen";
  else if (cp === 0x200e || cp === 0x200f) kind = "bidi-control";
  else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) kind = "bidi-control";
  else if (cp >= 0xe0000 && cp <= 0xe007f) kind = "unicode-tag";
  else if (cp >= 0x80 && cp <= 0x9f) kind = "C1-control";
  else kind = "control";
  return `${kind} (${hex})`;
}

/**
 * True if the codepoint is an emoji/pictograph component that a ZWJ legitimately
 * joins: Extended_Pictographic, an emoji modifier (skin tone), or VS16. A ZWJ
 * (U+200D) flanked by two such codepoints is a benign composite-emoji join
 * (family, profession, pride flag, couple), not a hidden-char poisoning attempt.
 * (security: H2 ZWJ false-positive)
 */
function isEmojiJoinComponent(cp: number | undefined): boolean {
  if (cp === undefined) return false;
  if (cp === 0xfe0f) return true; // VS16 (emoji presentation selector)
  if (cp >= 0x1f3fb && cp <= 0x1f3ff) return true; // emoji skin-tone modifiers
  return /\p{Extended_Pictographic}/u.test(String.fromCodePoint(cp));
}

/**
 * Scans a RAW leaf (pre-normalization) for a hidden/control character. Presence
 * is binary: returns at most one HIGH finding per leaf. Must be called BEFORE
 * normalizeForMatch() runs, since that pipeline strips exactly these chars.
 *
 * Exported for direct unit testing.
 */
export function detectHiddenChars(leaf: string, target: SignatureTarget): InspectFinding[] {
  // Bound the scan to the same head+tail window as signature matching so a
  // pathological giant metadata leaf can't stall the relay. Metadata is small
  // in practice; this is symmetry with normalizeForMatch's cap. (security #27)
  const scanned =
    leaf.length <= MATCH_SEGMENT_CAP * 2
      ? leaf
      : leaf.slice(0, MATCH_SEGMENT_CAP) + leaf.slice(-MATCH_SEGMENT_CAP);

  // Iterate matches (the class is a global regex) so a benign composite-emoji
  // ZWJ can be skipped while still reporting a later genuine hidden char in the
  // same leaf. Presence is binary: return on the FIRST non-benign match.
  HIDDEN_CHAR_CLASS.lastIndex = 0; // reset stateful global regex
  for (let m = HIDDEN_CHAR_CLASS.exec(scanned); m !== null; m = HIDDEN_CHAR_CLASS.exec(scanned)) {
    // U+200D (ZWJ) is the standard joiner for composite emoji. When it is flanked
    // on BOTH sides by emoji/pictograph (or modifier/VS16) codepoints it is a
    // benign sequence (family, profession, flag) — not a poisoning indicator.
    if (m[0].codePointAt(0) === 0x200d) {
      const before = codePointBefore(scanned, m.index);
      const after = scanned.codePointAt(m.index + 1);
      if (isEmojiJoinComponent(before) && isEmojiJoinComponent(after)) continue;
    }
    return [
      {
        signature_id: "hidden-chars-in-metadata",
        category: "OWASP-MCP-1",
        severity: "high",
        target,
        matched_text_excerpt: `${classifyHiddenChar(m[0])} in ${target}`,
        remediation:
          "Tool metadata contains invisible/control characters that hide content from " +
          "human review (tool-poisoning indicator). Inspect the server's source; if " +
          "legitimate (rare), mute via `mcpm guard mute hidden-chars-in-metadata`.",
      },
    ];
  }
  return [];
}

/** Codepoint immediately before `index` in `s`, surrogate-pair aware. */
function codePointBefore(s: string, index: number): number | undefined {
  if (index <= 0) return undefined;
  const prev = s.charCodeAt(index - 1);
  // Low surrogate: combine with the preceding high surrogate for the real cp.
  if (prev >= 0xdc00 && prev <= 0xdfff && index >= 2) {
    return s.codePointAt(index - 2);
  }
  return prev;
}

/**
 * Action ordering (pass < warn < block). Exported so run-inner.ts can compare
 * per-finding actions with the same scale instead of re-declaring a duplicate map.
 */
export const ACTION_RANK = { pass: 0, warn: 1, block: 2 } as const;

/**
 * Carriers of RETRIEVED DATA. A signature match here is annotate-and-forward:
 * the action is clamped to `warn` even when the finding is critical, because
 * BLOCKING retrieved data corrupts the very READMEs / emails / source / logs the
 * user asked to read. Pre-invocation CONTEXT (tool metadata, initialize
 * instructions) is NOT in this set and stays block-capable.
 *
 * Note: `tool_response` (tools/call result) is deliberately NOT warn-only — it
 * keeps its existing block-capable policy.
 */
const WARN_ONLY_TARGETS: ReadonlySet<SignatureTarget> = new Set<SignatureTarget>([
  "resource_content",
  "prompt_content",
]);

/** Native (pre-clamp) action a finding's severity maps to. */
function severityToAction(sev: Severity): InspectResult["action"] {
  if (sev === "critical") return "block";
  if (sev === "high") return "warn";
  return "pass";
}

/**
 * A finding's effective DEFAULT action: native severity mapping, then clamped to
 * `warn` if the finding sits on a warn-only (retrieved-data) carrier. The
 * finding's `severity` is left untouched — only the action is degraded.
 *
 * Shared with run-inner.ts applyPolicy so the carrier clamp is enforced
 * consistently across the inspect pipeline and the policy pass (no second
 * severity→action recompute can silently re-block a warn-only finding).
 */
export function defaultActionForFinding(f: InspectFinding): InspectResult["action"] {
  const native = severityToAction(f.severity);
  if (WARN_ONLY_TARGETS.has(f.target) && ACTION_RANK[native] > ACTION_RANK.warn) {
    return "warn";
  }
  return native;
}

/**
 * Inspect a JSON-RPC message against a set of signatures, all targets.
 * Highest effective action across findings decides the result:
 *   - critical  → block        (warn-only carriers clamp to warn)
 *   - high      → warn (policy can promote to block)
 *   - medium/low → pass with log
 */
export function inspectMessage(
  msg: JSONRPCMessage,
  signatures: readonly Signature[],
): InspectResult {
  const targets: readonly SignatureTarget[] = [
    "tool_response",
    "tool_call_args",
    "tool_description",
    "tool_annotations",
    "resource_content",
    "prompt_content",
    "initialize_instructions",
  ];
  const findings: InspectFinding[] = [];
  for (const target of targets) {
    const subtree = targetSubtree(msg, target);
    if (subtree === null || subtree === undefined) continue;
    for (const leaf of stringLeaves(subtree)) {
      // H2: scan the RAW leaf for hidden/control chars BEFORE the signature
      // pipeline normalizes them away. Metadata carriers only.
      if (HIDDEN_CHAR_TARGETS.has(target)) {
        findings.push(...detectHiddenChars(leaf, target));
      }
      findings.push(...inspectAgainstSignatures(leaf, signatures, target));
    }
  }
  if (findings.length === 0) return { action: "pass", findings: [] };
  // Max action across findings AFTER each is clamped by its carrier policy. A
  // warn-only resource finding can't be elevated by — and doesn't suppress — a
  // block-capable finding in the same message. (security: H1 finding-level clamp)
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
  return { action, findings };
}
