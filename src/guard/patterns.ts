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

function normalizeForMatch(leaf: string): string {
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

function severityRank(s: Severity): number {
  switch (s) {
    case "critical": return 3;
    case "high":     return 2;
    case "medium":   return 1;
    case "low":      return 0;
  }
}

/**
 * Inspect a JSON-RPC message against a set of signatures, all targets.
 * Highest-severity finding decides the action:
 *   - critical  → block
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
  ];
  const findings: InspectFinding[] = [];
  for (const target of targets) {
    const subtree = targetSubtree(msg, target);
    if (subtree === null || subtree === undefined) continue;
    for (const leaf of stringLeaves(subtree)) {
      findings.push(...inspectAgainstSignatures(leaf, signatures, target));
    }
  }
  if (findings.length === 0) return { action: "pass", findings: [] };
  const topSeverity = findings.reduce<Severity>(
    (acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc),
    "low",
  );
  const action = topSeverity === "critical" ? "block" : topSeverity === "high" ? "warn" : "pass";
  return { action, findings };
}
