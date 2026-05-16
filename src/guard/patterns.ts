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
    // tools/call response → result.content[*]
    if ("result" in msg) {
      const result = (msg as { result?: { content?: unknown } }).result;
      return result?.content ?? null;
    }
    return null;
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
    // tools/list response → result.tools[*].description
    if ("result" in msg) {
      const result = (msg as { result?: { tools?: Array<{ description?: string }> } }).result;
      const tools = result?.tools;
      if (!tools) return null;
      return tools.map((t) => t.description ?? "");
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
 * NFKC-normalize a string leaf and run every signature whose target matches
 * the inspection scope. Returns all matches as findings.
 *
 * Skip leaves longer than 1MB defensively — those are not user-instruction-
 * shaped and would dominate the engine's tail latency on pathological input.
 */
const MAX_LEAF_BYTES = 1_024 * 1_024; // 1MB

function normalizeForMatch(leaf: string): string {
  if (leaf.length > MAX_LEAF_BYTES) return leaf; // skip normalization on huge leaves
  return leaf.normalize("NFKC");
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
