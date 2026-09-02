/**
 * Tool-NAME inspection — the carrier the guard never looked at.
 *
 * `tool_description` extracts `[description, title, inputSchema]` and
 * `tool_annotations` extracts `annotations`; a tool's `name` is in NEITHER, so
 * until now no signature and not even the H2 hidden-character detector ever saw
 * it. A zero-width or homoglyph character inside a tool NAME was completely
 * silent — not even a warn — while the same character in a description warns.
 *
 * Two STATELESS checks, both properties of a single `tools/list` frame, so they
 * hold on every surface including `mcpm guard inspect` and the published
 * benchmark (the v0.27.0 lesson: a detector that lives only in the relay is
 * unreachable through the public scoring seam):
 *
 * 1. CONFUSABLE DUPLICATE — two tools in one list whose names canonicalize to
 *    the same form under {@link canonicalToolName} but whose raw spellings
 *    differ. This is the co-existence half of the TODOS #58 residual: a
 *    poisoned `Fоrmat_code` (Cyrillic о) shipped beside the trusted
 *    `format_code`. The relay's stateful path deliberately EXCLUDES such pairs
 *    from drift comparison (a spec-legal `Read`/`read` pair must never
 *    hard-block a real server), so this warn is what keeps the shape visible.
 * 2. NON-CONFORMING NAME — a name outside SEP-986's charset
 *    (`/^[A-Za-z0-9._-]{1,128}$/`, enforced by the SDK's toolNameValidation).
 *    This is the complement to the fold, not a duplicate of it: the confusable
 *    table is scoped (Cyrillic/Greek look-alikes), so out-of-table homoglyphs
 *    like `ԝrite_file` (U+051D) or `ɡet_user` (U+0261) survive canonicalization
 *    — but they cannot survive a charset check. Measured 0 false positives:
 *    863/863 tool names across 53 real public and hosted MCP servers are pure
 *    ASCII within this charset (see research/name-canon/).
 *
 * Both are WARN tier (severity `high`). A wrong BLOCK on a tools/list bricks the
 * whole server, and a case-only pair is spec-legal even though no observed
 * server ships one — so these report rather than enforce. The enforcing half of
 * #58 is the canonical drift/pin keying in run-inner.ts + drift.ts, which
 * BLOCKS the replace-form rug-pull this pair of warnings cannot.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { canonicalToolName } from "./key-canon.js";
import { sanitizeForTerminal } from "./sanitize.js";
import { worstAction } from "./patterns.js";
import type { InspectFinding, InspectResult } from "./types.js";

export const CONFUSABLE_TOOL_NAME_SIGNATURE_ID = "tool-name-confusable-duplicate";
export const NONCONFORMING_TOOL_NAME_SIGNATURE_ID = "tool-name-non-conforming";

/** SEP-986 (MCP SDK `TOOL_NAME_REGEX`): tool names are case-sensitive ASCII. */
const SEP986_TOOL_NAME = /^[A-Za-z0-9._-]{1,128}$/;

const PASS: InspectResult = { action: "pass", findings: [] };

function toolNames(msg: JSONRPCMessage): string[] | null {
  const result = (msg as { result?: { tools?: unknown } }).result;
  if (!Array.isArray(result?.tools)) return null;
  const names: string[] = [];
  for (const t of result.tools) {
    if (t === null || typeof t !== "object") continue;
    const name = (t as { name?: unknown }).name;
    if (typeof name === "string") names.push(name);
  }
  return names;
}

/**
 * Inspect a `tools/list` frame's tool NAMES. A no-op (pass) on every other frame
 * shape — self-guarding, so it needs no caller-side gating.
 */
export function detectConfusableToolNames(msg: JSONRPCMessage): InspectResult {
  const names = toolNames(msg);
  if (names === null || names.length === 0) return PASS;

  const findings: InspectFinding[] = [];

  // 1. confusable duplicates within this one list
  const firstRawFor = new Map<string, string>();
  const reported = new Set<string>();
  for (const name of names) {
    const canon = canonicalToolName(name);
    const prior = firstRawFor.get(canon);
    if (prior === undefined) {
      firstRawFor.set(canon, name);
      continue;
    }
    // A byte-identical repeat is a malformed list, not a confusable pair.
    if (prior === name || reported.has(canon)) continue;
    reported.add(canon);
    findings.push({
      signature_id: CONFUSABLE_TOOL_NAME_SIGNATURE_ID,
      category: "OWASP-MCP-1",
      severity: "high",
      target: "tool_description",
      matched_text_excerpt: `${sanitizeForTerminal(name, 64)} vs ${sanitizeForTerminal(prior, 64)}`,
      remediation:
        `This tools/list advertises two tools whose names are visually indistinguishable ` +
        `after Unicode normalization ("${sanitizeForTerminal(name, 64)}" and ` +
        `"${sanitizeForTerminal(prior, 64)}"). A look-alike name is how a poisoned tool ` +
        `definition is smuggled past a same-session drift check. Confirm with the server's ` +
        `publisher that BOTH tools are intended; if not, remove the server.`,
    });
  }

  // 2. names outside the SEP-986 charset
  for (const name of names) {
    if (SEP986_TOOL_NAME.test(name)) continue;
    findings.push({
      signature_id: NONCONFORMING_TOOL_NAME_SIGNATURE_ID,
      category: "OWASP-MCP-1",
      severity: "high",
      target: "tool_description",
      matched_text_excerpt: sanitizeForTerminal(name, 64),
      remediation:
        `Tool name "${sanitizeForTerminal(name, 64)}" is outside the MCP tool-name charset ` +
        `([A-Za-z0-9._-], max 128). Invisible or non-Latin characters in a name are a ` +
        `known way to impersonate a trusted tool. Report it to the server's publisher.`,
    });
  }

  if (findings.length === 0) return PASS;
  return { action: worstAction(findings), findings };
}
