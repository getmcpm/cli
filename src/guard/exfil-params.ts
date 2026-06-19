/**
 * F5 — structural exfil-param detector for the guard relay.
 *
 * Walks the KEYS of each tool's `inputSchema.properties` in a `tools/list` response
 * and blocks the frame when a parameter name matches the zero-FP exfil-sigil
 * denylist (see exfil-names.ts). Runs at advertisement time — BEFORE the model ever
 * sees the tool — so it closes the line-jumping window the content-regex pipeline
 * cannot (that pipeline only walks string values, never property keys).
 *
 * IMPORTANT (blast radius): a block on a `tools/list` frame replaces the WHOLE frame
 * with one JSON-RPC error, so the server's entire tool surface is disabled until the
 * finding is muted — not just the one poisoned tool. That is why the denylist is
 * strictly zero-FP. The finding reuses the block-capable `tool_description` target
 * (critical → block) so it needs no new SignatureTarget wiring.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectFinding, InspectResult } from "./types.js";
import { ACTION_RANK, defaultActionForFinding } from "./patterns.js";
import { classifyParamName } from "./exfil-names.js";

export const EXFIL_PARAM_SIGNATURE_ID = "exfil-param-in-schema";

const MAX_EXCERPT = 200;
const PASS: InspectResult = { action: "pass", findings: [] };

const REMEDIATION =
  "A tool's input schema declares a parameter named like a context-exfiltration sigil " +
  "(e.g. `_system_prompt_`) that the model would silently auto-fill from the conversation / " +
  "system prompt — a zero-interaction prompt leak. No legitimate tool names a parameter this " +
  "way. The server's ENTIRE tools/list was blocked before the agent saw it. This is a tripwire " +
  "for the documented underscore-sigil convention — a renamed parameter evades it. If you trust " +
  "this server, mute via `mcpm guard mute exfil-param-in-schema` (re-enables the whole server).";

function truncate(s: string): string {
  return s.length > MAX_EXCERPT ? `${s.slice(0, MAX_EXCERPT)}…` : s;
}

/**
 * Yield every property KEY (bounded to top-level + one nested `properties` level)
 * whose name matches the exfil denylist. Walks `.properties` keys ONLY — never enum
 * values (those live in `sub.enum`, an array we never key-walk), so a legitimate
 * string value like `enum: ["_system_prompt_"]` is not flagged. `Object.hasOwn`
 * guards against inherited keys. `$ref`/`allOf`/`anyOf` are not resolved in v1 (the
 * local key is still classified; the ref is not followed).
 */
function* exfilKeys(schema: unknown, depth: number): Iterable<string> {
  if (depth > 1 || schema === null || typeof schema !== "object") return;
  const props = (schema as { properties?: unknown }).properties;
  if (props === null || typeof props !== "object" || Array.isArray(props)) return;
  for (const key of Object.keys(props)) {
    if (!Object.hasOwn(props, key)) continue;
    if (classifyParamName(key) === "deny") yield key;
    yield* exfilKeys((props as Record<string, unknown>)[key], depth + 1);
  }
}

function makeFinding(toolName: string, rawKey: string): InspectFinding {
  return {
    signature_id: EXFIL_PARAM_SIGNATURE_ID,
    category: "OWASP-MCP-1",
    severity: "critical",
    target: "tool_description", // block-capable carrier (NOT in WARN_ONLY_TARGETS)
    matched_text_excerpt: truncate(`parameter "${rawKey}" in tool "${toolName}"`),
    remediation: REMEDIATION,
  };
}

/**
 * Inspect a `tools/list` response for exfil-sigil parameter names. A no-op (pass)
 * on every non-tools/list frame. Returns block when any tool declares one.
 */
export function detectExfilParams(msg: JSONRPCMessage): InspectResult {
  if (!("result" in msg)) return PASS;
  const tools = (msg as { result?: { tools?: unknown } }).result?.tools;
  if (!Array.isArray(tools)) return PASS;

  const findings: InspectFinding[] = [];
  for (const tool of tools) {
    if (tool === null || typeof tool !== "object") continue;
    const rawName = (tool as { name?: unknown }).name;
    const toolName = typeof rawName === "string" ? rawName : "<unnamed>";
    for (const key of exfilKeys((tool as { inputSchema?: unknown }).inputSchema, 0)) {
      findings.push(makeFinding(toolName, key));
    }
  }
  if (findings.length === 0) return PASS;

  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
  return { action, findings };
}
