/**
 * The ONE stateless inspection composition — everything the guard can decide
 * about a single frame without relay state (no pins, no session, no policy).
 *
 * Why this module exists: the relay composed three detectors inline
 * (`inspectMessage` + `detectExfilParams` + `inspectServerInitiated`) while
 * `mcpm guard inspect` and the fixture release-gate each called `inspectMessage`
 * alone. So the PUBLIC scoring seam reported `pass` on frames the relay blocks
 * as critical, for 3 of the 12 catalog signatures — and because
 * `mcptox.test.ts` evaluated fixtures through the same incomplete pipeline, a
 * fixture for one of those signatures would have FAILED the release gate. The
 * corpus was shaped by the hole, and mcp-guardbench (which extracts from that
 * corpus) inherited it. One composition, three consumers, no drift.
 *
 * Deliberately excluded — these need relay state and stay in run-inner:
 * schema/handshake drift (pin store + per-session cache) and policy overrides.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage, ACTION_RANK, worstAction } from "./patterns.js";
import { detectExfilParams } from "./exfil-params.js";
import { detectShellMetacharArgs } from "./shell-metachar-args.js";
import { detectQueryControlArgs } from "./query-control-args.js";
import { detectCliFlagInjectionArgs } from "./cli-flag-injection-args.js";
import { detectConfusableToolNames } from "./tool-name-confusable.js";
import { OWASP_MCP_TOP_10 } from "./signatures.js";
import type { InspectFinding, InspectResult } from "./types.js";

/**
 * H7: replyToOrigin is only meaningful on a block. A policy that downgrades
 * block→warn/pass must not leave a stranded reply-to-origin flag behind.
 */
export function withReplyToOrigin(result: InspectResult, replyToOrigin: boolean): InspectResult {
  if (replyToOrigin && result.action === "block") return { ...result, replyToOrigin: true };
  return result;
}

export function mergeInspect(a: InspectResult, b: InspectResult): InspectResult {
  // Most-severe action wins; concat findings. Uses the shared ACTION_RANK scale
  // (pass < warn < block) instead of a local duplicate map.
  const action = ACTION_RANK[a.action] >= ACTION_RANK[b.action] ? a.action : b.action;
  // H7: carry replyToOrigin if EITHER side requested it (a server-initiated
  // sampling/elicitation block must not be stranded by merging with a benign
  // pattern/drift result). Only kept on a block action (see withReplyToOrigin).
  return withReplyToOrigin(
    { action, findings: [...a.findings, ...b.findings] },
    a.replyToOrigin === true || b.replyToOrigin === true,
  );
}

export function hasToolsList(msg: JSONRPCMessage): boolean {
  if (!("result" in msg)) return false;
  const result = (msg as { result?: { tools?: unknown } }).result;
  return Array.isArray(result?.tools);
}

/** H7: a server-INITIATED sampling/elicitation method frame (id OR no-id — used
 * for content SCANNING; block-to-origin eligibility separately requires an id). */
function isServerInitiatedMethod(msg: JSONRPCMessage): boolean {
  if (!("method" in msg)) return false;
  const m = (msg as { method?: unknown }).method;
  return m === "sampling/createMessage" || m === "elicitation/create";
}

/**
 * Extract the server-authored content leaves to scan from a sampling/elicitation
 * request: sampling → params.systemPrompt + params.messages[*].content;
 * elicitation → params.message plus the requestedSchema property descriptions.
 * Non-object/missing shapes yield an empty list (nothing to scan).
 */
function serverInitiatedContent(msg: JSONRPCMessage): unknown[] {
  const params = (msg as { params?: unknown }).params;
  if (params === null || typeof params !== "object") return [];
  const p = params as {
    messages?: unknown;
    message?: unknown;
    requestedSchema?: unknown;
    systemPrompt?: unknown;
  };
  const out: unknown[] = [];
  // systemPrompt is server-authored model context (MCP CreateMessageRequestParams)
  // and the highest-leverage sampling injection surface — scan it (review: HIGH).
  if (typeof p.systemPrompt === "string") out.push(p.systemPrompt);
  if (Array.isArray(p.messages)) {
    for (const m of p.messages) {
      if (m !== null && typeof m === "object" && "content" in m) out.push((m as { content: unknown }).content);
    }
  }
  if (typeof p.message === "string") out.push(p.message);
  if (p.requestedSchema !== null && typeof p.requestedSchema === "object") out.push(p.requestedSchema);
  return out;
}

/**
 * H7: inspect a server-INITIATED sampling/elicitation request's server-authored
 * content for prompt-injection. Returns block (+ replyToOrigin when the frame can
 * be error-replied) on a detected injection, else null (benign / out of scope) →
 * caller forwards untouched. We gate the injection CONTENT, not the mechanism.
 *
 * The content is wrapped into a synthetic `prompts/get`-shaped frame so the
 * existing `prompt_content` array-content extraction (H1) scans it WITHOUT a new
 * targetSubtree case. But the findings are then RE-TAGGED to `sampling_prompt`:
 *   - `prompt_content` is a WARN_ONLY carrier (retrieved prompts/get data), so
 *     leaving the finding on it makes applyPolicy's defaultActionForFinding clamp
 *     the block back to WARN whenever guard-policy.yaml has ANY signature_override
 *     — silently forwarding the injection (CRITICAL, caught in review).
 *   - `sampling_prompt` is NOT warn-only, so the action derives from the finding's
 *     native severity (critical→block) and survives applyPolicy unclamped.
 * Content scanning covers BOTH id-bearing requests and no-id (notification-shaped)
 * frames; only an id-bearing block carries replyToOrigin (a no-id frame is still
 * dropped — makeBlockResponse returns null for it — but has no reply channel).
 */
export function inspectServerInitiated(msg: JSONRPCMessage): InspectResult | null {
  if (!isServerInitiatedMethod(msg)) return null;
  const contentLeaves = serverInitiatedContent(msg);
  if (contentLeaves.length === 0) return null;

  const synthetic = {
    jsonrpc: "2.0",
    id: 0, // dummy — the scan reads only the result subtree, never the id.
    result: { messages: contentLeaves.map((c) => ({ role: "user", content: c })) },
  } as JSONRPCMessage;

  const scan = inspectMessage(synthetic, OWASP_MCP_TOP_10);
  if (scan.findings.length === 0) return null;

  const findings: InspectFinding[] = scan.findings.map((f) => ({ ...f, target: "sampling_prompt" }));
  const action = worstAction(findings);

  const hasId = "id" in msg && (msg as { id?: unknown }).id !== undefined;
  return action === "block" && hasId
    ? { action, findings, replyToOrigin: true }
    : { action, findings };
}

/**
 * The pattern/structural detectors that apply regardless of which direction a
 * frame travels: the OWASP regex catalog, detectExfilParams (self-guards on
 * `result.tools` — a no-op on anything else), and detectShellMetacharArgs +
 * detectQueryControlArgs + detectCliFlagInjectionArgs (all three self-guard on
 * a `tools/call` request — a no-op on anything else). No caller-side gating
 * needed. reduce(mergeInspect) over an array (rather than nested calls) so
 * adding a future detector is a one-line array entry, not a growing nest of
 * merges.
 *
 * Deliberately EXCLUDES inspectServerInitiated: that check is only valid on
 * the child->parent direction (a server sending sampling/createMessage or
 * elicitation/create). run-inner.ts's inspectParent (parent->child requests)
 * uses this function directly, not inspectFrame, so a malformed/malicious
 * client message can never trip isServerInitiatedMethod and get routed
 * through inspectServerInitiated's replyToOrigin path — found in review: the
 * in-process relay's inspectAndWrite sink selection for replyToOrigin is
 * shared, non-direction-aware code, so a parent-side false match would have
 * misrouted a block response to the child instead of back to the real client.
 */
export function inspectStatelessDetectors(msg: JSONRPCMessage): InspectResult {
  return [
    inspectMessage(msg, OWASP_MCP_TOP_10),
    detectExfilParams(msg),
    detectShellMetacharArgs(msg),
    detectQueryControlArgs(msg),
    detectCliFlagInjectionArgs(msg),
    detectConfusableToolNames(msg),
  ].reduce(mergeInspect);
}

/**
 * Every stateless verdict the guard can reach for one CHILD->PARENT frame (a
 * server response or a server-initiated request). A server-initiated
 * sampling/elicitation frame SHORT-CIRCUITS, matching the relay: such a frame
 * carries `method`, never `result`, so the pattern and exfil passes would
 * have nothing to inspect anyway. Only ever call this on child-authored
 * content — see inspectStatelessDetectors above for the parent->child path.
 */
export function inspectFrame(msg: JSONRPCMessage): InspectResult {
  const serverInitiated = inspectServerInitiated(msg);
  if (serverInitiated !== null) return serverInitiated;
  return inspectStatelessDetectors(msg);
}
