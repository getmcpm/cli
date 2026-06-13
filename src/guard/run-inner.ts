/**
 * `mcpm guard run --inner` entry point (v0.5.0).
 *
 * Spawned by wrapped client configs after `mcpm guard enable` rewrites them.
 * Wires the production relay to the current process's stdio + the OWASP MCP
 * Top 10 signature set + schema-drift detection against the pin store.
 *
 * IMPORTANT: this is the internal hot path. Keep startup work minimal —
 * security review Reviewer Concern #8 (warm-up latency) calls out cold-start
 * cost for every wrapped-server session. Defer non-essential imports.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage, defaultActionForFinding, ACTION_RANK } from "./patterns.js";
import { OWASP_MCP_TOP_10 } from "./signatures.js";
import { startRelay, buildSafeEnv, type GuardEvent } from "./relay.js";
import { inspectForDrift, classifyDrift, buildDriftFinding } from "./drift.js";
import { readPins, writePins } from "./pins.js";
import { readPolicy, expireStale, PolicyIntegrityError, type GuardPolicyFile } from "./policy.js";
import { appendEvent } from "./event-log.js";
import { sanitizeForTerminal } from "./sanitize.js";
import { resolveEnvPlaceholders } from "../store/keychain.js";
import type { InspectFinding, InspectResult } from "./types.js";

export interface RunInnerArgs {
  readonly serverName: string;
  readonly command: string;
  readonly args: readonly string[];
  /**
   * Issue #20: KEY names of the wrapped server's DECLARED env (embedded in the
   * wrap marker at `enable` time). Only these keys are forwarded from the
   * relay's process.env to the child, on top of the safe baseline — ambient
   * shell secrets (OPENAI_API_KEY, AWS_*, GITHUB_TOKEN, …) are NOT forwarded.
   */
  readonly declaredEnvKeys: readonly string[];
}

const SIGNATURE_LIST_VERSION = "owasp-mcp-top-10@v0.5.0";

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

/**
 * Attach `replyToOrigin: true` to a result ONLY when it requested AND the result
 * is still a block. The flag is meaningless on warn/pass (you don't error-reply a
 * non-blocked request), so it must never survive onto a downgraded action.
 */
function withReplyToOrigin(result: InspectResult, replyToOrigin: boolean): InspectResult {
  if (replyToOrigin && result.action === "block") return { ...result, replyToOrigin: true };
  return result;
}

/**
 * Apply guard-policy.yaml signature_overrides to an inspection result.
 *
 * Per-finding semantics:
 *   - no override  → finding keeps its native severity → action
 *   - "ignore"     → finding is dropped from the result entirely
 *   - "log_only"   → finding is kept (visible in event log) but counts as "pass" for action
 *   - "warn"       → finding is kept, counts as "warn"
 *   - "block"      → finding is kept, counts as "block"
 *
 * Action is the MAX severity across ALL findings post-override. A log_only
 * override on one finding cannot suppress a block from another unmuted
 * finding — security review Step 7 F1 caught this as the previous code's
 * critical bug.
 *
 * With no override, a finding's default action comes from {@link defaultActionForFinding}
 * — which applies the warn-only carrier clamp (a critical match in retrieved
 * resource/prompt data degrades to `warn`). This keeps the clamp from being
 * silently undone by a second severity→action recompute here. An EXPLICIT user
 * override (warn/block/log_only/ignore) still wins: user intent outranks the
 * default carrier policy, so a user can choose to block even retrieved data.
 */
export function applyPolicy(result: InspectResult, policy: GuardPolicyFile): InspectResult {
  const overrides = policy.signature_overrides ?? [];
  if (overrides.length === 0) return result;
  const byId = new Map(overrides.map((o) => [o.id, o]));

  let highest: InspectResult["action"] = "pass";
  const kept: InspectFinding[] = [];
  for (const f of result.findings) {
    const o = byId.get(f.signature_id);
    let perFindingAction: InspectResult["action"];
    if (o === undefined) {
      perFindingAction = defaultActionForFinding(f);
      kept.push(f);
    } else if (o.action === "ignore") {
      continue; // drop entirely
    } else if (o.action === "log_only") {
      perFindingAction = "pass";
      kept.push(f);
    } else {
      perFindingAction = o.action; // "warn" or "block"
      kept.push(f);
    }
    if (ACTION_RANK[perFindingAction] > ACTION_RANK[highest]) highest = perFindingAction;
  }

  // H7: carry replyToOrigin through, but withReplyToOrigin drops it unless the
  // post-policy action is STILL a block — a policy that downgrades block→warn/pass
  // must not leave a stranded reply-to-origin flag on a non-block result.
  return withReplyToOrigin({ action: highest, findings: kept }, result.replyToOrigin === true);
}

function hasToolsList(msg: JSONRPCMessage): boolean {
  if (!("result" in msg)) return false;
  const result = (msg as { result?: { tools?: unknown } }).result;
  return Array.isArray(result?.tools);
}

/**
 * H7: true if `msg` is a server-INITIATED `sampling/createMessage` REQUEST (has
 * an id). Fail-closed on the notification shape: a frame carrying the method but
 * NO id is NOT eligible for block-to-origin — you can't error-reply a
 * notification, so block-to-origin would strand it.
 */
export function isSamplingRequest(msg: JSONRPCMessage): boolean {
  return isServerRequestMethod(msg, "sampling/createMessage");
}

/** H7: true if `msg` is a server-INITIATED `elicitation/create` REQUEST (has an id). */
export function isElicitationRequest(msg: JSONRPCMessage): boolean {
  return isServerRequestMethod(msg, "elicitation/create");
}

function isServerRequestMethod(msg: JSONRPCMessage, method: string): boolean {
  if (!("method" in msg) || (msg as { method?: unknown }).method !== method) return false;
  // A request MUST carry an id; a notification-shaped frame (no id) is not
  // eligible for block-to-origin (no reply channel) — fail closed.
  return "id" in msg && (msg as { id?: unknown }).id !== undefined;
}

/** H7: a server-INITIATED sampling/elicitation method frame (id OR no-id — used
 * for content SCANNING; block-to-origin eligibility separately requires an id). */
function isServerInitiatedMethod(msg: JSONRPCMessage): boolean {
  if (!("method" in msg)) return false;
  const m = (msg as { method?: unknown }).method;
  return m === "sampling/createMessage" || m === "elicitation/create";
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
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");

  const hasId = "id" in msg && (msg as { id?: unknown }).id !== undefined;
  return action === "block" && hasId
    ? { action, findings, replyToOrigin: true }
    : { action, findings };
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

export async function runInner(parsed: RunInnerArgs): Promise<number> {
  const safeName = sanitizeForTerminal(parsed.serverName);

  const logEvent = (event: GuardEvent): void => {
    if (event.action === "block" || event.action === "warn") {
      process.stderr.write(
        `[mcpm-guard] ${event.action.toUpperCase()} ${safeName} ` +
          `${event.findings.map((f) => f.signature_id).join(",")}\n`,
      );
      // Persist to ~/.mcpm/guard-events.jsonl best-effort (Step 10).
      void appendEvent(event, parsed.serverName);
    }
  };

  // Drift detection is async (reads + writes pins.json). The relay's inspect
  // callbacks are sync, so we keep a cached snapshot updated off-thread.
  //
  // FAIL CLOSED on a pins-read error. First-run ENOENT is handled INSIDE
  // readPins (returns an empty pins file, no throw), so the only errors that
  // reach here are the dangerous ones: a PinsIntegrityError (tampered sidecar),
  // EACCES/EMFILE, or a corrupt/invalid pins.json. Swallowing those to an empty
  // snapshot would silently disable cross-session rug-pull detection — exactly
  // when it matters most. Refuse to start the relay instead.
  let pinsSnapshot: PinsFile;
  try {
    pinsSnapshot = await readPins();
  } catch (err) {
    process.stderr.write(
      `[mcpm-guard] PINS-READ-ERROR: ${safeName} could not load ~/.mcpm/pins.json: ` +
        `${(err as Error).message}\n` +
        `Refusing to start the relay — running with rug-pull (schema-drift) protection ` +
        `silently disabled is more dangerous than not starting. Review ` +
        `~/.mcpm/guard-events.jsonl for unauthorized activity. If you intentionally ` +
        `changed pins.json, run \`mcpm guard reset-integrity\`.\n`,
    );
    process.exit(1);
  }

  // Load policy once per session (mute/pause/etc.). Stale overrides expire
  // here; the next session picks up fresh state. Pausing mid-session is not
  // supported in v0.5.0 — restart the wrapped server to pick up changes.
  //
  // The `{}` fallback is the SAFE state (full enforcement), so we keep falling
  // back on any read failure. BUT a PolicyIntegrityError (tampered
  // guard-policy.yaml) would otherwise be invisible — surface it on stderr
  // before falling back so the user knows their policy file was tampered with.
  const policy = expireStale(
    await readPolicy().catch((err: unknown) => {
      if (err instanceof PolicyIntegrityError) {
        process.stderr.write(
          `[mcpm-guard] POLICY-INTEGRITY-ERROR: ${safeName} ${(err as Error).message}\n` +
            `Falling back to full enforcement (ignoring guard-policy.yaml) for this session.\n`,
        );
      } else {
        // Generic non-ENOENT I/O error (EACCES, EMFILE, …). ENOENT is already
        // returned as {} inside readPolicy and never reaches here. The {}
        // fallback is the SAFE state (full enforcement), but swallowing the
        // error silently hides a misconfigured/unreadable policy file — surface
        // it on stderr before falling back. Do NOT exit: enforcement is preserved.
        process.stderr.write(
          `[mcpm-guard] POLICY-READ-ERROR: ${(err as Error).message}\n`,
        );
      }
      return {};
    }),
  );
  const pausedUntilFuture =
    policy.paused_until !== undefined && new Date(policy.paused_until) > new Date();

  // SECURITY F3: per-session drift state — the "first hash seen" cache + the H4
  // single-shot re-validation arm. Closes the double-tools/list bypass (a server
  // sending two tools/list within a session must hash-match or block) while
  // letting an ANNOUNCED list_changed legitimately re-baseline once.
  const sessionState: SessionDriftState = { firstHashes: new Map(), revalidationArmed: false };

  // FROZEN session-start baseline. The off-thread refresh may keep reassigning
  // pinsSnapshot for its own fallback, but the sync classifier must compare
  // against the immutable session-start pins so a mid-session pin rewrite can't
  // retroactively launder a drift.
  const baselineForDrift = pinsSnapshot;

  const inspectChild = (msg: JSONRPCMessage): InspectResult => {
    if (pausedUntilFuture) return { action: "pass", findings: [] };

    // H4: a server→client list_changed notification ARMS single-shot
    // re-validation. Forward it silently (no stderr noise) — the follow-up
    // list's classification is the logged event. No pattern/drift on the bare
    // notification.
    if (isToolsListChangedNotification(msg)) {
      sessionState.revalidationArmed = true;
      return { action: "pass", findings: [] };
    }

    // H7: a server-INITIATED sampling/elicitation request — scan its
    // server-authored content for prompt injection BEFORE the regular pattern/
    // drift path. A detected injection blocks the request BACK to the server
    // (replyToOrigin), via applyPolicy so user overrides still apply. A benign
    // request returns null here and falls through to forward untouched (we gate
    // the injection content, not the mechanism).
    const serverInitiated = inspectServerInitiated(msg);
    if (serverInitiated !== null) return applyPolicy(serverInitiated, policy);

    const patternResult = inspectMessage(msg, OWASP_MCP_TOP_10);
    let driftResult: InspectResult = { action: "pass", findings: [] };

    if (hasToolsList(msg)) {
      driftResult = inspectForDriftSync(msg, parsed.serverName, baselineForDrift, sessionState);

      // Off-thread: refresh snapshot + apply first-session pin capture.
      void (async () => {
        await inspectForDrift(msg, parsed.serverName, {
          read: () => readPins().catch(() => pinsSnapshot),
          write: writePins,
          signatureListVersion: SIGNATURE_LIST_VERSION,
        });
        pinsSnapshot = await readPins().catch(() => pinsSnapshot);
      })();
    }

    return applyPolicy(mergeInspect(patternResult, driftResult), policy);
  };

  const inspectParent = (msg: JSONRPCMessage): InspectResult => {
    if (pausedUntilFuture) return { action: "pass", findings: [] };
    return applyPolicy(inspectMessage(msg, OWASP_MCP_TOP_10), policy);
  };

  // SECURITY F2 / issue #20: build the wrapped child's env from an intentional
  // allowlist instead of forwarding the relay's entire process.env. The relay
  // env mixes the user's AMBIENT shell secrets (OPENAI_API_KEY, AWS_*,
  // GITHUB_TOKEN, …) with the IDE-injected DECLARED vars; the wrapped server is
  // only semi-trusted, so it must see just:
  //   1. a safe baseline (PATH, HOME, locale, … via buildSafeEnv), plus
  //   2. the server's own DECLARED env keys (names carried in the wrap marker).
  // Values written as `mcpm:keychain:server/KEY` placeholders (by `mcpm
  // secrets`) are then resolved to their decrypted secrets, so the plaintext
  // exists only in this child's in-memory env and never on disk.
  const baselineEnv = buildSafeEnv(process.env);
  const childEnvSource: NodeJS.ProcessEnv = { ...baselineEnv };
  for (const key of parsed.declaredEnvKeys) {
    const value = process.env[key];
    if (value !== undefined) childEnvSource[key] = value;
  }

  let childEnv: Record<string, string>;
  try {
    childEnv = await resolveEnvPlaceholders(childEnvSource);
  } catch (err) {
    process.stderr.write(
      `[mcpm-guard] SECRET-MISSING ${safeName} ${(err as Error).message}\n`,
    );
    return 1;
  }

  const handle = startRelay({
    command: parsed.command,
    args: parsed.args,
    env: childEnv,
    parentIn: process.stdin,
    parentOut: process.stdout,
    inspectChildResponse: inspectChild,
    inspectParentRequest: inspectParent,
    onEvent: logEvent,
  });

  return handle.exit;
}

// ---------------------------------------------------------------------------
// Sync drift inspection against a pin snapshot (no I/O — pure function).
// drift.ts has the async version that also writes first-session pins; this
// is the sync variant the per-message inspect callback uses.
// ---------------------------------------------------------------------------

import { hashToolDefinition, fieldHashesOf, type PinsFile } from "./pins.js";

/**
 * Per-session drift state. `firstHashes` is the SECURITY F3 same-session "first
 * hash seen" cache (the ONE deliberately-mutable in-memory session cache).
 * `revalidationArmed` is a SINGLE-SHOT flag set by an announced
 * `notifications/tools/list_changed`: the next tools/list frame is allowed to
 * legitimately change definitions, after which the flag reverts to the strict
 * F3 guard.
 */
export interface SessionDriftState {
  firstHashes: Map<string, string>;
  revalidationArmed: boolean;
}

function sanitizeLabel(s: string): string {
  return sanitizeForTerminal(s, 128);
}

/**
 * Sync, pure-ish (no I/O) drift inspection against an in-memory pin snapshot.
 * The ONLY mutation is the session-state cache (firstHashes / revalidationArmed)
 * — a deliberate in-memory session store. Exported for unit testing the
 * SECURITY F3 same-session guard + the H4 tiered classification; the async
 * {@link inspectForDrift} in drift.ts also writes first-session pins.
 */
export function inspectForDriftSync(
  msg: JSONRPCMessage,
  serverName: string,
  baseline: PinsFile,
  state: SessionDriftState,
): InspectResult {
  // Frame-scoped single-shot arm: read then immediately disarm so a SECOND
  // frame in the same buffer chunk reverts to the strict F3 guard.
  const armed = state.revalidationArmed;
  state.revalidationArmed = false;

  const result = (msg as { result?: { tools?: unknown } }).result;
  const tools = Array.isArray(result?.tools) ? result.tools : [];

  const findings: InspectFinding[] = [];
  for (const rawTool of tools) {
    const finding = inspectToolDrift(rawTool, serverName, baseline, state, armed);
    if (finding !== null) findings.push(finding);
  }
  // Action = MAX over findings via defaultActionForFinding (no hardcoded block):
  // a cosmetic-only result is warn; any security finding makes it block.
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
  return { action, findings };
}

interface RawTool {
  name?: unknown;
  description?: unknown;
  schema?: unknown;
  inputSchema?: unknown;
  annotations?: unknown;
}

/**
 * Inspect ONE tool from a tools/list frame. Mutates the session `firstHashes`
 * cache (records on first sight, rebaselines when `armed`). Returns at most one
 * finding (F3 same-session block, OR a tiered pin-drift finding), or null.
 */
function inspectToolDrift(
  rawTool: unknown,
  serverName: string,
  baseline: PinsFile,
  state: SessionDriftState,
  armed: boolean,
): InspectFinding | null {
  if (rawTool === null || typeof rawTool !== "object") return null;
  const tool = rawTool as RawTool;
  const toolName = typeof tool.name === "string" ? tool.name : null;
  if (toolName === null) return null;

  const fields = {
    description: typeof tool.description === "string" ? tool.description : null,
    schema: tool.inputSchema ?? tool.schema,
    annotations: tool.annotations,
  };
  const liveWhole = hashToolDefinition(fields);
  const liveFields = fieldHashesOf(fields);

  // SECURITY F13: lookup via Object.hasOwn to avoid prototype/constructor confusion.
  const serverPins = Object.hasOwn(baseline.servers, serverName) ? baseline.servers[serverName] : undefined;
  const pinned = serverPins && Object.hasOwn(serverPins, toolName) ? serverPins[toolName] : undefined;

  // SECURITY F3: same-session bypass check. If we've already seen a hash for
  // (server, tool) this session, a subsequent differing tools/list is a rug-pull
  // attempt — UNLESS `armed` (an announced list_changed legitimately changes
  // definitions). When armed we skip F3 and rebaseline instead.
  const sessionKey = `${serverName}::${toolName}`;
  const firstSeen = state.firstHashes.get(sessionKey);
  if (!armed && firstSeen !== undefined && firstSeen !== liveWhole) {
    return inSessionDriftFinding(serverName, toolName, firstSeen, liveWhole);
  }
  // Record on first sight, or rebaseline when an announced list_changed armed us.
  if (firstSeen === undefined || armed) state.firstHashes.set(sessionKey, liveWhole);

  if (!pinned || pinned.current_hash === null) return null;
  if (liveWhole === pinned.current_hash) return null;

  // Tier the drift by field (cosmetic description-only → warn; schema /
  // annotations / coarse → block). Same finding shapes as drift.ts. For a
  // cosmetic warn, carry a sanitized + truncated NEW description so the
  // guard-events.jsonl entry is self-contained for review.
  const cls = classifyDrift(pinned, liveFields);
  const newDescriptionExcerpt =
    typeof tool.description === "string" ? sanitizeForTerminal(tool.description, 80) : undefined;
  return buildDriftFinding({
    cls,
    safeServer: sanitizeLabel(serverName),
    safeTool: sanitizeLabel(toolName),
    expected: pinned.current_hash,
    actual: liveWhole,
    newDescriptionExcerpt,
  });
}

/** SECURITY F3: same-session double-tools/list rug-pull finding (critical block). */
function inSessionDriftFinding(
  serverName: string,
  toolName: string,
  firstSeen: string,
  liveWhole: string,
): InspectFinding {
  return {
    signature_id: "schema-drift-in-session",
    category: "OWASP-MCP-1",
    severity: "critical",
    target: "tool_description",
    matched_text_excerpt: `${sanitizeLabel(toolName)}: ${firstSeen.slice(7, 19)}… → ${liveWhole.slice(7, 19)}… (same session)`,
    remediation:
      `Server "${sanitizeLabel(serverName)}" delivered two different schemas for tool "${sanitizeLabel(toolName)}" ` +
      `in the same session. This is a rug-pull attempt; restart the IDE and reinspect ` +
      `the server's source.`,
  };
}

/** True if `msg` is a server→client `notifications/tools/list_changed`. */
export function isToolsListChangedNotification(msg: JSONRPCMessage): boolean {
  if (!("method" in msg)) return false;
  if ((msg as { method?: unknown }).method !== "notifications/tools/list_changed") return false;
  // A notification has no `result` (and no `id`); guard against a crafted frame
  // that pairs the method with a result.
  return !("result" in msg);
}
