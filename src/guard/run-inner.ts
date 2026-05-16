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
import { inspectMessage } from "./patterns.js";
import { OWASP_MCP_TOP_10 } from "./signatures.js";
import { startRelay, type GuardEvent } from "./relay.js";
import { inspectForDrift } from "./drift.js";
import { readPins, writePins, emptyPinsFile } from "./pins.js";
import { readPolicy, expireStale, type GuardPolicyFile } from "./policy.js";
import { sanitizeForTerminal } from "./sanitize.js";
import type { InspectFinding, InspectResult } from "./types.js";

export interface RunInnerArgs {
  readonly serverName: string;
  readonly command: string;
  readonly args: readonly string[];
}

const SIGNATURE_LIST_VERSION = "owasp-mcp-top-10@v0.5.0";

function mergeInspect(a: InspectResult, b: InspectResult): InspectResult {
  // Most-severe action wins; concat findings.
  const rank = { block: 3, warn: 2, pass: 1 } as const;
  const action = rank[a.action] >= rank[b.action] ? a.action : b.action;
  return { action, findings: [...a.findings, ...b.findings] };
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
 */
function applyPolicy(result: InspectResult, policy: GuardPolicyFile): InspectResult {
  const overrides = policy.signature_overrides ?? [];
  if (overrides.length === 0) return result;
  const byId = new Map(overrides.map((o) => [o.id, o]));

  const rank = { pass: 0, warn: 1, block: 2 } as const;
  const fromSeverity = (sev: InspectFinding["severity"]): InspectResult["action"] => {
    if (sev === "critical") return "block";
    if (sev === "high") return "warn";
    return "pass";
  };

  let highest: InspectResult["action"] = "pass";
  const kept: InspectFinding[] = [];
  for (const f of result.findings) {
    const o = byId.get(f.signature_id);
    let perFindingAction: InspectResult["action"];
    if (o === undefined) {
      perFindingAction = fromSeverity(f.severity);
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
    if (rank[perFindingAction] > rank[highest]) highest = perFindingAction;
  }

  return { action: highest, findings: kept };
}

function hasToolsList(msg: JSONRPCMessage): boolean {
  if (!("result" in msg)) return false;
  const result = (msg as { result?: { tools?: unknown } }).result;
  return Array.isArray(result?.tools);
}

export async function runInner(parsed: RunInnerArgs): Promise<number> {
  const safeName = sanitizeForTerminal(parsed.serverName);

  const logEvent = (event: GuardEvent): void => {
    if (event.action === "block" || event.action === "warn") {
      process.stderr.write(
        `[mcpm-guard] ${event.action.toUpperCase()} ${safeName} ` +
          `${event.findings.map((f) => f.signature_id).join(",")}\n`,
      );
    }
  };

  // Drift detection is async (reads + writes pins.json). The relay's inspect
  // callbacks are sync, so we keep a cached snapshot updated off-thread.
  let pinsSnapshot = await readPins().catch(() => emptyPinsFile());

  // Load policy once per session (mute/pause/etc.). Stale overrides expire
  // here; the next session picks up fresh state. Pausing mid-session is not
  // supported in v0.5.0 — restart the wrapped server to pick up changes.
  const policy = expireStale(await readPolicy().catch(() => ({})));
  const pausedUntilFuture =
    policy.paused_until !== undefined && new Date(policy.paused_until) > new Date();

  // SECURITY F3: per-session "first hash seen" map. Closes the double-
  // tools/list bypass — if a server sends two tools/list within the same
  // session, the second must hash-match the first or it blocks. Without this,
  // a malicious server could deliver benign-then-poisoned tools/list back-to-
  // back before the off-thread pin write completes; both would pass sync
  // inspection because pinsSnapshot has no pin for the tool yet.
  const sessionFirstHashes = new Map<string, string>();

  const inspectChild = (msg: JSONRPCMessage): InspectResult => {
    if (pausedUntilFuture) return { action: "pass", findings: [] };
    const patternResult = inspectMessage(msg, OWASP_MCP_TOP_10);
    let driftResult: InspectResult = { action: "pass", findings: [] };

    if (hasToolsList(msg)) {
      driftResult = inspectForDriftSync(msg, parsed.serverName, pinsSnapshot, sessionFirstHashes);

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

  // SECURITY F2: forward env unchanged — IDE already chose which vars to expose.
  const handle = startRelay({
    command: parsed.command,
    args: parsed.args,
    env: process.env,
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

import { hashToolDefinition, type PinsFile } from "./pins.js";

function inspectForDriftSync(
  msg: JSONRPCMessage,
  serverName: string,
  pins: PinsFile,
  sessionFirstHashes: Map<string, string>,
): InspectResult {
  const result = (msg as { result?: { tools?: unknown } }).result;
  const tools = Array.isArray(result?.tools) ? result.tools : [];

  const findings: InspectFinding[] = [];
  for (const rawTool of tools) {
    if (rawTool === null || typeof rawTool !== "object") continue;
    const tool = rawTool as {
      name?: unknown;
      description?: unknown;
      schema?: unknown;
      inputSchema?: unknown;
      annotations?: unknown;
    };
    const toolName = typeof tool.name === "string" ? tool.name : null;
    if (toolName === null) continue;

    const liveHash = hashToolDefinition({
      description: typeof tool.description === "string" ? tool.description : null,
      schema: tool.inputSchema ?? tool.schema,
      annotations: tool.annotations,
    });

    // SECURITY F13: lookup via Object.hasOwn to avoid prototype/constructor confusion.
    const serverPins = Object.hasOwn(pins.servers, serverName) ? pins.servers[serverName] : undefined;
    const pinned = serverPins && Object.hasOwn(serverPins, toolName) ? serverPins[toolName] : undefined;

    // SECURITY F3: same-session bypass check. If we've already seen a hash
    // for (server, tool) in this session, any subsequent tools/list for the
    // same pair must match — otherwise the server is trying to rug-pull
    // within a single session before the off-thread pin write commits.
    const sessionKey = `${serverName}::${toolName}`;
    const firstSeen = sessionFirstHashes.get(sessionKey);
    if (firstSeen !== undefined && firstSeen !== liveHash) {
      findings.push({
        signature_id: "schema-drift-in-session",
        category: "OWASP-MCP-1",
        severity: "critical",
        target: "tool_description",
        matched_text_excerpt: `${toolName}: ${firstSeen.slice(7, 19)}… → ${liveHash.slice(7, 19)}… (same session)`,
        remediation:
          `Server "${serverName}" delivered two different schemas for tool "${toolName}" ` +
          `in the same session. This is a rug-pull attempt; restart the IDE and reinspect ` +
          `the server's source.`,
      });
      continue;
    }
    if (firstSeen === undefined) sessionFirstHashes.set(sessionKey, liveHash);

    if (!pinned || pinned.current_hash === null) continue;

    if (liveHash !== pinned.current_hash) {
      findings.push({
        signature_id: "schema-drift",
        category: "OWASP-MCP-1",
        severity: "critical",
        target: "tool_description",
        matched_text_excerpt: `${toolName}: ${pinned.current_hash.slice(7, 19)}… → ${liveHash.slice(7, 19)}…`,
        remediation:
          `Tool "${toolName}" schema changed since install (rug-pull suspected). ` +
          `Run \`mcpm guard accept-drift ${serverName} --tool ${toolName} --new-hash ${liveHash}\` if legitimate.`,
      });
    }
  }
  return findings.length > 0
    ? { action: "block", findings }
    : { action: "pass", findings: [] };
}
