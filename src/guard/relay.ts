/**
 * Production stdio MITM relay for mcpm-guard (v0.5.0).
 *
 * Two entry points share the same inspection pipeline:
 *   - startRelay(opts)          — wraps a real subprocess (production)
 *   - startInProcessRelay(opts) — wires a synthetic responder (unit tests, demo)
 *
 * Both parse incoming JSON-RPC frames via the SDK's ReadBuffer, run the
 * supplied `inspect` callback, and either forward the message or replace it
 * with a synthetic JSON-RPC error response when inspection returns "block".
 *
 * Perf budget closed in the OQ1 spike (`mingshum-feat-v0.5.0-mcpm-guard-spike-report-...md`):
 * p99 0.065ms small / 3.1ms large with parse+reserialize. Adopt SDK helpers
 * as the substrate — no manual framing required.
 */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectResult } from "./types.js";

export type InspectFn = (msg: JSONRPCMessage) => InspectResult;

// ---------------------------------------------------------------------------
// Block response synthesis
// ---------------------------------------------------------------------------

/**
 * JSON-RPC error code reserved for mcpm-guard. Avoids collision with the
 * MCP / JSON-RPC standard codes (-32000 to -32099 are implementation-defined).
 */
const GUARD_BLOCK_ERROR_CODE = -32099;

/**
 * Synthesize a JSON-RPC error response that replaces a blocked tool response.
 * Preserves the original message id so the MCP client can correlate.
 * Returns null if the blocked message had no id (notifications can't be replied to).
 *
 * SECURITY: `matched_text_excerpt` is attacker-controlled (up to 200 chars of
 * payload that tripped the signature). It flows ONLY to the MCP client — which
 * is in our trust boundary (it's the user's IDE) — not back to the malicious
 * server. If a future architecture surfaces this excerpt outside the IDE
 * (e.g., via a public dashboard), redact it then.
 */
function makeBlockResponse(blocked: JSONRPCMessage, result: InspectResult): JSONRPCMessage | null {
  if (!("id" in blocked) || blocked.id === undefined) return null;
  const finding = result.findings[0];
  return {
    jsonrpc: "2.0",
    id: blocked.id,
    error: {
      code: GUARD_BLOCK_ERROR_CODE,
      message: "BLOCKED by mcpm-guard",
      data: finding
        ? {
            signature_id: finding.signature_id,
            category: finding.category,
            severity: finding.severity,
            matched_text_excerpt: finding.matched_text_excerpt,
            remediation: finding.remediation,
          }
        : undefined,
    },
  } as JSONRPCMessage;
}

/**
 * Minimal env passthrough for spawned MCP server children. Avoids leaking
 * unrelated parent secrets (OPENAI_API_KEY, AWS_*, GITHUB_TOKEN, etc.) to a
 * server we are wrapping precisely because we don't fully trust it. Callers
 * that need to forward a specific secret can pass it explicitly via opts.env.
 */
const SAFE_ENV_PASSTHROUGH = new Set([
  "PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "USER", "SHELL",
]);

export function buildSafeEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(source)) {
    if (SAFE_ENV_PASSTHROUGH.has(k) || k.startsWith("LC_")) out[k] = v;
  }
  return out;
}

/**
 * Cap per-direction buffer growth. A malicious child that withholds the
 * newline delimiter can otherwise grow the buffer unboundedly, exhausting
 * relay memory. 64MB is far above any legitimate MCP response and gives
 * a clean DoS signal when crossed.
 */
const MAX_BUFFER_BYTES = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Subprocess relay (production)
// ---------------------------------------------------------------------------

export interface RelayOptions {
  readonly command: string;
  readonly args: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly parentIn: Readable;
  readonly parentOut: Writable;
  /** Inspects every message flowing from child → parent. */
  readonly inspectChildResponse?: InspectFn;
  /** Inspects every message flowing from parent → child. */
  readonly inspectParentRequest?: InspectFn;
  /** Optional sink for inspection events (block / warn). Defaults to noop. */
  readonly onEvent?: (event: GuardEvent) => void;
}

export interface RelayHandle {
  readonly child: ChildProcess;
  readonly exit: Promise<number>;
}

export interface GuardEvent {
  readonly ts: string;
  readonly direction: "parent->child" | "child->parent";
  readonly action: InspectResult["action"];
  readonly findings: InspectResult["findings"];
}

/* c8 ignore start — subprocess production path: behavior verified via E2E
 * smoke (mcpm guard run --inner with real spawned echo-bot), not unit-testable
 * without forking child processes in CI. The shared logic (frame parsing,
 * inspection, block synthesis) is covered via startInProcessRelay. */
export function startRelay(opts: RelayOptions): RelayHandle {
  const child = spawn(opts.command, [...opts.args], {
    env: opts.env ?? buildSafeEnv(),
    stdio: ["pipe", "pipe", "inherit"], // stderr passthrough — preserves IDE diagnostics
  });

  // Swallow write-after-close errors when the child has already exited.
  // Without this listener, Node throws an uncaught exception on the relay
  // process, which a malicious child can exploit by crashing intentionally.
  child.stdin?.on("error", (err) => {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "EPIPE" && code !== "ERR_STREAM_DESTROYED") {
      // Anything else is unexpected — surface via event log if available.
      opts.onEvent?.({
        ts: new Date().toISOString(),
        direction: "parent->child",
        action: "warn",
        findings: [],
      });
    }
  });

  wireDirection({
    source: opts.parentIn,
    target: (bytes) => {
      // child.stdin can be destroyed after child exit; .write returns false
      // when not writable but does not throw thanks to the error handler above.
      if (child.stdin && !child.stdin.destroyed) child.stdin.write(bytes);
    },
    targetEnd: () => child.stdin?.end(),
    parentOut: opts.parentOut,
    inspect: opts.inspectParentRequest,
    direction: "parent->child",
    onEvent: opts.onEvent,
  });

  if (child.stdout) {
    wireDirection({
      source: child.stdout,
      target: (bytes) => opts.parentOut.write(bytes),
      targetEnd: () => undefined, // never end parentOut on child exit
      parentOut: opts.parentOut,
      inspect: opts.inspectChildResponse,
      direction: "child->parent",
      onEvent: opts.onEvent,
    });
  }

  // Signal forwarding — IDE-originated SIGTERM / SIGINT propagates to child.
  // Use named handlers + explicit removal on exit so repeated startRelay calls
  // don't accumulate listeners (would emit MaxListenersExceededWarning at 11+).
  const forwardSignal = (sig: NodeJS.Signals): void => {
    if (!child.killed) child.kill(sig);
  };
  process.on("SIGTERM", forwardSignal);
  process.on("SIGINT", forwardSignal);

  const exit = new Promise<number>((resolve) => {
    child.on("exit", (code) => {
      process.off("SIGTERM", forwardSignal);
      process.off("SIGINT", forwardSignal);
      resolve(code ?? 0);
    });
  });

  return { child, exit };
}
/* c8 ignore stop */

// ---------------------------------------------------------------------------
// In-process relay (unit tests + demo)
// ---------------------------------------------------------------------------

export interface InProcessRelayOptions {
  readonly parentIn: Readable;
  readonly parentOut: Writable;
  /** Synthetic responder — receives parent's message, returns child's response (or null for notifications). */
  readonly respond: (msg: JSONRPCMessage) => JSONRPCMessage | null;
  readonly inspectChildResponse?: InspectFn;
  readonly inspectParentRequest?: InspectFn;
  readonly onEvent?: (event: GuardEvent) => void;
}

export function startInProcessRelay(opts: InProcessRelayOptions): void {
  const inspectAndWrite = (
    msg: JSONRPCMessage,
    direction: GuardEvent["direction"],
    inspect: InspectFn | undefined,
  ): boolean => {
    const decision = inspect?.(msg);
    logEvent(decision, direction, opts.onEvent);
    if (decision?.action === "block") {
      const errResp = makeBlockResponse(msg, decision);
      if (errResp !== null) opts.parentOut.write(serializeMessage(errResp));
      return true; // blocked — don't continue the round-trip
    }
    return false;
  };

  const buffer = new ReadBuffer();
  opts.parentIn.on("data", (chunk: Buffer) => {
    buffer.append(chunk);
    let parentMsg = buffer.readMessage();
    while (parentMsg !== null) {
      const blocked = inspectAndWrite(parentMsg, "parent->child", opts.inspectParentRequest);
      if (!blocked) {
        const response = opts.respond(parentMsg);
        if (response !== null) {
          const respBlocked = inspectAndWrite(response, "child->parent", opts.inspectChildResponse);
          if (!respBlocked) opts.parentOut.write(serializeMessage(response));
        }
      }
      parentMsg = buffer.readMessage();
    }
  });
}

// ---------------------------------------------------------------------------
// Shared wiring (subprocess-side: byte-level pass-through with inspection)
// ---------------------------------------------------------------------------

/* c8 ignore start — only called by startRelay (subprocess path); the
 * inspection + block logic is mirrored in startInProcessRelay which IS unit-tested. */
interface DirectionWiring {
  readonly source: Readable;
  readonly target: (bytes: string) => void;
  readonly targetEnd: () => void;
  readonly parentOut: Writable;
  readonly inspect: InspectFn | undefined;
  readonly direction: GuardEvent["direction"];
  readonly onEvent: ((event: GuardEvent) => void) | undefined;
}

function wireDirection(w: DirectionWiring): void {
  const buffer = new ReadBuffer();
  let bufferedBytes = 0;
  w.source.on("data", (chunk: Buffer) => {
    bufferedBytes += chunk.byteLength;
    if (bufferedBytes > MAX_BUFFER_BYTES) {
      // Malicious child can withhold newline indefinitely to exhaust relay RAM.
      // 64MB is far above any legitimate MCP frame; crossing it is a DoS signal.
      w.onEvent?.({
        ts: new Date().toISOString(),
        direction: w.direction,
        action: "block",
        findings: [],
      });
      w.source.destroy(new Error("mcpm-guard: buffer cap exceeded — possible DoS"));
      return;
    }
    buffer.append(chunk);
    let msg = buffer.readMessage();
    while (msg !== null) {
      bufferedBytes = 0; // reset on every consumed frame
      const decision = w.inspect?.(msg);
      if (decision?.action === "block") {
        logEvent(decision, w.direction, w.onEvent);
        // Drop the message; synthesize an error response back to the parent
        // when the original carries an id. Parent->child blocks may leave the
        // IDE waiting on a request — synthesized error responses cover the
        // common (id-bearing) case; notifications have no reply channel.
        const errResp = makeBlockResponse(msg, decision);
        if (errResp !== null) w.parentOut.write(serializeMessage(errResp));
      } else {
        logEvent(decision, w.direction, w.onEvent);
        w.target(serializeMessage(msg));
      }
      msg = buffer.readMessage();
    }
  });
  w.source.on("end", () => {
    w.targetEnd();
  });
}
/* c8 ignore stop */

// ---------------------------------------------------------------------------
// Event helper
// ---------------------------------------------------------------------------

function logEvent(
  result: InspectResult | undefined,
  direction: GuardEvent["direction"],
  onEvent: ((event: GuardEvent) => void) | undefined,
): void {
  if (!result || result.findings.length === 0) return;
  onEvent?.({
    ts: new Date().toISOString(),
    direction,
    action: result.action,
    findings: result.findings,
  });
}
