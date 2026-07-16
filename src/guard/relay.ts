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
  /**
   * Test seam (H9 B.2): factory that produces the child process. Defaults to a
   * real `spawn`. Injected by the relay unit test to drive the `'error'` path
   * (spawn failure) without forking a real subprocess. Production never sets it.
   */
  readonly spawnChild?: (command: string, args: readonly string[], env: NodeJS.ProcessEnv) => ChildProcess;
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

export function startRelay(opts: RelayOptions): RelayHandle {
  const env = opts.env ?? buildSafeEnv();
  const child = opts.spawnChild
    ? opts.spawnChild(opts.command, opts.args, env)
    : spawn(opts.command, [...opts.args], {
        env,
        stdio: ["pipe", "pipe", "inherit"], // stderr passthrough — preserves IDE diagnostics
      });

  // Signal forwarding handlers are removed both on a clean exit and on a
  // spawn-failure ('error'); hoist them so both settle paths can detach.
  const forwardSignal = (sig: NodeJS.Signals): void => {
    if (!child.killed) child.kill(sig);
  };

  // H9 (B.2): fail CLOSED on a child-spawn failure. `spawn` succeeds
  // synchronously even when the binary is missing — Node then emits an async
  // `'error'` event on the child (ENOENT/EACCES/…). Without a handler this
  // either crashes the guard process (unhandled exception) or hangs forever
  // (the `'exit'` promise never resolves), and the IDE is left with a half-open
  // channel or a dead session. Instead: detach signal handlers, log a `block`
  // event so the failure is visible in ~/.mcpm/guard-events.jsonl, forward NO
  // bytes (none were exchanged), and resolve `exit` nonzero so the guard
  // process exits cleanly. A dead server cannot serve UNGUARDED.
  let settled = false;
  let resolveExit!: (code: number) => void;
  const exit = new Promise<number>((resolve) => {
    resolveExit = resolve;
  });
  child.on("error", (err: NodeJS.ErrnoException) => {
    if (settled) return;
    settled = true;
    process.off("SIGTERM", forwardSignal);
    process.off("SIGINT", forwardSignal);
    // Forensics: record WHY the channel closed (ENOENT/EACCES + message), so an
    // operator triaging guard-events.jsonl can tell a missing-binary spawn
    // failure apart from a content-level block. The finding carries the cause in
    // a valid InspectFinding shape (no type change to GuardEvent).
    const code = err.code ?? "SPAWN-FAILED";
    opts.onEvent?.({
      ts: new Date().toISOString(),
      direction: "child->parent",
      action: "block",
      findings: [
        {
          signature_id: "spawn-failure",
          category: "RELAY",
          severity: "critical",
          target: "tool_response",
          matched_text_excerpt: `${code}: ${err.message}`,
          remediation:
            "The wrapped MCP server binary failed to start. Verify the command exists and is executable.",
        },
      ],
    });
    // Attributable stderr line so the closed channel reads as guard-intercepted
    // rather than an opaque crash (mirrors the PINS-READ-ERROR pattern).
    process.stderr.write(`[mcpm-guard] SPAWN-FAILED ${opts.command}: ${code}\n`);
    // Defensive: detach/destroy the child streams so no late data listener (e.g.
    // a wrapper that prints then dies, or a late-resolving symlink) can forward
    // uninspected bytes to parentOut after settlement. Matches the buffer-cap
    // path's source.destroy() discipline.
    child.stdout?.destroy();
    child.stdin?.destroy();
    resolveExit(1);
  });

  /* c8 ignore start — subprocess production path: behavior verified via E2E
   * smoke (mcpm guard run --inner with real spawned echo-bot), not unit-testable
   * without forking child processes in CI. The shared logic (frame parsing,
   * inspection, block synthesis) is covered via startInProcessRelay; the
   * spawn-failure 'error' path above is covered via an injected fake child. */
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

  // Shared child-stdin writer: child.stdin can be destroyed after child exit;
  // .write returns false when not writable but does not throw thanks to the
  // error handler above. Reused by the parent->child `target` and the
  // child->parent `replyToSource` (H7 block-to-origin → write back to server).
  const writeToChild = (bytes: string): void => {
    if (child.stdin && !child.stdin.destroyed) child.stdin.write(bytes);
  };

  wireDirection({
    source: opts.parentIn,
    target: writeToChild,
    targetEnd: () => child.stdin?.end(),
    parentOut: opts.parentOut,
    inspect: opts.inspectParentRequest,
    direction: "parent->child",
    onEvent: opts.onEvent,
    // Symmetry only — a parent-INITIATED block replies to the client (parentOut),
    // so this is unused for this direction (no replyToOrigin on parent requests).
    replyToSource: (bytes) => opts.parentOut.write(bytes),
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
      // H7: a blocked server-INITIATED request (sampling/elicitation) errors
      // back to the SERVER (child.stdin), not the client.
      replyToSource: writeToChild,
    });
  }

  // Signal forwarding — IDE-originated SIGTERM / SIGINT propagates to child.
  // Use named handlers + explicit removal on exit so repeated startRelay calls
  // don't accumulate listeners (would emit MaxListenersExceededWarning at 11+).
  process.on("SIGTERM", forwardSignal);
  process.on("SIGINT", forwardSignal);

  child.on("exit", (code) => {
    if (settled) return;
    settled = true;
    process.off("SIGTERM", forwardSignal);
    process.off("SIGINT", forwardSignal);
    resolveExit(code ?? 0);
  });
  /* c8 ignore stop */

  return { child, exit };
}

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
  /**
   * H7: server-stdin analogue. When a server-INITIATED request (pushed via
   * {@link InProcessRelayHandle.pushServerRequest}) is blocked with
   * `replyToOrigin: true`, the synthetic JSON-RPC error is written HERE — back
   * to the origin server — not to `parentOut` (the client). The server-side
   * production wiring binds this to `child.stdin`. Undefined keeps the legacy
   * client-directed routing.
   */
  readonly toServer?: (bytes: string) => void;
}

/**
 * Handle returned by {@link startInProcessRelay}. `pushServerRequest` models an
 * UNSOLICITED server→client request (sampling/createMessage, elicitation/create)
 * flowing through the child→parent inspection path — the seam the H7 relay
 * block-to-origin invariant needs but the parent→child `respond` round-trip
 * cannot express.
 */
export interface InProcessRelayHandle {
  /**
   * Inject a server-initiated request. A pass/warn forwards it to `parentOut`
   * (the client); a `replyToOrigin: true` block routes the synthetic error to
   * `toServer` (the origin) and forwards NOTHING to the client.
   */
  readonly pushServerRequest: (msg: JSONRPCMessage) => void;
}

export function startInProcessRelay(opts: InProcessRelayOptions): InProcessRelayHandle {
  // Returns true if the message was BLOCKED (so the round-trip must not continue).
  // H7: when the decision carries `replyToOrigin`, the synthetic error is routed
  // to `opts.toServer` (the origin server) instead of `parentOut` (the client) —
  // and the original request is NOT forwarded (the caller returns on `true`).
  const inspectAndWrite = (
    msg: JSONRPCMessage,
    direction: GuardEvent["direction"],
    inspect: InspectFn | undefined,
  ): boolean => {
    const decision = inspect?.(msg);
    logEvent(decision, direction, opts.onEvent);
    if (decision?.action === "block") {
      const errResp = makeBlockResponse(msg, decision);
      if (errResp !== null) {
        const sink =
          decision.replyToOrigin === true && opts.toServer !== undefined
            ? opts.toServer
            : (bytes: string) => opts.parentOut.write(bytes);
        sink(serializeMessage(errResp));
      }
      return true; // blocked — don't continue the round-trip
    }
    return false;
  };

  const buffer = new ReadBuffer();
  opts.parentIn.on("data", (chunk: Buffer) => {
    buffer.append(chunk);
    let parentMsg: JSONRPCMessage | null;
    try {
      parentMsg = buffer.readMessage();
    } catch {
      // Malformed / non-JSON-RPC frame — same fail-closed posture as
      // wireDirection: emit a RELAY block event, tear the source down, forward
      // nothing, rather than crashing the guard with an uncaughtException.
      opts.onEvent?.(malformedFrameEvent("parent->child"));
      opts.parentIn.destroy();
      return;
    }
    while (parentMsg !== null) {
      const blocked = inspectAndWrite(parentMsg, "parent->child", opts.inspectParentRequest);
      if (!blocked) {
        const response = opts.respond(parentMsg);
        if (response !== null) {
          const respBlocked = inspectAndWrite(response, "child->parent", opts.inspectChildResponse);
          if (!respBlocked) opts.parentOut.write(serializeMessage(response));
        }
      }
      try {
        parentMsg = buffer.readMessage();
      } catch {
        opts.onEvent?.(malformedFrameEvent("parent->child"));
        opts.parentIn.destroy();
        return;
      }
    }
  });

  return {
    pushServerRequest: (msg: JSONRPCMessage) => {
      const blocked = inspectAndWrite(msg, "child->parent", opts.inspectChildResponse);
      // INVARIANT: a replyToOrigin block already wrote the error to toServer and
      // returns `true` here, so the forward below is skipped — the client sees
      // nothing for this id. A pass/warn forwards the request to the client.
      if (!blocked) opts.parentOut.write(serializeMessage(msg));
    },
  };
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
  /**
   * H7: sink for a block-to-origin error reply. When a blocked decision carries
   * `replyToOrigin: true` (a server-INITIATED sampling/elicitation request), the
   * synthetic error is written HERE — back to the request's ORIGIN (the source's
   * own counterpart sink) — instead of `parentOut` (the client). For the
   * child->parent wiring this is `child.stdin`; for parent->child it is
   * `parentOut` (symmetry; unused for parent-initiated blocks).
   */
  readonly replyToSource: (bytes: string) => void;
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
      // No-arg destroy() — NOT destroy(new Error(...)): the source (child.stdout)
      // has no 'error' listener, so destroy(err) re-emits as an uncaughtException
      // and crash-loops the relay. Same fail-closed teardown as the malformed
      // branch below; the block event above already records the DoS signal.
      w.source.destroy();
      return;
    }
    buffer.append(chunk);
    let msg: JSONRPCMessage | null;
    try {
      msg = buffer.readMessage();
    } catch {
      // A malformed / non-JSON-RPC line (startup banner, garbage, valid-JSON
      // that isn't a JSON-RPC frame) makes the SDK parse throw. Mirror the
      // buffer-cap branch: emit a RELAY block event and tear the source down —
      // NO bytes forwarded (the throw is before any target write) — instead of
      // letting it propagate as an uncaughtException and crash the guard.
      w.onEvent?.(malformedFrameEvent(w.direction));
      w.source.destroy();
      return;
    }
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
        if (errResp !== null) {
          // H7 two-part invariant: on a replyToOrigin block we (a) write the
          // error to the request's ORIGIN via replyToSource — NOT parentOut —
          // and (b) DO NOT forward the request (the forward lives ONLY in the
          // else branch below). So the client sink receives nothing for this id:
          // no error AND no forwarded request. Otherwise keep the legacy routing
          // (error → client / parentOut).
          if (decision.replyToOrigin === true) w.replyToSource(serializeMessage(errResp));
          else w.parentOut.write(serializeMessage(errResp));
        }
      } else {
        logEvent(decision, w.direction, w.onEvent);
        w.target(serializeMessage(msg));
      }
      try {
        msg = buffer.readMessage();
      } catch {
        w.onEvent?.(malformedFrameEvent(w.direction));
        w.source.destroy();
        return;
      }
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

/**
 * Build the RELAY block event for a malformed / non-JSON-RPC frame. A single
 * bad line on the wrapped server's stdout (a startup banner, garbage, or
 * valid-JSON-that-isn't-JSONRPC) makes the SDK's parse throw; without this the
 * throw becomes an uncaughtException and the relay crash-loops. Mirrors the
 * spawn-failure finding shape so an operator triaging guard-events.jsonl can
 * tell a malformed frame apart from a content-level block.
 */
function malformedFrameEvent(direction: GuardEvent["direction"]): GuardEvent {
  return {
    ts: new Date().toISOString(),
    direction,
    action: "block",
    findings: [
      {
        signature_id: "malformed-frame",
        category: "RELAY",
        severity: "critical",
        target: "tool_response",
        matched_text_excerpt: "malformed JSON-RPC frame on stdio",
        remediation:
          "The wrapped MCP server emitted a non-JSON-RPC line (e.g. a startup banner). It must write only JSON-RPC frames to stdout.",
      },
    ],
  };
}

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
