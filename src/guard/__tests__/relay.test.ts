/**
 * Tests for the production stdio MITM relay (Next Step 4).
 *
 * Covers both entry points (startRelay subprocess + startInProcessRelay)
 * for: line-delimited framing, partial reads, UTF-8 multibyte split,
 * large messages, concurrent IDs, notifications pass-through, EOF
 * mid-message buffering, and the new inspection + block behavior.
 *
 * Note: Content-Length framing intentionally not tested — MCP stdio is
 * line-delimited only (closed in OQ1 spike).
 */

import { describe, expect, test } from "vitest";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ChildProcess } from "node:child_process";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { buildSafeEnv, startInProcessRelay, startRelay, type GuardEvent } from "../relay.js";
import type { InspectResult } from "../types.js";

// ──────────────────────── helpers ────────────────────────

const makeRequest = (id: number, method: string, params: unknown = {}): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  method,
  params,
} as JSONRPCMessage);

const makeResponse = (id: number, content: string): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  result: { content: [{ type: "text", text: content }] },
} as JSONRPCMessage);

const makeNotification = (method: string, params: unknown = {}): JSONRPCMessage => ({
  jsonrpc: "2.0",
  method,
  params,
} as JSONRPCMessage);

interface Captured {
  parent: JSONRPCMessage[];
  output: JSONRPCMessage[];
  events: GuardEvent[];
}

function setupRelay(
  respond: (msg: JSONRPCMessage) => JSONRPCMessage | null,
  options: {
    inspectChildResponse?: (msg: JSONRPCMessage) => InspectResult;
    inspectParentRequest?: (msg: JSONRPCMessage) => InspectResult;
  } = {},
): { parentIn: PassThrough; parentOut: PassThrough; captured: Captured } {
  const parentIn = new PassThrough();
  const parentOut = new PassThrough();
  const captured: Captured = { parent: [], output: [], events: [] };

  const outBuffer = new ReadBuffer();
  parentOut.on("data", (chunk: Buffer) => {
    outBuffer.append(chunk);
    let msg = outBuffer.readMessage();
    while (msg !== null) {
      captured.output.push(msg);
      msg = outBuffer.readMessage();
    }
  });

  startInProcessRelay({
    parentIn,
    parentOut,
    respond: (m) => {
      captured.parent.push(m);
      return respond(m);
    },
    inspectChildResponse: options.inspectChildResponse,
    inspectParentRequest: options.inspectParentRequest,
    onEvent: (e) => captured.events.push(e),
  });

  return { parentIn, parentOut, captured };
}

// ─────────────────── framing conformance ───────────────────

describe("relay framing conformance", () => {
  test("line-delimited round-trip", async () => {
    const { parentIn, captured } = setupRelay((msg) =>
      "id" in msg ? makeResponse(msg.id as number, "ok") : null,
    );
    parentIn.write(serializeMessage(makeRequest(1, "tools/call")));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
    expect(captured.output).toHaveLength(1);
  });

  test("partial reads buffered until newline", async () => {
    const { parentIn, captured } = setupRelay((msg) =>
      "id" in msg ? makeResponse(msg.id as number, "ok") : null,
    );
    const wire = serializeMessage(makeRequest(2, "tools/call"));
    const buf = Buffer.from(wire, "utf8");
    parentIn.write(buf.subarray(0, 5));
    parentIn.write(buf.subarray(5, 15));
    parentIn.write(buf.subarray(15));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
  });

  test("UTF-8 multibyte split survives", async () => {
    const { parentIn, captured } = setupRelay((msg) =>
      "id" in msg ? makeResponse(msg.id as number, "ack") : null,
    );
    const payload = "hello 👋 world";
    const wire = serializeMessage(makeRequest(3, "tools/call", { msg: payload }));
    const buf = Buffer.from(wire, "utf8");
    const waveStart = buf.indexOf(0xf0);
    parentIn.write(buf.subarray(0, waveStart + 2));
    await new Promise((r) => setImmediate(r));
    parentIn.write(buf.subarray(waveStart + 2));
    await new Promise((r) => setImmediate(r));
    const got = captured.parent[0] as { params?: { msg?: string } };
    expect(got.params?.msg).toBe(payload);
  });

  test("100KB messages round-trip", async () => {
    const { parentIn, captured } = setupRelay((msg) =>
      "id" in msg ? makeResponse(msg.id as number, "x".repeat(100_000)) : null,
    );
    const big = "a".repeat(100_000);
    parentIn.write(serializeMessage(makeRequest(4, "tools/call", { blob: big })));
    await new Promise((r) => setImmediate(r));
    expect(captured.output).toHaveLength(1);
    const out = captured.output[0] as { result?: { content?: Array<{ text?: string }> } };
    expect(out.result?.content?.[0]?.text?.length).toBe(100_000);
  });

  test("50 interleaved concurrent IDs preserve order", async () => {
    const { parentIn, captured } = setupRelay((msg) =>
      "id" in msg ? makeResponse(msg.id as number, `r-${msg.id as number}`) : null,
    );
    let wire = "";
    for (let i = 0; i < 50; i++) wire += serializeMessage(makeRequest(100 + i, "tools/call"));
    parentIn.write(wire);
    await new Promise((r) => setImmediate(r));
    expect(captured.output).toHaveLength(50);
    for (let i = 0; i < 50; i++) {
      expect((captured.output[i] as { id?: number }).id).toBe(100 + i);
    }
  });

  test("notifications pass through without response", async () => {
    const { parentIn, captured } = setupRelay(() => null);
    parentIn.write(serializeMessage(makeNotification("notifications/cancelled", { requestId: 5 })));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
    expect(captured.output).toHaveLength(0);
  });

  test("EOF mid-message leaves incomplete frame buffered", async () => {
    const { parentIn, captured } = setupRelay((msg) =>
      "id" in msg ? makeResponse(msg.id as number, "ok") : null,
    );
    const wire = serializeMessage(makeRequest(6, "tools/call"));
    parentIn.write(wire.slice(0, -1));
    parentIn.end();
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(0);
  });
});

// ─────────────────── inspection + block behavior ───────────────────

describe("relay inspection + block behavior", () => {
  test("block on child response replaces it with JSON-RPC error", async () => {
    const { parentIn, captured } = setupRelay(
      (msg) => ("id" in msg ? makeResponse(msg.id as number, "evil payload") : null),
      {
        inspectChildResponse: (msg) => {
          if (!("result" in msg)) return { action: "pass", findings: [] };
          return {
            action: "block",
            findings: [
              {
                signature_id: "test-sig",
                category: "TEST",
                severity: "critical",
                target: "tool_response",
                matched_text_excerpt: "evil",
                remediation: "do something",
              },
            ],
          };
        },
      },
    );
    parentIn.write(serializeMessage(makeRequest(10, "tools/call")));
    await new Promise((r) => setImmediate(r));
    expect(captured.output).toHaveLength(1);
    const out = captured.output[0] as {
      error?: { code: number; message: string; data?: { signature_id: string } };
    };
    expect(out.error?.code).toBe(-32099);
    expect(out.error?.message).toBe("BLOCKED by mcpm-guard");
    expect(out.error?.data?.signature_id).toBe("test-sig");
  });

  test("pass on child response forwards unchanged", async () => {
    const { parentIn, captured } = setupRelay(
      (msg) => ("id" in msg ? makeResponse(msg.id as number, "benign") : null),
      {
        inspectChildResponse: () => ({ action: "pass", findings: [] }),
      },
    );
    parentIn.write(serializeMessage(makeRequest(11, "tools/call")));
    await new Promise((r) => setImmediate(r));
    const out = captured.output[0] as { result?: unknown; error?: unknown };
    expect(out.result).toBeDefined();
    expect(out.error).toBeUndefined();
  });

  test("warn action records event but forwards message", async () => {
    const { parentIn, captured } = setupRelay(
      (msg) => ("id" in msg ? makeResponse(msg.id as number, "warn-me") : null),
      {
        inspectChildResponse: () => ({
          action: "warn",
          findings: [
            {
              signature_id: "warn-sig",
              category: "TEST",
              severity: "high",
              target: "tool_response",
              matched_text_excerpt: "warn",
              remediation: "review",
            },
          ],
        }),
      },
    );
    parentIn.write(serializeMessage(makeRequest(12, "tools/call")));
    await new Promise((r) => setImmediate(r));
    const out = captured.output[0] as { result?: unknown };
    expect(out.result).toBeDefined();
    expect(captured.events).toHaveLength(1);
    expect(captured.events[0]?.action).toBe("warn");
  });

  test("block on parent request short-circuits — child never sees the message", async () => {
    let childSawMessage = false;
    const { parentIn, captured } = setupRelay(
      (msg) => {
        childSawMessage = true;
        return "id" in msg ? makeResponse(msg.id as number, "x") : null;
      },
      {
        inspectParentRequest: () => ({
          action: "block",
          findings: [
            {
              signature_id: "exfil-sig",
              category: "TEST",
              severity: "critical",
              target: "tool_call_args",
              matched_text_excerpt: ".ssh/id_rsa",
              remediation: "no",
            },
          ],
        }),
      },
    );
    parentIn.write(serializeMessage(makeRequest(13, "tools/call", { path: "~/.ssh/id_rsa" })));
    await new Promise((r) => setImmediate(r));
    expect(childSawMessage).toBe(false);
    const out = captured.output[0] as { error?: { code: number } };
    expect(out.error?.code).toBe(-32099);
  });

  test("buildSafeEnv allowlists PATH, HOME, USER, locale; strips secrets (security review F7)", () => {
    const source = {
      PATH: "/usr/bin",
      HOME: "/home/u",
      USER: "u",
      LANG: "en_US.UTF-8",
      LC_ALL: "en_US.UTF-8",
      LC_CTYPE: "en_US.UTF-8",
      TMPDIR: "/tmp",
      // These MUST NOT leak to the spawned child
      OPENAI_API_KEY: "sk-secret-xxx",
      AWS_ACCESS_KEY_ID: "AKIA...",
      AWS_SECRET_ACCESS_KEY: "secret",
      GITHUB_TOKEN: "ghp_...",
      ANTHROPIC_API_KEY: "sk-ant-...",
    };
    const safe = buildSafeEnv(source);
    expect(safe.PATH).toBe("/usr/bin");
    expect(safe.HOME).toBe("/home/u");
    expect(safe.USER).toBe("u");
    expect(safe.LANG).toBe("en_US.UTF-8");
    expect(safe.LC_ALL).toBe("en_US.UTF-8");
    expect(safe.LC_CTYPE).toBe("en_US.UTF-8");
    expect(safe.TMPDIR).toBe("/tmp");
    expect(safe.OPENAI_API_KEY).toBeUndefined();
    expect(safe.AWS_ACCESS_KEY_ID).toBeUndefined();
    expect(safe.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(safe.GITHUB_TOKEN).toBeUndefined();
    expect(safe.ANTHROPIC_API_KEY).toBeUndefined();
  });

  test("buildSafeEnv strips code-injection env vars but forwards SHELL (allowlist)", () => {
    const source = {
      SHELL: "/bin/zsh",
      // Code-injection vectors: a wrapped (semi-trusted) server must NOT inherit
      // these — they let an attacker preload native code or rewrite npm config.
      NODE_OPTIONS: "--require /tmp/evil.js",
      LD_PRELOAD: "/tmp/evil.so",
      DYLD_INSERT_LIBRARIES: "/tmp/evil.dylib",
      NPM_CONFIG_USERCONFIG: "/tmp/evil-npmrc",
    };
    const safe = buildSafeEnv(source);
    // SHELL is on the allowlist — forwarded.
    expect(safe.SHELL).toBe("/bin/zsh");
    // Injection vectors are not on the allowlist — stripped.
    expect(safe.NODE_OPTIONS).toBeUndefined();
    expect(safe.LD_PRELOAD).toBeUndefined();
    expect(safe.DYLD_INSERT_LIBRARIES).toBeUndefined();
    expect(safe.NPM_CONFIG_USERCONFIG).toBeUndefined();
  });

  test("block on notification has no error response (no id to reply to)", async () => {
    const { parentIn, captured } = setupRelay(() => null, {
      inspectParentRequest: () => ({
        action: "block",
        findings: [
          {
            signature_id: "x",
            category: "Y",
            severity: "critical",
            target: "tool_response",
            matched_text_excerpt: "",
            remediation: "",
          },
        ],
      }),
    });
    parentIn.write(serializeMessage(makeNotification("notifications/cancelled")));
    await new Promise((r) => setImmediate(r));
    expect(captured.output).toHaveLength(0);
    expect(captured.events).toHaveLength(1);
  });
});

// ─────────────── H7: block-to-origin invariant (server-initiated request) ───────────────

/**
 * H7: a server-INITIATED request (sampling/createMessage, elicitation/create)
 * that inspection blocks with replyToOrigin:true must error BACK to the SERVER
 * (the request's origin), and the CLIENT must receive NOTHING for that id —
 * not the error and not the forwarded request.
 *
 * The two-part invariant under test:
 *   (a) the error lands on the origin/server sink (toServer) with the request id;
 *   (b) the client sink (parentOut) receives NOTHING for that id.
 */
describe("relay block-to-origin invariant (H7 server-initiated request)", () => {
  const injectionFinding = (sigId: string): InspectResult["findings"][number] => ({
    signature_id: sigId,
    category: "OWASP-MCP-2",
    severity: "critical",
    target: "prompt_content",
    matched_text_excerpt: "ignore previous instructions",
    remediation: "block it",
  });

  function setupServerInitiated(
    inspectChildResponse: (msg: JSONRPCMessage) => InspectResult,
  ): {
    handle: ReturnType<typeof startInProcessRelay>;
    clientOut: JSONRPCMessage[];
    serverOut: JSONRPCMessage[];
  } {
    const parentIn = new PassThrough();
    const parentOut = new PassThrough();
    const clientOut: JSONRPCMessage[] = [];
    const serverOut: JSONRPCMessage[] = [];

    const outBuffer = new ReadBuffer();
    parentOut.on("data", (chunk: Buffer) => {
      outBuffer.append(chunk);
      let msg = outBuffer.readMessage();
      while (msg !== null) {
        clientOut.push(msg);
        msg = outBuffer.readMessage();
      }
    });

    const serverBuffer = new ReadBuffer();
    const handle = startInProcessRelay({
      parentIn,
      parentOut,
      respond: () => null,
      inspectChildResponse,
      toServer: (bytes) => {
        serverBuffer.append(Buffer.from(bytes, "utf8"));
        let msg = serverBuffer.readMessage();
        while (msg !== null) {
          serverOut.push(msg);
          msg = serverBuffer.readMessage();
        }
      },
    });
    return { handle, clientOut, serverOut };
  }

  test("replyToOrigin block: error to SERVER with the id; CLIENT gets nothing", async () => {
    const { handle, clientOut, serverOut } = setupServerInitiated((msg) => {
      if (!("method" in msg)) return { action: "pass", findings: [] };
      return { action: "block", findings: [injectionFinding("inj")], replyToOrigin: true };
    });
    handle.pushServerRequest(makeRequest(42, "sampling/createMessage"));
    await new Promise((r) => setImmediate(r));

    // (a) the server sink received the JSON-RPC error with the request id.
    expect(serverOut).toHaveLength(1);
    const err = serverOut[0] as { id?: number; error?: { code: number } };
    expect(err.id).toBe(42);
    expect(err.error?.code).toBe(-32099);
    // (b) the client sink received NOTHING — no error AND no forwarded request.
    expect(clientOut).toHaveLength(0);
  });

  test("non-replyToOrigin block keeps existing client-directed behavior (regression)", async () => {
    const { handle, clientOut, serverOut } = setupServerInitiated(() => ({
      action: "block",
      findings: [injectionFinding("inj")],
      // replyToOrigin undefined → error goes to the client (parentOut), as before.
    }));
    handle.pushServerRequest(makeRequest(43, "sampling/createMessage"));
    await new Promise((r) => setImmediate(r));

    // Error routed to the client sink (legacy behavior), server sink untouched.
    expect(clientOut).toHaveLength(1);
    expect((clientOut[0] as { error?: { code: number } }).error?.code).toBe(-32099);
    expect(serverOut).toHaveLength(0);
  });

  test("pass: the server-initiated request is forwarded to the CLIENT untouched", async () => {
    const { handle, clientOut, serverOut } = setupServerInitiated(() => ({
      action: "pass",
      findings: [],
    }));
    handle.pushServerRequest(makeRequest(44, "sampling/createMessage", { hello: "world" }));
    await new Promise((r) => setImmediate(r));

    expect(clientOut).toHaveLength(1);
    const fwd = clientOut[0] as { id?: number; method?: string };
    expect(fwd.id).toBe(44);
    expect(fwd.method).toBe("sampling/createMessage");
    expect(serverOut).toHaveLength(0);
  });
});

// ─────────────── H9 (B.2): child-spawn failure fails closed ───────────────

/**
 * A fake ChildProcess that lets the test drive a `'error'` event (the async
 * signal Node emits when spawn fails — e.g. ENOENT command-not-found) without
 * forking a real subprocess. Only the surface startRelay touches is modelled.
 */
function makeFakeChild(): ChildProcess & { emitError: (err: Error) => void } {
  const emitter = new EventEmitter() as EventEmitter & {
    stdin: PassThrough;
    stdout: PassThrough;
    killed: boolean;
    kill: () => boolean;
    emitError: (err: Error) => void;
  };
  emitter.stdin = new PassThrough();
  emitter.stdout = new PassThrough();
  emitter.killed = false;
  emitter.kill = () => true;
  emitter.emitError = (err: Error) => emitter.emit("error", err);
  return emitter as unknown as ChildProcess & { emitError: (err: Error) => void };
}

describe("startRelay — child-spawn failure fails closed (H9 B.2)", () => {
  test("a child 'error' event resolves exit nonzero, forwards no bytes, emits a block event", async () => {
    const fakeChild = makeFakeChild();
    const parentIn = new PassThrough();
    const parentOut = new PassThrough();

    let parentOutBytes = 0;
    parentOut.on("data", (c: Buffer) => {
      parentOutBytes += c.byteLength;
    });

    const events: GuardEvent[] = [];
    const handle = startRelay({
      command: "definitely-not-a-real-binary-xyz",
      args: [],
      parentIn,
      parentOut,
      onEvent: (e) => events.push(e),
      // Test seam: inject the fake child instead of a real spawn.
      spawnChild: () => fakeChild,
    });

    // Simulate the OS failing to spawn the binary (async 'error' on the child).
    fakeChild.emitError(
      Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" }),
    );

    const code = await handle.exit;
    expect(code).not.toBe(0); // fail closed — nonzero exit
    expect(parentOutBytes).toBe(0); // no half-open channel: nothing forwarded
    // A block event is logged so the failure is visible in the event log.
    expect(events.some((e) => e.action === "block")).toBe(true);
  });

  test("the block event carries the spawn-failure cause (code + message), not an empty finding", async () => {
    const fakeChild = makeFakeChild();
    const events: GuardEvent[] = [];
    const handle = startRelay({
      command: "definitely-not-a-real-binary-xyz",
      args: [],
      parentIn: new PassThrough(),
      parentOut: new PassThrough(),
      onEvent: (e) => events.push(e),
      spawnChild: () => fakeChild,
    });

    fakeChild.emitError(Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" }));
    await handle.exit;

    const blockEvent = events.find((e) => e.action === "block");
    const finding = blockEvent?.findings[0];
    expect(finding?.signature_id).toBe("spawn-failure");
    // The cause is attributable: ENOENT code + the error message are recorded.
    expect(finding?.matched_text_excerpt).toContain("ENOENT");
    expect(finding?.matched_text_excerpt).toContain("spawn ENOENT");
  });

  test("a malformed / non-JSON-RPC line on child stdout does NOT crash the guard (Finding #5)", async () => {
    const fakeChild = makeFakeChild();
    const parentIn = new PassThrough();
    const parentOut = new PassThrough();

    let parentOutBytes = 0;
    parentOut.on("data", (c: Buffer) => {
      parentOutBytes += c.byteLength;
    });

    const events: GuardEvent[] = [];
    startRelay({
      command: "x",
      args: [],
      parentIn,
      parentOut,
      onEvent: (e) => events.push(e),
      spawnChild: () => fakeChild,
    });

    // A wrapped server's startup banner: valid text, NOT a JSON-RPC frame. On
    // the old code this makes the SDK parse throw inside the stream 'data'
    // handler and propagates as an uncaughtException (the crash-loop). The fix
    // must contain it: no throw, a RELAY/block event, nothing forwarded.
    expect(() => fakeChild.stdout.write("Starting v1.0\n")).not.toThrow();
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const block = events.find((e) => e.action === "block");
    expect(block).toBeDefined();
    expect(block?.direction).toBe("child->parent");
    expect(block?.findings[0]?.signature_id).toBe("malformed-frame");
    expect(block?.findings[0]?.category).toBe("RELAY");
    // Fail closed: the malformed line was NOT forwarded to the client.
    expect(parentOutBytes).toBe(0);
    // Source torn down so no further uninspected bytes can flow.
    expect(fakeChild.stdout.destroyed).toBe(true);
  });

  test("after spawn-failure the child stdout is destroyed — no late bytes reach parentOut", async () => {
    const fakeChild = makeFakeChild();
    const parentOut = new PassThrough();
    let parentOutBytes = 0;
    parentOut.on("data", (c: Buffer) => {
      parentOutBytes += c.byteLength;
    });

    const handle = startRelay({
      command: "x",
      args: [],
      parentIn: new PassThrough(),
      parentOut,
      onEvent: () => undefined,
      spawnChild: () => fakeChild,
    });

    fakeChild.emitError(Object.assign(new Error("spawn EACCES"), { code: "EACCES" }));
    await handle.exit;

    // The source stream must be destroyed so a late emit can't forward bytes.
    expect(fakeChild.stdout.destroyed).toBe(true);
    // Attempting to push after destroy must not reach parentOut.
    expect(fakeChild.stdout.write("late uninspected bytes\n")).toBe(false);
    await new Promise((r) => setImmediate(r));
    expect(parentOutBytes).toBe(0);
  });
});
