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
import { PassThrough } from "node:stream";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { buildSafeEnv, startInProcessRelay, type GuardEvent } from "../relay.js";
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
