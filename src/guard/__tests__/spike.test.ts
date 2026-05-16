/**
 * Spike conformance harness + bench for the v0.5.0 MITM substrate decision (OQ1).
 *
 * Tests:
 *  - line-delimited JSON-RPC framing round-trips correctly (the only framing MCP uses)
 *  - partial reads at arbitrary byte boundaries are buffered until newline
 *  - UTF-8 multibyte chars split across reads survive
 *  - large messages (≥ 64KB, Node's default highWaterMark) round-trip
 *  - concurrent / interleaved request IDs preserve order
 *  - request cancellation pass-through works (notifications/cancelled)
 *  - notifications/* pass-through works without inspection
 *  - EOF mid-message is detected (incomplete frames remain buffered)
 *
 * Bench:
 *  - p50 / p95 / p99 round-trip overhead at 4KB (small) and 100KB (large) sizes
 *
 * NOTE: Content-Length framing is intentionally NOT tested — MCP stdio uses
 * line-delimited JSON only (per @modelcontextprotocol/sdk's ReadBuffer source).
 * Eng review F2.1 listed Content-Length checks; verified against SDK source
 * and dropped from scope.
 */

import { describe, expect, test } from "vitest";
import { PassThrough } from "node:stream";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { startInProcessRelay } from "../spike/relay.js";

// ───────────────────────── helpers ──────────────────────────

const makeRequest = (id: number, method: string, params: unknown = {}): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  method,
  params,
} as JSONRPCMessage);

const makeResponse = (id: number, content: string): JSONRPCMessage => ({
  jsonrpc: "2.0",
  id,
  result: {
    content: [{ type: "text", text: content }],
  },
} as JSONRPCMessage);

const makeNotification = (method: string, params: unknown = {}): JSONRPCMessage => ({
  jsonrpc: "2.0",
  method,
  params,
} as JSONRPCMessage);

interface CapturedMessages {
  parent: JSONRPCMessage[];
  child: JSONRPCMessage[];
  output: JSONRPCMessage[];
}

function setupRelay(
  responder: (msg: JSONRPCMessage) => JSONRPCMessage | null,
): { parentIn: PassThrough; parentOut: PassThrough; captured: CapturedMessages } {
  const parentIn = new PassThrough();
  const parentOut = new PassThrough();
  const captured: CapturedMessages = { parent: [], child: [], output: [] };

  // Drain parentOut into captured.output via a ReadBuffer (model what an IDE sees).
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
    respond: responder,
    onParentMessage: (m) => captured.parent.push(m),
    onChildMessage: (m) => captured.child.push(m),
  });

  return { parentIn, parentOut, captured };
}

// ────────────────────── conformance tests ───────────────────

describe("MITM substrate spike (OQ1)", () => {
  test("line-delimited framing round-trips a tools/call", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("method" in msg && msg.method === "tools/call" && "id" in msg) {
        return makeResponse(msg.id as number, "result-body");
      }
      return null;
    });
    parentIn.write(serializeMessage(makeRequest(1, "tools/call")));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
    expect(captured.output).toHaveLength(1);
    const out = captured.output[0]!;
    expect("result" in out).toBe(true);
  });

  test("partial reads at arbitrary byte boundaries are buffered until newline", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("id" in msg) return makeResponse(msg.id as number, "ok");
      return null;
    });
    const wire = serializeMessage(makeRequest(2, "tools/call"));
    // Slice the wire bytes into 4 arbitrary chunks
    const buf = Buffer.from(wire, "utf8");
    const splits = [3, 12, 25];
    let cursor = 0;
    for (const s of splits) {
      parentIn.write(buf.subarray(cursor, s));
      cursor = s;
      await new Promise((r) => setImmediate(r));
      // Should not have parsed yet — no newline seen in early chunks
    }
    parentIn.write(buf.subarray(cursor));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
  });

  test("UTF-8 multibyte chars split across reads survive", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("id" in msg) return makeResponse(msg.id as number, "ack");
      return null;
    });
    // 👋 is 4-byte UTF-8 — slice between bytes 2 and 3
    const payload = "hello 👋 world";
    const wire = serializeMessage(makeRequest(3, "tools/call", { msg: payload }));
    const buf = Buffer.from(wire, "utf8");
    const waveStart = buf.indexOf(0xf0); // F0 9F 91 8B is the wave emoji
    expect(waveStart).toBeGreaterThan(0);
    parentIn.write(buf.subarray(0, waveStart + 2)); // split in middle of multibyte
    await new Promise((r) => setImmediate(r));
    parentIn.write(buf.subarray(waveStart + 2));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
    const params = (captured.parent[0] as { params?: { msg?: string } }).params;
    expect(params?.msg).toBe(payload);
  });

  test("large messages (100KB) round-trip cleanly", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("id" in msg) return makeResponse(msg.id as number, "x".repeat(100 * 1024));
      return null;
    });
    const big = "a".repeat(100 * 1024);
    parentIn.write(serializeMessage(makeRequest(4, "tools/call", { blob: big })));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
    expect(captured.output).toHaveLength(1);
    const out = captured.output[0] as { result?: { content?: Array<{ text?: string }> } };
    expect(out.result?.content?.[0]?.text?.length).toBe(100 * 1024);
  });

  test("concurrent in-flight requests preserve interleaved IDs", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("id" in msg) return makeResponse(msg.id as number, `id-${(msg.id as number)}`);
      return null;
    });
    // Write 50 requests back-to-back; expect 50 responses in matching order.
    let wire = "";
    for (let i = 0; i < 50; i++) {
      wire += serializeMessage(makeRequest(100 + i, "tools/call"));
    }
    parentIn.write(wire);
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(50);
    expect(captured.output).toHaveLength(50);
    for (let i = 0; i < 50; i++) {
      expect((captured.output[i] as { id?: number }).id).toBe(100 + i);
    }
  });

  test("notifications (no id) pass through without response", async () => {
    const { parentIn, captured } = setupRelay(() => null);
    parentIn.write(serializeMessage(makeNotification("notifications/cancelled", { requestId: 5 })));
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(1);
    expect(captured.output).toHaveLength(0); // no response for notifications
  });

  test("EOF mid-message leaves incomplete frame buffered (no false parse)", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("id" in msg) return makeResponse(msg.id as number, "ok");
      return null;
    });
    const wire = serializeMessage(makeRequest(6, "tools/call"));
    // Write everything except the trailing newline.
    parentIn.write(wire.slice(0, -1));
    parentIn.end();
    await new Promise((r) => setImmediate(r));
    expect(captured.parent).toHaveLength(0); // no message parsed without newline
  });
});

// ─────────────────────────── bench ──────────────────────────

describe.skipIf(process.env.SPIKE_BENCH !== "1")("MITM substrate spike bench (set SPIKE_BENCH=1)", () => {
  test("p99 round-trip overhead at small (4KB) and large (100KB) payloads", async () => {
    const { parentIn, captured } = setupRelay((msg) => {
      if ("id" in msg) {
        const inSize = ((msg as { params?: { blob?: string } }).params?.blob?.length) ?? 0;
        return makeResponse(msg.id as number, "x".repeat(inSize));
      }
      return null;
    });

    async function bench(sizeBytes: number, iterations: number): Promise<number[]> {
      const blob = "a".repeat(sizeBytes);
      const times: number[] = [];
      let received = 0;
      const start = captured.output.length;
      for (let i = 0; i < iterations; i++) {
        const t0 = performance.now();
        parentIn.write(serializeMessage(makeRequest(1_000_000 + i, "tools/call", { blob })));
        // Wait for matching response
        while (captured.output.length <= start + received) {
          await new Promise((r) => setImmediate(r));
        }
        const t1 = performance.now();
        times.push(t1 - t0);
        received++;
      }
      return times;
    }

    const percentile = (xs: number[], p: number): number => {
      const sorted = [...xs].sort((a, b) => a - b);
      const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
      return sorted[idx] ?? 0;
    };

    const smallTimes = await bench(4 * 1024, 1000);
    const largeTimes = await bench(100 * 1024, 200);

    const smallP50 = percentile(smallTimes, 50);
    const smallP99 = percentile(smallTimes, 99);
    const largeP50 = percentile(largeTimes, 50);
    const largeP99 = percentile(largeTimes, 99);

    // Emit a structured bench line that the spike report consumes.
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({
      spike: "v0.5.0-mitm-substrate-OQ1",
      small_4kb: { p50_ms: smallP50, p99_ms: smallP99, n: smallTimes.length },
      large_100kb: { p50_ms: largeP50, p99_ms: largeP99, n: largeTimes.length },
    }));

    // Asserts: design doc OQ1 budget = < 5ms p99 small, < 25ms p99 large
    expect(smallP99).toBeLessThan(5);
    expect(largeP99).toBeLessThan(25);
  }, 60_000);
});
