/**
 * #104 sweep — every recursive walker reachable from `inspectFrame` must
 * survive a pathologically deep, but shallow-looking-on-the-wire, JSON value
 * regardless of WHERE in a frame it appears.
 *
 * `stringArgLeaves` (tool-call-args-walk.ts) was the one genuine bug (see
 * tool-call-args-walk.test.ts and inspect-cli-deep-args.test.ts): a recursive
 * generator with no depth/node budget, reachable only via a `tools/call`
 * request's `params.arguments`. Every OTHER carrier already funnels through
 * `stringLeaves` (patterns.ts), which has been an iterative, node-budgeted
 * walk since v0.26.0, and `exfilKeys` (exfil-params.ts), whose depth check
 * runs before any recursive step regardless of shape. This file is the
 * measurement that confirms those carriers hold, not an assumption.
 *
 * Two deep shapes, matching the two the CHANGELOG's v0.42.2 entry measured for
 * the sibling relay bug: 100,000-deep nested ARRAYS (walked transparently by
 * every recursive-array unwrap in this codebase) and 20,000-deep `"0"`-keyed
 * OBJECTS (walked by the generic object-value recursion). Both are built via
 * `JSON.parse` of a directly-concatenated JSON string — iterative in V8 — so
 * building the fixture itself never recurses.
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectFrame } from "../inspect-frame.js";

function deepArray(depth: number, leaf: unknown): unknown {
  return JSON.parse("[".repeat(depth) + JSON.stringify(leaf) + "]".repeat(depth));
}

function deepZeroKeyedObject(depth: number, leaf: unknown): unknown {
  return JSON.parse('{"0":'.repeat(depth) + JSON.stringify(leaf) + "}".repeat(depth));
}

interface Carrier {
  readonly name: string;
  readonly build: (deep: unknown) => JSONRPCMessage;
}

const CARRIERS: readonly Carrier[] = [
  {
    name: "tools/call params.arguments",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "t", arguments: { items: deep } },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "tools/list result tool.inputSchema",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 2,
        result: { tools: [{ name: "t", description: "d", inputSchema: deep }] },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "tools/list result tool.annotations",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 3,
        result: { tools: [{ name: "t", description: "d", annotations: deep }] },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "tools/call response result.structuredContent",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 4,
        result: { content: [{ type: "text", text: "ok" }], structuredContent: deep },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "tools/call response result.content[].text SIBLING field",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 5,
        result: { content: [{ type: "text", text: "ok", extra: deep }] },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "sampling/createMessage request params (server-initiated)",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 6,
        method: "sampling/createMessage",
        params: { messages: [{ role: "user", content: deep }] },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "resources/read response result.contents[].text",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 7,
        result: { contents: [{ uri: "file:///x", text: deep }] },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "prompts/get response result.messages[].content",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 8,
        result: { messages: [{ role: "user", content: deep }] },
      }) as unknown as JSONRPCMessage,
  },
  {
    name: "initialize response result.serverInfo",
    build: (deep) =>
      ({
        jsonrpc: "2.0",
        id: 9,
        result: { protocolVersion: "2025-06-18", instructions: "hi", serverInfo: deep },
      }) as unknown as JSONRPCMessage,
  },
];

describe("inspectFrame — deep-nesting sweep across every carrier (#104)", () => {
  for (const carrier of CARRIERS) {
    test(`${carrier.name} — 100,000-deep nested arrays does not throw`, () => {
      const msg = carrier.build(deepArray(100_000, "x"));
      expect(() => inspectFrame(msg)).not.toThrow();
    });

    test(`${carrier.name} — 20,000-deep "0"-keyed objects does not throw`, () => {
      const msg = carrier.build(deepZeroKeyedObject(20_000, "x"));
      expect(() => inspectFrame(msg)).not.toThrow();
    });
  }
});
