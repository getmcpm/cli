/**
 * Tests for drift.ts — schema-drift detection + first-session-pin capture
 * + accept-drift application (v0.5.0 Next Step 6).
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectForDrift, applyAcceptDrift, type DriftCheckDeps } from "../drift.js";
import {
  PinsIntegrityError,
  emptyPinsFile,
  hashToolDefinition,
  upsertToolPin,
  type PinsFile,
} from "../pins.js";

const SIGV = "v0.5.0";

function makeToolsListResponse(
  tools: Array<{ name: string; description?: string; inputSchema?: unknown; annotations?: unknown }>,
): JSONRPCMessage {
  return { jsonrpc: "2.0", id: 1, result: { tools } } as JSONRPCMessage;
}

function makeDeps(initialPins: PinsFile): {
  deps: DriftCheckDeps;
  writes: PinsFile[];
} {
  const writes: PinsFile[] = [];
  let snapshot = initialPins;
  return {
    writes,
    deps: {
      read: async () => snapshot,
      write: async (p) => {
        writes.push(p);
        snapshot = p;
      },
      signatureListVersion: SIGV,
    },
  };
}

describe("inspectForDrift — first-session capture", () => {
  test("with no pin: writes a first-session pin and passes traffic", async () => {
    const { deps, writes } = makeDeps(emptyPinsFile());
    const msg = makeToolsListResponse([
      { name: "read_file", description: "Read a file", inputSchema: { type: "object" } },
    ]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("pass");
    expect(writes).toHaveLength(1);
    const entry = writes[0]?.servers["fs-mcp"]?.["read_file"];
    expect(entry?.current_hash).toMatch(/^sha256:/);
    expect(entry?.captured_via).toBe("first-session");
  });

  test("with placeholder pin (current_hash:null): fills it in on first session", async () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs-mcp", "read_file", {
      current_hash: null,
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: SIGV,
    });
    const { deps, writes } = makeDeps(pins);
    const msg = makeToolsListResponse([
      { name: "read_file", description: "Read a file", inputSchema: { type: "object" } },
    ]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("pass");
    expect(writes[0]?.servers["fs-mcp"]?.["read_file"]?.current_hash).toMatch(/^sha256:/);
  });
});

describe("inspectForDrift — drift detection", () => {
  test("matching pin → pass", async () => {
    const tool = { name: "read_file", description: "Read a file", inputSchema: { type: "object" } };
    const hash = hashToolDefinition({
      description: tool.description,
      schema: tool.inputSchema,
      annotations: undefined,
    });
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs-mcp", "read_file", {
      current_hash: hash,
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: SIGV,
    });
    const { deps } = makeDeps(pins);
    const result = await inspectForDrift(makeToolsListResponse([tool]), "fs-mcp", deps);
    expect(result.action).toBe("pass");
  });

  test("description changed → BLOCK with schema-drift finding", async () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs-mcp", "read_file", {
      current_hash: hashToolDefinition({ description: "old desc" }),
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: SIGV,
    });
    const { deps } = makeDeps(pins);
    const msg = makeToolsListResponse([{ name: "read_file", description: "new (poisoned) desc" }]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("block");
    expect(result.findings[0]?.signature_id).toBe("schema-drift");
    expect(result.findings[0]?.severity).toBe("critical");
    expect(result.findings[0]?.remediation).toContain("accept-drift");
    expect(result.findings[0]?.remediation).toContain("--new-hash"); // security F5
  });

  test("multiple tools, only the drifted one fires", async () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs-mcp", "good", {
      current_hash: hashToolDefinition({ description: "stable" }),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: SIGV,
    });
    pins = upsertToolPin(pins, "fs-mcp", "bad", {
      current_hash: hashToolDefinition({ description: "old" }),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: SIGV,
    });
    const { deps } = makeDeps(pins);
    const msg = makeToolsListResponse([
      { name: "good", description: "stable" },
      { name: "bad", description: "new" },
    ]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("block");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.matched_text_excerpt).toContain("bad");
  });

  test("fails CLOSED on PinsIntegrityError (security F1)", async () => {
    const deps: DriftCheckDeps = {
      read: async () => { throw new PinsIntegrityError("tampered"); },
      write: async () => undefined,
      signatureListVersion: SIGV,
    };
    const msg = makeToolsListResponse([{ name: "read_file", description: "any" }]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("block");
    expect(result.findings[0]?.signature_id).toBe("pins-integrity-failure");
  });

  test("transient I/O read failure fails OPEN (recoverable)", async () => {
    const deps: DriftCheckDeps = {
      read: async () => { throw new Error("EIO disk error"); },
      write: async () => undefined,
      signatureListVersion: SIGV,
    };
    const msg = makeToolsListResponse([{ name: "read_file", description: "any" }]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("pass");
  });

  test("non-tools/list message → pass, no I/O", async () => {
    const { deps, writes } = makeDeps(emptyPinsFile());
    const msg = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "x" }] } } as JSONRPCMessage;
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("pass");
    expect(writes).toHaveLength(0);
  });
});

describe("applyAcceptDrift", () => {
  test("--remove drops the whole server pin", () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs", "read", {
      current_hash: "sha256:a",
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: SIGV,
    });
    const next = applyAcceptDrift(pins, "fs", { remove: true });
    expect(next.servers.fs).toBeUndefined();
  });

  test("--remove --tool drops one tool, keeps others", () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs", "read", {
      current_hash: "sha256:a", previous_hashes: [],
      captured_at: "x", captured_via: "install", signature_list_version: SIGV,
    });
    pins = upsertToolPin(pins, "fs", "write", {
      current_hash: "sha256:b", previous_hashes: [],
      captured_at: "x", captured_via: "install", signature_list_version: SIGV,
    });
    const next = applyAcceptDrift(pins, "fs", { remove: true, toolName: "read" });
    expect(next.servers.fs?.read).toBeUndefined();
    expect(next.servers.fs?.write?.current_hash).toBe("sha256:b");
  });

  test("with --new-hash: pins to that exact hash + preserves history (security F5)", () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs", "read", {
      current_hash: "sha256:" + "a".repeat(64), previous_hashes: [],
      captured_at: "x", captured_via: "install", signature_list_version: SIGV,
    });
    const newHash = "sha256:" + "b".repeat(64);
    const next = applyAcceptDrift(pins, "fs", { newHash });
    expect(next.servers.fs?.read?.current_hash).toBe(newHash);
    expect(next.servers.fs?.read?.previous_hashes).toEqual(["sha256:" + "a".repeat(64)]);
  });

  test("without --new-hash or --remove: throws (security F5 — no unbounded re-pin window)", () => {
    const pins = emptyPinsFile();
    expect(() => applyAcceptDrift(pins, "fs", {})).toThrow(/--new-hash/);
  });

  test("invalid --new-hash format throws", () => {
    const pins = emptyPinsFile();
    expect(() => applyAcceptDrift(pins, "fs", { newHash: "not-a-hash" })).toThrow(/--new-hash/);
  });

  test("non-existent server with --remove is a no-op", () => {
    const pins = emptyPinsFile();
    const next = applyAcceptDrift(pins, "nope", { remove: true });
    expect(next).toBe(pins);
  });
});
