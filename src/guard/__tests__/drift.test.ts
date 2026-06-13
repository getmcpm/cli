/**
 * Tests for drift.ts — schema-drift detection + first-session-pin capture
 * + accept-drift application (v0.5.0 Next Step 6).
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import {
  inspectForDrift,
  applyAcceptDrift,
  diffToolDefinition,
  classifyDrift,
  type DriftCheckDeps,
} from "../drift.js";
import {
  PinsIntegrityError,
  emptyPinsFile,
  hashToolDefinition,
  fieldHashesOf,
  upsertToolPin,
  type PinEntry,
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

// ─────────────── H4: field-level drift classification ───────────────

const makePin = (
  fields: Parameters<typeof fieldHashesOf>[0],
  withFieldHashes = true,
): PinEntry => ({
  current_hash: hashToolDefinition({
    description: fields.description,
    schema: fields.schema,
    annotations: fields.annotations,
  }),
  previous_hashes: [],
  captured_at: "2026-05-17T00:00:00Z",
  captured_via: "install",
  signature_list_version: SIGV,
  ...(withFieldHashes ? { field_hashes: fieldHashesOf(fields) } : {}),
});

describe("diffToolDefinition", () => {
  test("undefined pinned → [] (coarse)", () => {
    expect(diffToolDefinition(undefined, fieldHashesOf({ description: "x" }))).toEqual([]);
  });

  test("no change → []", () => {
    const fh = fieldHashesOf({ description: "x", schema: { type: "object" } });
    expect(diffToolDefinition(fh, fh)).toEqual([]);
  });

  test("description-only change", () => {
    const a = fieldHashesOf({ description: "old", schema: { type: "object" } });
    const b = fieldHashesOf({ description: "new", schema: { type: "object" } });
    expect(diffToolDefinition(a, b)).toEqual(["description"]);
  });

  test("multi-field change is ordered description,schema,annotations", () => {
    const a = fieldHashesOf({ description: "old", schema: { type: "object" }, annotations: { x: 1 } });
    const b = fieldHashesOf({ description: "new", schema: { type: "string" }, annotations: { x: 2 } });
    expect(diffToolDefinition(a, b)).toEqual(["description", "schema", "annotations"]);
  });
});

describe("classifyDrift", () => {
  test("description-only → cosmetic", () => {
    const pinned = makePin({ description: "old", schema: { type: "object" } });
    const live = fieldHashesOf({ description: "new wording", schema: { type: "object" } });
    expect(classifyDrift(pinned, live)).toEqual({
      kind: "cosmetic",
      changedFields: ["description"],
    });
  });

  test("schema-only → security", () => {
    const pinned = makePin({ description: "d", schema: { type: "object" } });
    const live = fieldHashesOf({ description: "d", schema: { type: "string" } });
    expect(classifyDrift(pinned, live)).toEqual({ kind: "security", changedFields: ["schema"] });
  });

  test("annotations-only (readOnlyHint true→false) → security", () => {
    const pinned = makePin({ description: "d", annotations: { readOnlyHint: true } });
    const live = fieldHashesOf({ description: "d", annotations: { readOnlyHint: false } });
    expect(classifyDrift(pinned, live)).toEqual({ kind: "security", changedFields: ["annotations"] });
  });

  test("description + schema → security", () => {
    const pinned = makePin({ description: "old", schema: { type: "object" } });
    const live = fieldHashesOf({ description: "new", schema: { type: "string" } });
    expect(classifyDrift(pinned, live)).toEqual({
      kind: "security",
      changedFields: ["description", "schema"],
    });
  });

  test("pre-H4 pin (no field_hashes) → coarse security with empty changedFields", () => {
    const pinned = makePin({ description: "old" }, /* withFieldHashes */ false);
    const live = fieldHashesOf({ description: "new" });
    expect(classifyDrift(pinned, live)).toEqual({ kind: "security", changedFields: [] });
  });
});

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
    // H4: first-session capture now records per-field hashes.
    expect(entry?.field_hashes?.description).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(entry?.field_hashes?.schema).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(entry?.field_hashes?.annotations).toMatch(/^sha256:[0-9a-f]{64}$/);
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

  // H4: a description-only change on an H4 pin (with field_hashes) is COSMETIC →
  // warn, signature schema-drift-cosmetic, and the durable pin is NOT rewritten.
  test("description-only change on H4 pin → WARN (schema-drift-cosmetic), no re-pin", async () => {
    const baseFields = { description: "old desc", schema: { type: "object" } };
    let pins = emptyPinsFile();
    const pinEntry: PinEntry = {
      current_hash: hashToolDefinition(baseFields),
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: SIGV,
      field_hashes: fieldHashesOf(baseFields),
    };
    pins = upsertToolPin(pins, "fs-mcp", "read_file", pinEntry);
    const { deps, writes } = makeDeps(pins);
    const msg = makeToolsListResponse([
      { name: "read_file", description: "new wording, same behavior", inputSchema: { type: "object" } },
    ]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("warn");
    expect(result.findings[0]?.signature_id).toBe("schema-drift-cosmetic");
    expect(result.findings[0]?.severity).toBe("high");
    expect(result.findings[0]?.remediation).toContain("accept-drift");
    expect(result.findings[0]?.matched_text_excerpt).toContain("description");
    // The durable pin's current_hash must NOT have been rewritten to the new hash.
    for (const w of writes) {
      expect(w.servers["fs-mcp"]?.["read_file"]?.current_hash).toBe(pinEntry.current_hash);
    }
  });

  // H4: a schema change on an H4 pin is a SECURITY drift → block.
  test("schema change on H4 pin → BLOCK (schema-drift)", async () => {
    const baseFields = { description: "d", schema: { type: "object" } };
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs-mcp", "read_file", {
      current_hash: hashToolDefinition(baseFields),
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: SIGV,
      field_hashes: fieldHashesOf(baseFields),
    });
    const { deps } = makeDeps(pins);
    const msg = makeToolsListResponse([
      { name: "read_file", description: "d", inputSchema: { type: "string" } },
    ]);
    const result = await inspectForDrift(msg, "fs-mcp", deps);
    expect(result.action).toBe("block");
    expect(result.findings[0]?.signature_id).toBe("schema-drift");
    expect(result.findings[0]?.severity).toBe("critical");
    expect(result.findings[0]?.remediation).toContain("accept-drift");
    expect(result.findings[0]?.remediation).toContain("--new-hash");
    expect(result.findings[0]?.matched_text_excerpt).toContain("schema");
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

  test("drops stale field_hashes → entry reverts to coarse SECURITY tiering (H4)", () => {
    // A pinned tool carrying H4 field_hashes for its V1 definition.
    let pins = emptyPinsFile();
    const v1 = { description: "v1 desc", schema: { type: "object" } };
    pins = upsertToolPin(pins, "fs", "read", {
      current_hash: hashToolDefinition(v1),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "first-session",
      signature_list_version: SIGV,
      field_hashes: fieldHashesOf(v1),
    });
    const newHash = "sha256:" + "c".repeat(64);
    const entry = applyAcceptDrift(pins, "fs", { newHash }).servers.fs?.read as PinEntry;

    // field_hashes is dropped — keeping V1 hashes past a current_hash rewrite would
    // break the whole⟺field invariant and could mis-tier a later drift as cosmetic.
    expect(entry.field_hashes).toBeUndefined();
    expect(entry.current_hash).toBe(newHash);
    // So a later drift is now classified coarse SECURITY (block), never cosmetic/warn.
    expect(classifyDrift(entry, fieldHashesOf({ description: "anything new" }))).toEqual({
      kind: "security",
      changedFields: [],
    });
  });
});
