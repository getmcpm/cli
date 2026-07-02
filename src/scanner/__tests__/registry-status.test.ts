import { describe, it, expect } from "vitest";
import { assessRegistryStatus, assessServerStatus } from "../registry-status.js";
import type { ServerEntry } from "../../registry/types.js";

function entryWithStatus(status?: string, statusMessage?: string): ServerEntry {
  return {
    server: { name: "example/server", version: "1.0.0", packages: [] },
    _meta: status
      ? {
          "io.modelcontextprotocol.registry/official": {
            status,
            ...(statusMessage ? { statusMessage } : {}),
          },
        }
      : undefined,
  } as unknown as ServerEntry;
}

describe("assessRegistryStatus", () => {
  it('BLOCKS on "deleted" and emits a medium finding', () => {
    const r = assessRegistryStatus("deleted");
    expect(r.blocks).toBe(true);
    expect(r.finding?.type).toBe("registry-status");
    expect(r.finding?.severity).toBe("medium");
  });

  it('WARNS but does NOT block on "deprecated"', () => {
    const r = assessRegistryStatus("deprecated");
    expect(r.blocks).toBe(false);
    expect(r.finding?.type).toBe("registry-status");
  });

  it('is inert on "active" (no block, no finding)', () => {
    const r = assessRegistryStatus("active");
    expect(r.blocks).toBe(false);
    expect(r.finding).toBeUndefined();
  });

  it("is fail-SAFE on undefined status (no block, no finding)", () => {
    const r = assessRegistryStatus(undefined);
    expect(r.blocks).toBe(false);
    expect(r.finding).toBeUndefined();
  });

  it("is fail-SAFE on an unknown/future status like 'removed' (no block)", () => {
    // A status the registry may add later must never start blocking installs.
    const r = assessRegistryStatus("removed");
    expect(r.blocks).toBe(false);
    expect(r.finding).toBeUndefined();
  });

  it("matches case-insensitively and trims whitespace", () => {
    expect(assessRegistryStatus("  DELETED  ").blocks).toBe(true);
    expect(assessRegistryStatus("Deprecated").finding?.type).toBe("registry-status");
  });

  it("includes the registry statusMessage in the finding when present", () => {
    const r = assessRegistryStatus("deleted", "removed for a security incident");
    expect(r.statusMessage).toBe("removed for a security incident");
    expect(r.finding?.message).toContain("removed for a security incident");
  });
});

describe("assessServerStatus (reads _meta)", () => {
  it("reads the official status block from a ServerEntry", () => {
    expect(assessServerStatus(entryWithStatus("deleted")).blocks).toBe(true);
    expect(assessServerStatus(entryWithStatus("deprecated")).blocks).toBe(false);
    expect(assessServerStatus(entryWithStatus("active")).finding).toBeUndefined();
    expect(assessServerStatus(entryWithStatus(undefined)).blocks).toBe(false);
  });
});
