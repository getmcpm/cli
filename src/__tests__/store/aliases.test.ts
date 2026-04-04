/**
 * Tests for src/store/aliases.ts
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { getAliases, setAlias, removeAlias, resolveAlias } from "../../store/aliases.js";

// Mock the store index to avoid real filesystem I/O.
vi.mock("../../store/index.js", () => {
  let store: Record<string, unknown> = {};
  return {
    readJson: vi.fn().mockImplementation(async (filename: string) => {
      return store[filename] ?? null;
    }),
    writeJson: vi.fn().mockImplementation(async (filename: string, data: unknown) => {
      store[filename] = data;
    }),
    // Expose for tests to reset state
    _resetStore: () => { store = {}; },
  };
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const storeModule = await import("../../store/index.js") as any;

describe("aliases store", () => {
  beforeEach(() => {
    storeModule._resetStore();
    vi.clearAllMocks();
  });

  it("returns empty object when no aliases file exists", async () => {
    const result = await getAliases();
    expect(result).toEqual({});
  });

  it("sets and retrieves an alias", async () => {
    await setAlias("fs", "io.github.domdomegg/filesystem-mcp");
    const aliases = await getAliases();
    expect(aliases["fs"]).toBe("io.github.domdomegg/filesystem-mcp");
  });

  it("overwrites an existing alias", async () => {
    await setAlias("fs", "old-server");
    await setAlias("fs", "new-server");
    const aliases = await getAliases();
    expect(aliases["fs"]).toBe("new-server");
  });

  it("removes an alias", async () => {
    await setAlias("fs", "some-server");
    await removeAlias("fs");
    const aliases = await getAliases();
    expect(aliases["fs"]).toBeUndefined();
  });

  it("throws when removing non-existent alias", async () => {
    await expect(removeAlias("nonexistent")).rejects.toThrow(/not found/i);
  });

  it("resolves alias to server name", async () => {
    await setAlias("fs", "io.github.domdomegg/filesystem-mcp");
    const resolved = await resolveAlias("fs");
    expect(resolved).toBe("io.github.domdomegg/filesystem-mcp");
  });

  it("returns input when no alias matches", async () => {
    const resolved = await resolveAlias("io.github.domdomegg/filesystem-mcp");
    expect(resolved).toBe("io.github.domdomegg/filesystem-mcp");
  });
});
