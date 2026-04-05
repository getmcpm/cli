/**
 * Tests for src/commands/alias.ts
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleAlias } from "../../commands/alias.js";
import type { AliasDeps } from "../../commands/alias.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDeps(overrides: Partial<AliasDeps> = {}): AliasDeps {
  return {
    getAliases: vi.fn().mockResolvedValue({}),
    setAlias: vi.fn().mockResolvedValue(undefined),
    removeAlias: vi.fn().mockResolvedValue(undefined),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleAlias", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("--list", () => {
    it("shows empty message when no aliases exist", async () => {
      const deps = makeDeps();
      await handleAlias([], { list: true }, deps);
      const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
      expect(output).toMatch(/No aliases/i);
    });

    it("displays aliases in a table", async () => {
      const deps = makeDeps({
        getAliases: vi.fn().mockResolvedValue({
          fs: "io.github.domdomegg/filesystem-mcp",
          gh: "io.github.modelcontextprotocol/github",
        }),
      });
      await handleAlias([], { list: true }, deps);
      const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
      expect(output).toContain("fs");
      expect(output).toContain("io.github.domdomegg/filesystem-mcp");
    });
  });

  describe("--remove", () => {
    it("removes an existing alias", async () => {
      const deps = makeDeps();
      await handleAlias([], { remove: "fs" }, deps);
      expect(deps.removeAlias).toHaveBeenCalledWith("fs");
    });

    it("outputs confirmation after removal", async () => {
      const deps = makeDeps();
      await handleAlias([], { remove: "fs" }, deps);
      const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
      expect(output).toMatch(/Removed.*fs/);
    });
  });

  describe("set alias", () => {
    it("sets an alias with two positional args", async () => {
      const deps = makeDeps();
      await handleAlias(["fs", "io.github.domdomegg/filesystem-mcp"], {}, deps);
      expect(deps.setAlias).toHaveBeenCalledWith("fs", "io.github.domdomegg/filesystem-mcp");
    });

    it("outputs the alias mapping", async () => {
      const deps = makeDeps();
      await handleAlias(["fs", "io.github.domdomegg/filesystem-mcp"], {}, deps);
      const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
      expect(output).toContain("fs");
      expect(output).toContain("io.github.domdomegg/filesystem-mcp");
    });

    it("throws when insufficient arguments", async () => {
      const deps = makeDeps();
      await expect(handleAlias(["fs"], {}, deps)).rejects.toThrow(/Usage/);
    });

    it("throws when alias contains /", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias(["bad/name", "some-server"], {}, deps)
      ).rejects.toThrow(/letters.*digits.*hyphens.*underscores/);
    });

    it("throws when alias contains .", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias(["bad.name", "some-server"], {}, deps)
      ).rejects.toThrow(/letters.*digits.*hyphens.*underscores/);
    });

    it("throws when alias is empty", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias(["", "some-server"], {}, deps)
      ).rejects.toThrow(/must not be empty/);
    });

    it("throws when alias contains shell metacharacters", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias(["bad$name", "some-server"], {}, deps)
      ).rejects.toThrow(/letters.*digits.*hyphens.*underscores/);
    });

    it("throws when alias exceeds max length", async () => {
      const deps = makeDeps();
      const longName = "a".repeat(65);
      await expect(
        handleAlias([longName, "some-server"], {}, deps)
      ).rejects.toThrow(/at most 64/);
    });

    it("throws when server name is empty", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias(["fs", ""], {}, deps)
      ).rejects.toThrow(/must not be empty/);
    });

    it("throws when server name is __proto__", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias(["fs", "__proto__"], {}, deps)
      ).rejects.toThrow(/not allowed/);
    });
  });

  describe("--remove validation", () => {
    it("validates alias name before removing", async () => {
      const deps = makeDeps();
      await expect(
        handleAlias([], { remove: "bad$name" }, deps)
      ).rejects.toThrow(/letters.*digits.*hyphens.*underscores/);
      expect(deps.removeAlias).not.toHaveBeenCalled();
    });
  });
});
