/**
 * Tests for src/config/adapters/claude-desktop.ts
 *
 * TDD — RED phase.
 * Uses vi.mock for fs/promises — no real filesystem.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn(),
  mkdir: vi.fn(),
  copyFile: vi.fn(),
}));

import { readFile, writeFile, rename, mkdir, copyFile } from "fs/promises";
import { ClaudeDesktopAdapter } from "../../../config/adapters/claude-desktop.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;
const mockCopyFile = copyFile as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/claude_desktop_config.json";

function makeConfig(servers: Record<string, McpServerEntry>) {
  return JSON.stringify({ mcpServers: servers });
}

describe("ClaudeDesktopAdapter", () => {
  const adapter = new ClaudeDesktopAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
    mockMkdir.mockResolvedValue(undefined);
    mockCopyFile.mockResolvedValue(undefined);
  });

  // -------------------------------------------------------------------------
  // clientId
  // -------------------------------------------------------------------------

  it("has clientId = claude-desktop", () => {
    expect(adapter.clientId).toBe("claude-desktop");
  });

  // -------------------------------------------------------------------------
  // read
  // -------------------------------------------------------------------------

  describe("read", () => {
    it("returns servers from mcpServers key", async () => {
      const entry: McpServerEntry = {
        command: "npx",
        args: ["-y", "some-server"],
      };
      mockReadFile.mockResolvedValue(makeConfig({ "my-server": entry }));
      const result = await adapter.read(CONFIG_PATH);
      expect(result).toEqual({ "my-server": entry });
    });

    it("returns empty object when mcpServers key is absent", async () => {
      mockReadFile.mockResolvedValue(JSON.stringify({ otherKey: "value" }));
      const result = await adapter.read(CONFIG_PATH);
      expect(result).toEqual({});
    });

    it("returns empty object when file does not exist (ENOENT)", async () => {
      const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      mockReadFile.mockRejectedValue(err);
      const result = await adapter.read(CONFIG_PATH);
      expect(result).toEqual({});
    });

    it("throws on malformed JSON", async () => {
      mockReadFile.mockResolvedValue("{ bad json ]");
      await expect(adapter.read(CONFIG_PATH)).rejects.toThrow();
    });

    it("throws on unreadable file (EACCES)", async () => {
      const err = Object.assign(new Error("EACCES"), { code: "EACCES" });
      mockReadFile.mockRejectedValue(err);
      await expect(adapter.read(CONFIG_PATH)).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // listServers — delegates to read
  // -------------------------------------------------------------------------

  describe("read", () => {
    it("returns same result as read", async () => {
      const entry: McpServerEntry = { command: "npx", args: ["-y", "srv"] };
      mockReadFile.mockResolvedValue(makeConfig({ srv: entry }));
      const result = await adapter.read(CONFIG_PATH);
      expect(result).toEqual({ srv: entry });
    });
  });

  // -------------------------------------------------------------------------
  // addServer
  // -------------------------------------------------------------------------

  describe("addServer", () => {
    it("writes new server into mcpServers using atomic write", async () => {
      mockReadFile.mockResolvedValue(makeConfig({}));
      const entry: McpServerEntry = { command: "npx", args: ["-y", "new-srv"] };
      await adapter.addServer(CONFIG_PATH, "new-srv", entry);

      expect(mockWriteFile).toHaveBeenCalledOnce();
      const writtenContent = JSON.parse(
        mockWriteFile.mock.calls[0][1] as string
      );
      expect(writtenContent.mcpServers["new-srv"]).toEqual(entry);

      // Atomic: rename from .tmp path to real path
      expect(mockRename).toHaveBeenCalledOnce();
      const [tmpPath, finalPath] = mockRename.mock.calls[0] as [string, string];
      expect(tmpPath).toMatch(/\.tmp$/);
      expect(finalPath).toBe(CONFIG_PATH);
    });

    it("preserves existing servers when adding a new one", async () => {
      const existing: McpServerEntry = { command: "uvx", args: ["existing"] };
      mockReadFile.mockResolvedValue(makeConfig({ existing }));
      const newEntry: McpServerEntry = { command: "npx", args: ["-y", "new"] };
      await adapter.addServer(CONFIG_PATH, "new-srv", newEntry);

      const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
      expect(written.mcpServers["existing"]).toEqual(existing);
      expect(written.mcpServers["new-srv"]).toEqual(newEntry);
    });

    it("preserves unrelated keys in the config file", async () => {
      mockReadFile.mockResolvedValue(
        JSON.stringify({ mcpServers: {}, someOtherKey: "preserve-me" })
      );
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);
      const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
      expect(written.someOtherKey).toBe("preserve-me");
    });

    it("creates config with mcpServers key when file does not exist", async () => {
      const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      mockReadFile.mockRejectedValue(err);
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);
      const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
      expect(written.mcpServers).toBeDefined();
      expect(written.mcpServers["srv"]).toEqual(entry);
    });

    it("throws if server already exists", async () => {
      const existing: McpServerEntry = { command: "npx", args: [] };
      mockReadFile.mockResolvedValue(makeConfig({ "my-srv": existing }));
      await expect(
        adapter.addServer(CONFIG_PATH, "my-srv", existing)
      ).rejects.toThrow(/already exists/i);
    });

    it("does not mutate the entry object passed in", async () => {
      mockReadFile.mockResolvedValue(makeConfig({}));
      const entry: McpServerEntry = {
        command: "npx",
        args: ["-y", "srv"],
        env: { KEY: "val" },
      };
      const entryCopy = structuredClone(entry);
      await adapter.addServer(CONFIG_PATH, "srv", entry);
      expect(entry).toEqual(entryCopy);
    });
  });

  // -------------------------------------------------------------------------
  // removeServer
  // -------------------------------------------------------------------------

  describe("removeServer", () => {
    it("removes the named server and writes atomically", async () => {
      const entry: McpServerEntry = { command: "npx", args: [] };
      mockReadFile.mockResolvedValue(
        makeConfig({ "to-remove": entry, "keep-me": entry })
      );
      await adapter.removeServer(CONFIG_PATH, "to-remove");

      const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
      expect(written.mcpServers["to-remove"]).toBeUndefined();
      expect(written.mcpServers["keep-me"]).toEqual(entry);

      expect(mockRename).toHaveBeenCalledOnce();
    });

    it("throws if server not found", async () => {
      mockReadFile.mockResolvedValue(makeConfig({ other: { command: "npx", args: [] } }));
      await expect(
        adapter.removeServer(CONFIG_PATH, "missing")
      ).rejects.toThrow(/not found/i);
    });

    it("throws if config file does not exist", async () => {
      const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      mockReadFile.mockRejectedValue(err);
      await expect(
        adapter.removeServer(CONFIG_PATH, "any")
      ).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // backup-before-write
  // -------------------------------------------------------------------------

  describe("backup-before-write", () => {
    it("creates a .bak copy before addServer writes", async () => {
      mockReadFile.mockResolvedValue(makeConfig({}));
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);

      expect(mockCopyFile).toHaveBeenCalledOnce();
      expect(mockCopyFile).toHaveBeenCalledWith(
        CONFIG_PATH,
        `${CONFIG_PATH}.bak`
      );
      // copyFile must be called BEFORE writeFile
      const copyOrder = mockCopyFile.mock.invocationCallOrder[0];
      const writeOrder = mockWriteFile.mock.invocationCallOrder[0];
      expect(copyOrder).toBeLessThan(writeOrder!);
    });

    it("creates a .bak copy before removeServer writes", async () => {
      const entry: McpServerEntry = { command: "npx", args: [] };
      mockReadFile.mockResolvedValue(makeConfig({ srv: entry }));
      await adapter.removeServer(CONFIG_PATH, "srv");

      expect(mockCopyFile).toHaveBeenCalledOnce();
      expect(mockCopyFile).toHaveBeenCalledWith(
        CONFIG_PATH,
        `${CONFIG_PATH}.bak`
      );
    });

    it("skips backup silently when config does not exist yet", async () => {
      const enoent = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      mockReadFile.mockRejectedValue(enoent);
      mockCopyFile.mockRejectedValue(enoent);

      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);

      // copyFile was attempted but ENOENT was swallowed
      expect(mockCopyFile).toHaveBeenCalledOnce();
      // writeFile still proceeded
      expect(mockWriteFile).toHaveBeenCalledOnce();
    });

    it("throws if backup fails with non-ENOENT error", async () => {
      mockReadFile.mockResolvedValue(makeConfig({}));
      const eacces = Object.assign(new Error("EACCES"), { code: "EACCES" });
      mockCopyFile.mockRejectedValue(eacces);

      const entry: McpServerEntry = { command: "npx", args: [] };
      await expect(
        adapter.addServer(CONFIG_PATH, "srv", entry)
      ).rejects.toThrow();
    });
  });
});
