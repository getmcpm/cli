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
}));

import { readFile, writeFile, rename, mkdir } from "fs/promises";
import { ClaudeDesktopAdapter } from "../../../config/adapters/claude-desktop.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;

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

      // Two writes: .bak backup + .tmp atomic write
      expect(mockWriteFile).toHaveBeenCalledTimes(2);
      const tmpContent = JSON.parse(
        mockWriteFile.mock.calls[1][1] as string
      );
      expect(tmpContent.mcpServers["new-srv"]).toEqual(entry);

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

      // .bak is calls[0], .tmp is calls[1]
      const written = JSON.parse(mockWriteFile.mock.calls[1][1] as string);
      expect(written.mcpServers["existing"]).toEqual(existing);
      expect(written.mcpServers["new-srv"]).toEqual(newEntry);
    });

    it("preserves unrelated keys in the config file", async () => {
      mockReadFile.mockResolvedValue(
        JSON.stringify({ mcpServers: {}, someOtherKey: "preserve-me" })
      );
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);
      const written = JSON.parse(mockWriteFile.mock.calls[1][1] as string);
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

      // .bak is calls[0], .tmp is calls[1]
      const written = JSON.parse(mockWriteFile.mock.calls[1][1] as string);
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
    it("writes .bak from in-memory content before addServer modifies config", async () => {
      const existing: McpServerEntry = { command: "uvx", args: ["old"] };
      mockReadFile.mockResolvedValue(makeConfig({ old: existing }));
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);

      // Two writeFile calls: first is .bak, second is .tmp
      expect(mockWriteFile).toHaveBeenCalledTimes(2);
      const [bakPath, bakContent] = mockWriteFile.mock.calls[0] as [string, string, unknown];
      expect(bakPath).toBe(`${CONFIG_PATH}.bak`);
      const parsed = JSON.parse(bakContent);
      expect(parsed.mcpServers.old).toEqual(existing);
      expect(parsed.mcpServers.srv).toBeUndefined();
    });

    it("writes .bak before removeServer modifies config", async () => {
      const entry: McpServerEntry = { command: "npx", args: [] };
      mockReadFile.mockResolvedValue(makeConfig({ srv: entry }));
      await adapter.removeServer(CONFIG_PATH, "srv");

      expect(mockWriteFile).toHaveBeenCalledTimes(2);
      const [bakPath] = mockWriteFile.mock.calls[0] as [string, string, unknown];
      expect(bakPath).toBe(`${CONFIG_PATH}.bak`);
    });

    it("skips .bak when config does not exist yet (first-time creation)", async () => {
      const enoent = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      mockReadFile.mockRejectedValue(enoent);

      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);

      // Only one writeFile call (the .tmp), no .bak
      expect(mockWriteFile).toHaveBeenCalledOnce();
      const [writtenPath] = mockWriteFile.mock.calls[0] as [string, string, unknown];
      expect(writtenPath).toMatch(/\.tmp$/);
    });
  });
});
