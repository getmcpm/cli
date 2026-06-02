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
  lstat: vi.fn(),
  unlink: vi.fn(),
}));

import { readFile, writeFile, rename, mkdir, lstat, unlink } from "fs/promises";
import { ClaudeDesktopAdapter } from "../../../config/adapters/claude-desktop.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;
const mockLstat = lstat as ReturnType<typeof vi.fn>;
const mockUnlink = unlink as ReturnType<typeof vi.fn>;

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
    // Config path is a regular file (not a symlink) by default.
    mockLstat.mockResolvedValue({ isSymbolicLink: () => false });
    mockUnlink.mockResolvedValue(undefined);
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

    it("returns empty object when file is empty (zero bytes)", async () => {
      mockReadFile.mockResolvedValue("");
      const result = await adapter.read(CONFIG_PATH);
      expect(result).toEqual({});
    });

    it("returns empty object when file is whitespace only", async () => {
      mockReadFile.mockResolvedValue("   \n  \n");
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
    // #25: the .bak must preserve the RAW original bytes verbatim — not a
    // re-serialized copy of the parsed object. We feed a config with custom
    // formatting + a comment-style key; pre-fix code (JSON.stringify of the
    // parsed object) would lose the exact bytes and fail this assertion.
    it("writes the RAW original bytes to .bak before addServer modifies config", async () => {
      // Valid JSON with deliberate formatting + key order that a re-serialize
      // (JSON.stringify of the parsed object) would NOT reproduce. Pre-fix
      // code wrote the re-serialized form and would fail the verbatim check.
      const rawOriginal =
        '{\n\t"z_last": true,\n\t"mcpServers": {"old": {"command": "uvx", "args": ["old"]}}\n}';
      mockReadFile.mockResolvedValue(rawOriginal);
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);

      // Two writeFile calls: first is .bak, second is .tmp
      expect(mockWriteFile).toHaveBeenCalledTimes(2);
      const [bakPath, bakContent, bakOpts] = mockWriteFile.mock.calls[0] as [
        string,
        string,
        { flag?: string },
      ];
      expect(bakPath).toBe(`${CONFIG_PATH}.bak`);
      // Verbatim — byte-for-byte equal to what was read (tabs + key order kept).
      expect(bakContent).toBe(rawOriginal);
      // It is NOT the re-serialized form a pre-fix implementation would write.
      expect(bakContent).not.toBe(JSON.stringify(JSON.parse(rawOriginal), null, 2));
      // #26: exclusive create so a pre-placed .bak symlink can't be followed.
      expect(bakOpts.flag).toBe("wx");
    });

    it("writes .bak before removeServer modifies config", async () => {
      const entry: McpServerEntry = { command: "npx", args: [] };
      mockReadFile.mockResolvedValue(makeConfig({ srv: entry }));
      await adapter.removeServer(CONFIG_PATH, "srv");

      expect(mockWriteFile).toHaveBeenCalledTimes(2);
      const [bakPath] = mockWriteFile.mock.calls[0] as [string, string, unknown];
      expect(bakPath).toBe(`${CONFIG_PATH}.bak`);
    });

    // #25: write-once. If a .bak already exists (the exclusive write rejects
    // EEXIST), the original backup is left intact and the operation still
    // succeeds. Pre-fix code overwrote the .bak on every single write.
    it("does not clobber an existing .bak (write-once)", async () => {
      mockReadFile.mockResolvedValue(makeConfig({ old: { command: "uvx", args: [] } }));
      // Simulate an existing .bak: the exclusive .bak write fails EEXIST,
      // the .tmp write succeeds.
      const eexist = Object.assign(new Error("EEXIST"), { code: "EEXIST" });
      mockWriteFile
        .mockReset()
        .mockRejectedValueOnce(eexist) // .bak — already exists
        .mockResolvedValueOnce(undefined); // .tmp

      const entry: McpServerEntry = { command: "npx", args: [] };
      await expect(adapter.addServer(CONFIG_PATH, "srv", entry)).resolves.toBeUndefined();

      // .bak attempt used the exclusive flag; the config write still happened.
      const [bakPath, , bakOpts] = mockWriteFile.mock.calls[0] as [
        string,
        string,
        { flag?: string },
      ];
      expect(bakPath).toBe(`${CONFIG_PATH}.bak`);
      expect(bakOpts.flag).toBe("wx");
      expect(mockRename).toHaveBeenCalledOnce();
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

  // -------------------------------------------------------------------------
  // symlink safety (#26)
  // -------------------------------------------------------------------------

  describe("symlink safety", () => {
    // #26: the .tmp is created exclusively (O_CREAT|O_EXCL via flag "wx") and
    // any stale .tmp is unlinked first, so a pre-placed .tmp symlink cannot
    // redirect the write. Pre-fix code used a plain writeFile (no flag).
    it("writes .tmp exclusively and unlinks any stale .tmp first", async () => {
      // No existing config → no .bak, so the only writeFile is the .tmp.
      const enoent = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      mockReadFile.mockRejectedValue(enoent);
      const entry: McpServerEntry = { command: "npx", args: [] };
      await adapter.addServer(CONFIG_PATH, "srv", entry);

      // Stale .tmp removed before the exclusive create.
      expect(mockUnlink).toHaveBeenCalledWith(`${CONFIG_PATH}.tmp`);
      const [tmpPath, , tmpOpts] = mockWriteFile.mock.calls[0] as [
        string,
        string,
        { flag?: string },
      ];
      expect(tmpPath).toBe(`${CONFIG_PATH}.tmp`);
      expect(tmpOpts.flag).toBe("wx");
    });

    // #26: refuse to write through a symlinked config path (lstat check).
    it("refuses to write when the config path itself is a symlink", async () => {
      mockReadFile.mockResolvedValue(makeConfig({ old: { command: "uvx", args: [] } }));
      mockLstat.mockResolvedValue({ isSymbolicLink: () => true });

      const entry: McpServerEntry = { command: "npx", args: [] };
      await expect(adapter.addServer(CONFIG_PATH, "srv", entry)).rejects.toThrow(/symlink/i);

      // Nothing was written or renamed through the symlink.
      expect(mockWriteFile).not.toHaveBeenCalled();
      expect(mockRename).not.toHaveBeenCalled();
    });
  });
});
