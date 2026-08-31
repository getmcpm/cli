/**
 * #23 — BaseAdapter.read() used to cast raw[rootKey] straight to
 * Record<string, McpServerEntry> with only a container-level object/array
 * check. A per-entry shape mismatch (e.g. `args` as a string instead of an
 * array) passed through untouched and could silently corrupt a downstream
 * transform that spreads `args` (guard/wrap.ts iterates a string char-by-char).
 *
 * These tests exercise read() through a concrete adapter (BaseAdapter itself
 * is abstract) — the validation lives in the shared base, so any adapter
 * proves it.
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

import { readFile, writeFile, rename, mkdir, unlink, lstat } from "fs/promises";
import { ClaudeDesktopAdapter } from "../../../config/adapters/claude-desktop.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;
const mockUnlink = unlink as ReturnType<typeof vi.fn>;
const mockLstat = lstat as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/claude_desktop_config.json";

describe("BaseAdapter.read() — per-entry shape validation (#23)", () => {
  const adapter = new ClaudeDesktopAdapter();
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.resetAllMocks();
    mockLstat.mockResolvedValue({ isSymbolicLink: () => false });
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  it("drops an entry whose args is a string instead of an array, and keeps well-formed siblings", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        mcpServers: {
          good: { command: "npx", args: ["-y", "server"] },
          // Hand-edited/IDE-mangled config: args should be string[].
          bad: { command: "npx", args: "bad" },
        },
      }),
    );
    const result = await adapter.read(CONFIG_PATH);
    expect(result).toEqual({ good: { command: "npx", args: ["-y", "server"] } });
    expect(result.bad).toBeUndefined();
  });

  it("warns to stderr naming the server and client when dropping a malformed entry", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({ mcpServers: { bad: { args: "bad" } } }),
    );
    await adapter.read(CONFIG_PATH);
    const written = stderrSpy.mock.calls.flat().join("");
    expect(written).toContain("bad");
    expect(written).toContain("claude-desktop");
  });

  it("drops an entry that is not an object at all (e.g. a bare string)", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({ mcpServers: { ghost: "not-an-object" } }),
    );
    const result = await adapter.read(CONFIG_PATH);
    expect(result).toEqual({});
  });

  it("preserves unrecognized extra fields on an otherwise well-formed entry", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        mcpServers: { srv: { command: "npx", args: [], type: "stdio" } },
      }),
    );
    const result = await adapter.read(CONFIG_PATH);
    expect(result.srv).toEqual({ command: "npx", args: [], type: "stdio" });
  });

  it("still accepts a well-formed url/headers HTTP-transport entry", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        mcpServers: { remote: { url: "https://api.example.com/mcp", headers: { Authorization: "Bearer x" } } },
      }),
    );
    const result = await adapter.read(CONFIG_PATH);
    expect(result.remote).toEqual({
      url: "https://api.example.com/mcp",
      headers: { Authorization: "Bearer x" },
    });
  });
});

// #23 follow-up (adversarial review, opus pass): setServerDisabled() used to
// spread `existing[name]` unconditionally. For a raw entry that is not a
// plain object (e.g. a bare string — exactly what read() now drops above),
// the spread iterates its characters ({"0":"a","1":"b",...}), corrupting the
// entry on disk. This is the entry point commands/toggle.ts's malformed-entry
// follow-up routes through, so it must fail loudly instead of corrupting.
describe("BaseAdapter.setServerDisabled() — rejects a non-object raw entry (#23)", () => {
  const adapter = new ClaudeDesktopAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockLstat.mockResolvedValue({ isSymbolicLink: () => false });
    mockMkdir.mockResolvedValue(undefined);
    mockUnlink.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
  });

  it("throws instead of corrupting a bare-string entry into char-indexed keys", async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ mcpServers: { ghost: "not-an-object" } }));

    await expect(adapter.setServerDisabled(CONFIG_PATH, "ghost", true)).rejects.toThrow(
      /not a valid object/,
    );
    // The corrupting shape this guards against: spreading a string produces
    // numeric-string keys ("0", "1", ...). Confirm no write was attempted at
    // all — fail closed, not "fail after partially writing".
    expect(mockWriteFile).not.toHaveBeenCalledWith(
      expect.stringContaining(".tmp"),
      expect.anything(),
      expect.anything(),
    );
  });

  it("still disables a well-formed entry, preserving its other fields", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({ mcpServers: { srv: { command: "npx", args: ["-y", "x"] } } }),
    );

    await adapter.setServerDisabled(CONFIG_PATH, "srv", true);

    const tmpWrite = mockWriteFile.mock.calls.find(
      (call) => typeof call[0] === "string" && call[0].endsWith(".tmp"),
    );
    const written = JSON.parse(tmpWrite![1] as string);
    expect(written.mcpServers.srv).toEqual({ command: "npx", args: ["-y", "x"], disabled: true });
  });

  it("throws for an array-valued entry too (Array.isArray guard, not just typeof)", async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ mcpServers: { ghost: ["a", "b"] } }));

    await expect(adapter.setServerDisabled(CONFIG_PATH, "ghost", true)).rejects.toThrow(
      /not a valid object/,
    );
  });
});
