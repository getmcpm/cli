/**
 * Tests for src/config/adapters/windsurf.ts
 *
 * Windsurf uses root key `mcpServers`.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn(),
  mkdir: vi.fn(),
}));

import { readFile, writeFile, rename } from "fs/promises";
import { WindsurfAdapter } from "../../../config/adapters/windsurf.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/.codeium/windsurf/mcp_config.json";

function makeConfig(servers: Record<string, McpServerEntry>) {
  return JSON.stringify({ mcpServers: servers });
}

describe("WindsurfAdapter", () => {
  const adapter = new WindsurfAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
  });

  it("has clientId = windsurf", () => {
    expect(adapter.clientId).toBe("windsurf");
  });

  it("reads from mcpServers key", async () => {
    const entry: McpServerEntry = { command: "docker", args: ["run", "my-image"] };
    mockReadFile.mockResolvedValue(makeConfig({ "docker-srv": entry }));
    const result = await adapter.read(CONFIG_PATH);
    expect(result).toEqual({ "docker-srv": entry });
  });

  it("returns empty when mcpServers is absent", async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({}));
    const result = await adapter.read(CONFIG_PATH);
    expect(result).toEqual({});
  });

  it("adds a server into mcpServers", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    const entry: McpServerEntry = {
      command: "npx",
      args: ["-y", "windsurf-mcp"],
      env: { SOME_VAR: "value" },
    };
    await adapter.addServer(CONFIG_PATH, "ws-srv", entry);

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.mcpServers["ws-srv"]).toEqual(entry);
  });

  it("throws if server already exists", async () => {
    mockReadFile.mockResolvedValue(
      makeConfig({ dup: { command: "npx", args: [] } })
    );
    await expect(
      adapter.addServer(CONFIG_PATH, "dup", { command: "npx", args: [] })
    ).rejects.toThrow(/already exists/i);
  });

  it("removes from mcpServers atomically", async () => {
    const entry: McpServerEntry = { command: "npx", args: [] };
    mockReadFile.mockResolvedValue(makeConfig({ del: entry, stay: entry }));
    await adapter.removeServer(CONFIG_PATH, "del");

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.mcpServers["del"]).toBeUndefined();
    expect(written.mcpServers["stay"]).toEqual(entry);
    expect(mockRename).toHaveBeenCalledOnce();
  });

  it("throws removing a server not found", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    await expect(
      adapter.removeServer(CONFIG_PATH, "missing")
    ).rejects.toThrow(/not found/i);
  });

  it("preserves unrelated top-level keys", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({ mcpServers: {}, extraSetting: true })
    );
    await adapter.addServer(CONFIG_PATH, "srv", { command: "npx", args: [] });
    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.extraSetting).toBe(true);
  });

  it("uses atomic write pattern (.tmp + rename)", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    await adapter.addServer(CONFIG_PATH, "srv", { command: "npx", args: [] });
    expect(mockRename).toHaveBeenCalledOnce();
    const [tmpPath, finalPath] = mockRename.mock.calls[0] as [string, string];
    expect(tmpPath).toMatch(/\.tmp$/);
    expect(finalPath).toBe(CONFIG_PATH);
  });
});
