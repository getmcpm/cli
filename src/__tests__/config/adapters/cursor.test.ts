/**
 * Tests for src/config/adapters/cursor.ts
 *
 * Cursor uses root key `mcpServers` — same as Claude Desktop.
 * Tests focus on cursor-specific clientId and any structural differences.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn(),
  mkdir: vi.fn(),
}));

import { readFile, writeFile, rename } from "fs/promises";
import { CursorAdapter } from "../../../config/adapters/cursor.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/.cursor/mcp.json";

function makeConfig(servers: Record<string, McpServerEntry>) {
  return JSON.stringify({ mcpServers: servers });
}

describe("CursorAdapter", () => {
  const adapter = new CursorAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
  });

  it("has clientId = cursor", () => {
    expect(adapter.clientId).toBe("cursor");
  });

  it("reads from mcpServers key", async () => {
    const entry: McpServerEntry = { url: "http://localhost:3000" };
    mockReadFile.mockResolvedValue(makeConfig({ "http-srv": entry }));
    const result = await adapter.read(CONFIG_PATH);
    expect(result).toEqual({ "http-srv": entry });
  });

  it("adds a server using mcpServers key", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    const entry: McpServerEntry = { url: "http://localhost:4000" };
    await adapter.addServer(CONFIG_PATH, "remote-srv", entry);

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.mcpServers["remote-srv"]).toEqual(entry);
  });

  it("preserves http entry fields (url + headers)", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    const entry: McpServerEntry = {
      url: "https://api.example.com/mcp",
      headers: { Authorization: "Bearer token123" },
    };
    await adapter.addServer(CONFIG_PATH, "api-srv", entry);

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.mcpServers["api-srv"].url).toBe(
      "https://api.example.com/mcp"
    );
    expect(written.mcpServers["api-srv"].headers).toEqual({
      Authorization: "Bearer token123",
    });
  });

  it("throws if server already exists", async () => {
    const entry: McpServerEntry = { command: "npx", args: [] };
    mockReadFile.mockResolvedValue(makeConfig({ existing: entry }));
    await expect(
      adapter.addServer(CONFIG_PATH, "existing", entry)
    ).rejects.toThrow(/already exists/i);
  });

  it("removes server using mcpServers key", async () => {
    const entry: McpServerEntry = { command: "npx", args: [] };
    mockReadFile.mockResolvedValue(
      makeConfig({ "rm-me": entry, keep: entry })
    );
    await adapter.removeServer(CONFIG_PATH, "rm-me");

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.mcpServers["rm-me"]).toBeUndefined();
    expect(written.mcpServers["keep"]).toEqual(entry);
  });

  it("throws removing a server that does not exist", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    await expect(
      adapter.removeServer(CONFIG_PATH, "ghost")
    ).rejects.toThrow(/not found/i);
  });

  it("uses atomic write (rename from .tmp)", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    await adapter.addServer(CONFIG_PATH, "srv", { command: "npx", args: [] });
    expect(mockRename).toHaveBeenCalledOnce();
    const [tmpPath] = mockRename.mock.calls[0] as [string, string];
    expect(tmpPath).toMatch(/\.tmp$/);
  });
});
