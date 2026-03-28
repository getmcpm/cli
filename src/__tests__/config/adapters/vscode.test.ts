/**
 * Tests for src/config/adapters/vscode.ts
 *
 * VS Code uses root key `servers` (NOT mcpServers).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn(),
  mkdir: vi.fn(),
}));

import { readFile, writeFile, rename } from "fs/promises";
import { VSCodeAdapter } from "../../../config/adapters/vscode.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/Code/User/mcp.json";

function makeConfig(servers: Record<string, McpServerEntry>) {
  return JSON.stringify({ servers });
}

describe("VSCodeAdapter", () => {
  const adapter = new VSCodeAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
  });

  it("has clientId = vscode", () => {
    expect(adapter.clientId).toBe("vscode");
  });

  it("reads from 'servers' key (not mcpServers)", async () => {
    const entry: McpServerEntry = { command: "npx", args: ["-y", "vscode-mcp"] };
    mockReadFile.mockResolvedValue(makeConfig({ "vscode-mcp": entry }));
    const result = await adapter.read(CONFIG_PATH);
    expect(result).toEqual({ "vscode-mcp": entry });
  });

  it("does NOT read from mcpServers key", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({ mcpServers: { wrong: { command: "x", args: [] } } })
    );
    const result = await adapter.read(CONFIG_PATH);
    // servers key is absent, so empty
    expect(result).toEqual({});
  });

  it("writes into 'servers' key", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    const entry: McpServerEntry = { command: "uvx", args: ["some-py-server"] };
    await adapter.addServer(CONFIG_PATH, "py-srv", entry);

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.servers["py-srv"]).toEqual(entry);
    expect(written.mcpServers).toBeUndefined();
  });

  it("preserves extra top-level keys in VS Code config", async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({ servers: {}, inputs: [], version: 2 })
    );
    await adapter.addServer(CONFIG_PATH, "srv", { command: "npx", args: [] });
    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.inputs).toEqual([]);
    expect(written.version).toBe(2);
  });

  it("creates file with 'servers' key when file does not exist", async () => {
    const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    mockReadFile.mockRejectedValue(err);
    await adapter.addServer(CONFIG_PATH, "srv", { command: "npx", args: [] });
    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.servers).toBeDefined();
    expect(written.mcpServers).toBeUndefined();
  });

  it("throws if server already exists", async () => {
    mockReadFile.mockResolvedValue(
      makeConfig({ existing: { command: "npx", args: [] } })
    );
    await expect(
      adapter.addServer(CONFIG_PATH, "existing", { command: "npx", args: [] })
    ).rejects.toThrow(/already exists/i);
  });

  it("removes from 'servers' key atomically", async () => {
    mockReadFile.mockResolvedValue(
      makeConfig({ rm: { command: "npx", args: [] }, keep: { command: "uvx", args: [] } })
    );
    await adapter.removeServer(CONFIG_PATH, "rm");

    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.servers["rm"]).toBeUndefined();
    expect(written.servers["keep"]).toBeDefined();
    expect(mockRename).toHaveBeenCalledOnce();
  });

  it("throws removing a server not found", async () => {
    mockReadFile.mockResolvedValue(makeConfig({}));
    await expect(
      adapter.removeServer(CONFIG_PATH, "ghost")
    ).rejects.toThrow(/not found/i);
  });
});
