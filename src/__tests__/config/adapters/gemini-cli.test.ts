/**
 * Tests for src/config/adapters/gemini-cli.ts
 *
 * GeminiCliAdapter is a rootKey-only subclass of BaseAdapter (identical I/O to
 * ClaudeDesktopAdapter, which is exhaustively covered in claude-desktop.test.ts).
 * We assert only what is specific to this adapter: its clientId, and the one
 * behavior that matters most for `~/.gemini/settings.json` — that a write into the
 * `mcpServers` map leaves every unrelated Gemini CLI setting (theme, auth, tool
 * config, …) untouched. settings.json holds a lot of unrelated state, so a naive
 * rewrite that dropped sibling keys would be data loss.
 * ponytail: no full I/O suite — BaseAdapter is already covered; this pins the
 * subclass + the sibling-preservation invariant unique to this file.
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
import { GeminiCliAdapter } from "../../../config/adapters/gemini-cli.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;
const mockLstat = lstat as ReturnType<typeof vi.fn>;
const mockUnlink = unlink as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/home/.gemini/settings.json";

describe("GeminiCliAdapter", () => {
  const adapter = new GeminiCliAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
    mockMkdir.mockResolvedValue(undefined);
    mockLstat.mockResolvedValue({ isSymbolicLink: () => false });
    mockUnlink.mockResolvedValue(undefined);
  });

  it("has clientId = gemini-cli", () => {
    expect(adapter.clientId).toBe("gemini-cli");
  });

  it("reads servers from the mcpServers key", async () => {
    const entry: McpServerEntry = { command: "npx", args: ["-y", "srv"] };
    mockReadFile.mockResolvedValue(JSON.stringify({ mcpServers: { srv: entry } }));
    expect(await adapter.read(CONFIG_PATH)).toEqual({ srv: entry });
  });

  it("preserves unrelated Gemini CLI settings when adding a server", async () => {
    // A realistic ~/.gemini/settings.json: mcpServers plus unrelated settings.
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        theme: "GitHub",
        selectedAuthType: "oauth-personal",
        toolCall: { timeout: 30000 },
        mcpServers: { existing: { command: "uvx", args: ["existing"], trust: false } },
      })
    );
    const entry: McpServerEntry = { command: "npx", args: ["-y", "new"] };
    await adapter.addServer(CONFIG_PATH, "new-srv", entry);

    // .bak is calls[0], .tmp (the new content) is calls[1].
    const written = JSON.parse(mockWriteFile.mock.calls[1][1] as string);
    // Every unrelated top-level key survives the write untouched.
    expect(written.theme).toBe("GitHub");
    expect(written.selectedAuthType).toBe("oauth-personal");
    expect(written.toolCall).toEqual({ timeout: 30000 });
    // Both the pre-existing server (with its extra `trust` field) and the new one survive.
    expect(written.mcpServers.existing).toEqual({
      command: "uvx",
      args: ["existing"],
      trust: false,
    });
    expect(written.mcpServers["new-srv"]).toEqual(entry);
    expect(mockRename).toHaveBeenCalledOnce();
  });
});
