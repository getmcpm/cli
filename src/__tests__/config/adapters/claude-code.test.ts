/**
 * Tests for src/config/adapters/claude-code.ts
 *
 * ClaudeCodeAdapter is a rootKey-only subclass of BaseAdapter (identical I/O to
 * ClaudeDesktopAdapter, which is exhaustively covered in claude-desktop.test.ts).
 * We assert only what is specific to this adapter: its clientId, and the one
 * behavior that matters most for `~/.claude.json` — that a write into the
 * `mcpServers` map leaves every unrelated Claude Code key (projects, oauthAccount,
 * numStartups, …) untouched. `~/.claude.json` holds a lot of unrelated state, so a
 * naive rewrite that dropped sibling keys would be data loss.
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
import { ClaudeCodeAdapter } from "../../../config/adapters/claude-code.js";
import type { McpServerEntry } from "../../../config/adapters/index.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;
const mockLstat = lstat as ReturnType<typeof vi.fn>;
const mockUnlink = unlink as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/home/.claude.json";

describe("ClaudeCodeAdapter", () => {
  const adapter = new ClaudeCodeAdapter();

  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
    mockMkdir.mockResolvedValue(undefined);
    mockLstat.mockResolvedValue({ isSymbolicLink: () => false });
    mockUnlink.mockResolvedValue(undefined);
  });

  it("has clientId = claude-code", () => {
    expect(adapter.clientId).toBe("claude-code");
  });

  it("reads servers from the mcpServers key", async () => {
    const entry: McpServerEntry = { command: "npx", args: ["-y", "srv"] };
    mockReadFile.mockResolvedValue(JSON.stringify({ mcpServers: { srv: entry } }));
    expect(await adapter.read(CONFIG_PATH)).toEqual({ srv: entry });
  });

  it("preserves unrelated Claude Code keys when adding a server", async () => {
    // A realistic ~/.claude.json: mcpServers plus lots of unrelated state.
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        numStartups: 42,
        oauthAccount: { emailAddress: "user@example.com" },
        projects: { "/some/path": { mcpServers: { local: { command: "x" } } } },
        mcpServers: { existing: { command: "uvx", args: ["existing"] } },
      })
    );
    const entry: McpServerEntry = { command: "npx", args: ["-y", "new"] };
    await adapter.addServer(CONFIG_PATH, "new-srv", entry);

    // .bak is calls[0], .tmp (the new content) is calls[1].
    const written = JSON.parse(mockWriteFile.mock.calls[1][1] as string);
    // Every unrelated top-level key survives the write untouched.
    expect(written.numStartups).toBe(42);
    expect(written.oauthAccount).toEqual({ emailAddress: "user@example.com" });
    expect(written.projects).toEqual({
      "/some/path": { mcpServers: { local: { command: "x" } } },
    });
    // Both the pre-existing and the new user-global server are present.
    expect(written.mcpServers.existing).toEqual({ command: "uvx", args: ["existing"] });
    expect(written.mcpServers["new-srv"]).toEqual(entry);
    expect(mockRename).toHaveBeenCalledOnce();
  });
});
