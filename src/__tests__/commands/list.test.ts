/**
 * Tests for src/commands/list.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - detectInstalledClients, config adapters, and getConfigPath are all injected.
 * - output() is injected to capture stdout.
 * - Test handler functions directly — not Commander parsing.
 * - This command is READ-ONLY — never calls registry API.
 * - Cover: single/multi client, --client filter, --json flag, no servers installed.
 */

import { describe, it, expect, vi } from "vitest";
import type { McpServerEntry } from "../../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CLAUDE_SERVERS: Record<string, McpServerEntry> = {
  "filesystem": { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
  "github": { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: "secret" } },
};

const CURSOR_SERVERS: Record<string, McpServerEntry> = {
  "http-tool": { url: "https://api.example.com/mcp" },
};

const VSCODE_SERVERS: Record<string, McpServerEntry> = {
  "python-server": { command: "uvx", args: ["python-mcp-server"] },
};

function makeMockAdapter(servers: Record<string, McpServerEntry> = {}) {
  return {
    read: vi.fn().mockResolvedValue(servers),
    read: vi.fn().mockResolvedValue(servers),
    addServer: vi.fn(),
    removeServer: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Import after fixture setup
// ---------------------------------------------------------------------------

import { handleList } from "../../commands/list.js";
import type { ListOptions, ListDeps } from "../../commands/list.js";

// ---------------------------------------------------------------------------
// handleList — happy path with multiple clients
// ---------------------------------------------------------------------------

describe("handleList — multiple clients", () => {
  it("calls listServers for each detected client", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const cursorAdapter = makeMockAdapter(CURSOR_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop", "cursor"]);
    const getAdapter = vi.fn()
      .mockReturnValueOnce(claudeAdapter)
      .mockReturnValueOnce(cursorAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    const deps: ListDeps = { detectClients, getAdapter, getPath, output };
    await handleList({}, deps);

    expect(claudeAdapter.read).toHaveBeenCalledWith("/fake/path/config.json");
    expect(cursorAdapter.read).toHaveBeenCalledWith("/fake/path/config.json");
  });

  it("displays Client and Server Name columns", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("Client");
    expect(fullOutput).toContain("Server Name");
  });

  it("displays the client ID in the table", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("claude-desktop");
  });

  it("displays server names for each client", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("filesystem");
    expect(fullOutput).toContain("github");
  });

  it("displays command for stdio servers", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("npx");
  });

  it("displays URL for HTTP servers", async () => {
    const cursorAdapter = makeMockAdapter(CURSOR_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["cursor"]);
    const getAdapter = vi.fn().mockReturnValue(cursorAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("https://api.example.com/mcp");
  });

  it("displays servers from multiple clients", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const cursorAdapter = makeMockAdapter(CURSOR_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop", "cursor"]);
    const getAdapter = vi.fn()
      .mockReturnValueOnce(claudeAdapter)
      .mockReturnValueOnce(cursorAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("claude-desktop");
    expect(fullOutput).toContain("cursor");
    expect(fullOutput).toContain("filesystem");
    expect(fullOutput).toContain("http-tool");
  });
});

// ---------------------------------------------------------------------------
// handleList — no clients installed
// ---------------------------------------------------------------------------

describe("handleList — no clients installed", () => {
  it("outputs helpful message when no clients are detected", async () => {
    const detectClients = vi.fn().mockResolvedValue([]);
    const getAdapter = vi.fn();
    const getPath = vi.fn();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("No MCP servers installed");
  });

  it("includes search suggestion in empty message", async () => {
    const detectClients = vi.fn().mockResolvedValue([]);
    const getAdapter = vi.fn();
    const getPath = vi.fn();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("mcpm search");
  });

  it("does NOT output a table when no clients are installed", async () => {
    const detectClients = vi.fn().mockResolvedValue([]);
    const getAdapter = vi.fn();
    const getPath = vi.fn();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).not.toContain("Client");
  });
});

// ---------------------------------------------------------------------------
// handleList — no servers installed in detected clients
// ---------------------------------------------------------------------------

describe("handleList — clients detected but no servers", () => {
  it("outputs helpful message when all clients have empty server lists", async () => {
    const emptyAdapter = makeMockAdapter({});
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(emptyAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("No MCP servers installed");
  });
});

// ---------------------------------------------------------------------------
// handleList — --client filter
// ---------------------------------------------------------------------------

describe("handleList — --client filter", () => {
  it("only queries the specified client when --client is provided", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const cursorAdapter = makeMockAdapter(CURSOR_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop", "cursor"]);
    const getAdapter = vi.fn()
      .mockImplementation((clientId: string) => {
        if (clientId === "claude-desktop") return claudeAdapter;
        return cursorAdapter;
      });
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ client: "claude-desktop" }, { detectClients, getAdapter, getPath, output });

    expect(claudeAdapter.read).toHaveBeenCalled();
    expect(cursorAdapter.read).not.toHaveBeenCalled();
  });

  it("only shows servers from the specified client", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const cursorAdapter = makeMockAdapter(CURSOR_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop", "cursor"]);
    const getAdapter = vi.fn()
      .mockImplementation((clientId: string) => {
        if (clientId === "claude-desktop") return claudeAdapter;
        return cursorAdapter;
      });
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ client: "claude-desktop" }, { detectClients, getAdapter, getPath, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("filesystem");
    expect(fullOutput).not.toContain("http-tool");
  });

  it("shows empty message when filtered client has no servers", async () => {
    const emptyAdapter = makeMockAdapter({});
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(emptyAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ client: "claude-desktop" }, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("No MCP servers installed");
  });

  it("shows empty message when --client specifies a client not installed", async () => {
    const detectClients = vi.fn().mockResolvedValue(["cursor"]);
    const cursorAdapter = makeMockAdapter(CURSOR_SERVERS);
    const getAdapter = vi.fn().mockReturnValue(cursorAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    // Filter for claude-desktop, which is not in detected clients
    await handleList({ client: "claude-desktop" }, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("No MCP servers installed");
  });
});

// ---------------------------------------------------------------------------
// handleList — --json flag
// ---------------------------------------------------------------------------

describe("handleList — --json flag", () => {
  it("outputs valid JSON when --json is passed", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ json: true }, { detectClients, getAdapter, getPath, output });

    const parsed = JSON.parse(lines.join("\n"));
    expect(Array.isArray(parsed)).toBe(true);
  });

  it("JSON output includes client and serverName fields", async () => {
    const claudeAdapter = makeMockAdapter({ "filesystem": CLAUDE_SERVERS["filesystem"]! });
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ json: true }, { detectClients, getAdapter, getPath, output });

    const parsed = JSON.parse(lines.join("\n")) as Array<{ client: string; serverName: string }>;
    expect(parsed[0].client).toBe("claude-desktop");
    expect(parsed[0].serverName).toBe("filesystem");
  });

  it("JSON output includes entry details (command/url)", async () => {
    const claudeAdapter = makeMockAdapter({ "filesystem": CLAUDE_SERVERS["filesystem"]! });
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ json: true }, { detectClients, getAdapter, getPath, output });

    const parsed = JSON.parse(lines.join("\n")) as Array<{ entry: { command?: string } }>;
    expect(parsed[0].entry.command).toBe("npx");
  });

  it("JSON output is an empty array when no servers installed", async () => {
    const detectClients = vi.fn().mockResolvedValue([]);
    const getAdapter = vi.fn();
    const getPath = vi.fn();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ json: true }, { detectClients, getAdapter, getPath, output });

    const parsed = JSON.parse(lines.join("\n"));
    expect(parsed).toEqual([]);
  });

  it("does NOT output table borders in JSON mode", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({ json: true }, { detectClients, getAdapter, getPath, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).not.toContain("─");
    expect(fullOutput).not.toContain("│");
  });
});

// ---------------------------------------------------------------------------
// handleList — read-only assertion
// ---------------------------------------------------------------------------

describe("handleList — read-only", () => {
  it("never calls addServer on any adapter", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const output = vi.fn();

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(claudeAdapter.addServer).not.toHaveBeenCalled();
  });

  it("never calls removeServer on any adapter", async () => {
    const claudeAdapter = makeMockAdapter(CLAUDE_SERVERS);
    const detectClients = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapter = vi.fn().mockReturnValue(claudeAdapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/config.json");
    const output = vi.fn();

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(claudeAdapter.removeServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// handleList — Command/URL display column
// ---------------------------------------------------------------------------

describe("handleList — Command/URL column", () => {
  it("shows command + args for stdio entries", async () => {
    const adapter = makeMockAdapter({
      "my-server": { command: "uvx", args: ["my-mcp"] },
    });
    const detectClients = vi.fn().mockResolvedValue(["vscode"]);
    const getAdapter = vi.fn().mockReturnValue(adapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/mcp.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("uvx");
  });

  it("shows URL for HTTP entries", async () => {
    const adapter = makeMockAdapter({
      "remote-tool": { url: "https://tools.example.com/mcp" },
    });
    const detectClients = vi.fn().mockResolvedValue(["cursor"]);
    const getAdapter = vi.fn().mockReturnValue(adapter);
    const getPath = vi.fn().mockReturnValue("/fake/path/mcp.json");
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleList({}, { detectClients, getAdapter, getPath, output });

    expect(lines.join("\n")).toContain("https://tools.example.com/mcp");
  });
});
