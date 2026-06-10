/**
 * Tests for src/commands/import.ts
 *
 * TDD — RED phase: all tests written before implementation.
 * All external dependencies (detectClients, adapters, store) are mocked via injectable deps.
 *
 * Coverage target: 90%+
 *
 * Test scenarios:
 * - handleImport: servers found across multiple clients
 * - handleImport: no servers found
 * - handleImport: some servers already tracked (skipped)
 * - handleImport: --yes flag skips confirmation
 * - handleImport: --client filter limits to one client
 * - handleImport: user declines confirmation
 * - handleImport: all servers already tracked
 * - checkFirstRun: store exists → returns early (no output)
 * - checkFirstRun: store doesn't exist and servers found → shows hint
 * - checkFirstRun: store doesn't exist and no servers → silent (no output)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import type { InstalledServer } from "../../store/servers.js";
import { scanTier1 } from "../../scanner/tier1.js";
import { computeTrustScore } from "../../scanner/trust-score.js";

// ---------------------------------------------------------------------------
// Import under test (will fail until implementation exists — RED phase)
// ---------------------------------------------------------------------------

import {
  handleImport,
  checkFirstRun,
  type ImportDeps,
  type ImportOptions,
} from "../../commands/import.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeAdapter(
  clientId: ClientId,
  servers: Record<string, McpServerEntry> = {}
): ConfigAdapter {
  return {
    clientId,
    read: vi.fn().mockResolvedValue(servers),
    addServer: vi.fn(),
    removeServer: vi.fn(),
    read: vi.fn().mockResolvedValue(servers),
  };
}

function makeInstalledServer(name: string, clients: ClientId[] = ["claude-desktop"]): InstalledServer {
  return {
    name,
    version: "unknown",
    clients,
    installedAt: "2026-01-01T00:00:00.000Z",
  };
}

function makeDeps(overrides: Partial<ImportDeps> = {}): ImportDeps {
  return {
    detectClients: vi.fn().mockResolvedValue([]),
    getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop")),
    getConfigPath: vi.fn().mockReturnValue("/fake/path/config.json"),
    getInstalledServers: vi.fn().mockResolvedValue([]),
    addToStore: vi.fn().mockResolvedValue(undefined),
    storeExists: vi.fn().mockResolvedValue(false),
    confirm: vi.fn().mockResolvedValue(true),
    output: vi.fn(),
    // #23: use the real (pure) scanner + trust-score functions by default so
    // tests exercise the actual assessment path, not a stub.
    scanTier1,
    computeTrustScore,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// handleImport — no servers found
// ---------------------------------------------------------------------------

describe("handleImport — no servers found", () => {
  it("outputs a message when no clients are detected", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue([]),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    expect(lines.join("\n")).toMatch(/no existing mcp servers found/i);
  });

  it("does not prompt for confirmation when no servers found", async () => {
    const confirmMock = vi.fn().mockResolvedValue(true);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", {})),
      confirm: confirmMock,
    });
    await handleImport({}, deps);
    expect(confirmMock).not.toHaveBeenCalled();
  });

  it("does not call addToStore when no servers found", async () => {
    const addToStoreMock = vi.fn();
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", {})),
      addToStore: addToStoreMock,
    });
    await handleImport({}, deps);
    expect(addToStoreMock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// handleImport — servers found, user confirms
// ---------------------------------------------------------------------------

describe("handleImport — servers found, user confirms", () => {
  const claudeServers: Record<string, McpServerEntry> = {
    "filesystem": { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] },
    "github": { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] },
  };
  const cursorServers: Record<string, McpServerEntry> = {
    "postgres": { command: "npx", args: ["-y", "@modelcontextprotocol/server-postgres"] },
  };

  function makeMultiClientDeps(overrides: Partial<ImportDeps> = {}): ImportDeps {
    const claudeAdapter = makeAdapter("claude-desktop", claudeServers);
    const cursorAdapter = makeAdapter("cursor", cursorServers);

    return makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) => {
        if (clientId === "claude-desktop") return claudeAdapter;
        if (clientId === "cursor") return cursorAdapter;
        return makeAdapter(clientId, {});
      }),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      ...overrides,
    });
  }

  it("displays a table with Client, Server Name, Command/URL columns", async () => {
    const lines: string[] = [];
    const deps = makeMultiClientDeps({ output: (t) => lines.push(t) });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/client/i);
    expect(out).toMatch(/server/i);
  });

  it("shows servers from all detected clients in the table", async () => {
    const lines: string[] = [];
    const deps = makeMultiClientDeps({ output: (t) => lines.push(t) });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toContain("filesystem");
    expect(out).toContain("github");
    expect(out).toContain("postgres");
  });

  it("shows client names in output", async () => {
    const lines: string[] = [];
    const deps = makeMultiClientDeps({ output: (t) => lines.push(t) });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/claude-desktop|cursor/i);
  });

  it("prompts user with count of servers to import", async () => {
    const confirmMock = vi.fn().mockResolvedValue(true);
    const deps = makeMultiClientDeps({ confirm: confirmMock });
    await handleImport({}, deps);
    expect(confirmMock).toHaveBeenCalledOnce();
    const promptMessage: string = confirmMock.mock.calls[0][0];
    expect(promptMessage).toMatch(/3/);
    expect(promptMessage).toMatch(/import/i);
  });

  it("calls addToStore for each discovered server when confirmed", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeMultiClientDeps({ addToStore: addToStoreMock });
    await handleImport({}, deps);
    expect(addToStoreMock).toHaveBeenCalledTimes(3);
  });

  it("calls addToStore with correct InstalledServer shape", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeMultiClientDeps({ addToStore: addToStoreMock });
    await handleImport({}, deps);
    const firstCall: InstalledServer = addToStoreMock.mock.calls[0][0];
    expect(firstCall).toHaveProperty("name");
    expect(firstCall).toHaveProperty("version");
    expect(firstCall).toHaveProperty("clients");
    expect(firstCall).toHaveProperty("installedAt");
    expect(Array.isArray(firstCall.clients)).toBe(true);
  });

  it("outputs summary: imported N, skipped M", async () => {
    const lines: string[] = [];
    const deps = makeMultiClientDeps({ output: (t) => lines.push(t) });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/imported 3/i);
    expect(out).toMatch(/skipped 0/i);
  });
});

// ---------------------------------------------------------------------------
// handleImport — some servers already tracked (skipped)
// ---------------------------------------------------------------------------

describe("handleImport — some already tracked", () => {
  const claudeServers: Record<string, McpServerEntry> = {
    "filesystem": { command: "npx", args: [] },
    "github": { command: "npx", args: [] },
    "postgres": { command: "npx", args: [] },
  };

  it("skips servers that are already in the store", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", claudeServers)),
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer("filesystem"),
        makeInstalledServer("github"),
      ]),
      addToStore: addToStoreMock,
      confirm: vi.fn().mockResolvedValue(true),
    });
    await handleImport({}, deps);
    // Only "postgres" is new
    expect(addToStoreMock).toHaveBeenCalledTimes(1);
    expect(addToStoreMock.mock.calls[0][0].name).toBe("postgres");
  });

  it("reports correct imported and skipped counts", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", claudeServers)),
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer("filesystem"),
        makeInstalledServer("github"),
      ]),
      addToStore: vi.fn().mockResolvedValue(undefined),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/imported 1/i);
    expect(out).toMatch(/skipped 2/i);
  });

  it("includes already-tracked servers in the displayed table", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", claudeServers)),
      getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer("filesystem")]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    // All servers should appear in the table before import
    expect(out).toContain("filesystem");
    expect(out).toContain("github");
  });
});

// ---------------------------------------------------------------------------
// handleImport — all servers already tracked
// ---------------------------------------------------------------------------

describe("handleImport — all already tracked", () => {
  it("still prompts when some servers exist but are all already tracked", async () => {
    const confirmMock = vi.fn().mockResolvedValue(true);
    const claudeServers: Record<string, McpServerEntry> = {
      "filesystem": { command: "npx", args: [] },
    };
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", claudeServers)),
      getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer("filesystem")]),
      confirm: confirmMock,
    });
    await handleImport({}, deps);
    // Table is shown, then prompt, then "imported 0, skipped 1"
    expect(confirmMock).toHaveBeenCalledOnce();
  });

  it("reports imported 0 skipped N when all are already tracked", async () => {
    const lines: string[] = [];
    const claudeServers: Record<string, McpServerEntry> = {
      "filesystem": { command: "npx", args: [] },
    };
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", claudeServers)),
      getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer("filesystem")]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/imported 0/i);
    expect(out).toMatch(/skipped 1/i);
  });
});

// ---------------------------------------------------------------------------
// handleImport — user declines confirmation
// ---------------------------------------------------------------------------

describe("handleImport — user declines confirmation", () => {
  it("does not call addToStore when user declines", async () => {
    const addToStoreMock = vi.fn();
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(false),
      addToStore: addToStoreMock,
    });
    await handleImport({}, deps);
    expect(addToStoreMock).not.toHaveBeenCalled();
  });

  it("outputs a cancellation message when user declines", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(false),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    expect(lines.join("\n")).toMatch(/cancelled|aborted|no changes/i);
  });
});

// ---------------------------------------------------------------------------
// handleImport — --yes flag
// ---------------------------------------------------------------------------

describe("handleImport — --yes flag", () => {
  it("does not call confirm when --yes is passed", async () => {
    const confirmMock = vi.fn().mockResolvedValue(true);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: confirmMock,
    });
    await handleImport({ yes: true }, deps);
    expect(confirmMock).not.toHaveBeenCalled();
  });

  it("imports all servers without confirmation when --yes is passed", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "filesystem": { command: "npx" },
          "github": { command: "npx" },
        })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      addToStore: addToStoreMock,
    });
    await handleImport({ yes: true }, deps);
    expect(addToStoreMock).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// handleImport — --client filter
// ---------------------------------------------------------------------------

describe("handleImport — --client filter invalid client", () => {
  it("throws when the specified --client is not installed", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
    });
    await expect(
      handleImport({ client: "vscode" }, deps)
    ).rejects.toThrow(/vscode.*not.*install/i);
  });
});

describe("handleImport — --client filter", () => {
  it("only reads from the specified client when --client is provided", async () => {
    const getAdapterMock = vi.fn().mockReturnValue(makeAdapter("cursor", {
      "postgres": { command: "npx" },
    }));
    const detectClientsMock = vi.fn().mockResolvedValue(["claude-desktop", "cursor", "vscode"]);
    const deps = makeDeps({
      detectClients: detectClientsMock,
      getAdapter: getAdapterMock,
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
    });
    await handleImport({ client: "cursor" }, deps);
    // getAdapter should only be called with "cursor"
    expect(getAdapterMock).toHaveBeenCalledWith("cursor");
    expect(getAdapterMock).not.toHaveBeenCalledWith("claude-desktop");
    expect(getAdapterMock).not.toHaveBeenCalledWith("vscode");
  });

  it("only shows servers from the filtered client", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) => {
        if (clientId === "cursor") {
          return makeAdapter("cursor", { "postgres": { command: "npx" } });
        }
        return makeAdapter("claude-desktop", { "filesystem": { command: "npx" } });
      }),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({ client: "cursor" }, deps);
    const out = lines.join("\n");
    expect(out).toContain("postgres");
    expect(out).not.toContain("filesystem");
  });

  it("uses the filtered client even if detectClients would return more", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) => {
        if (clientId === "cursor") {
          return makeAdapter("cursor", { "postgres": { command: "npx" } });
        }
        return makeAdapter("claude-desktop", { "filesystem": { command: "npx" } });
      }),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      addToStore: addToStoreMock,
    });
    await handleImport({ client: "cursor" }, deps);
    expect(addToStoreMock).toHaveBeenCalledTimes(1);
    expect(addToStoreMock.mock.calls[0][0].name).toBe("postgres");
  });
});

// ---------------------------------------------------------------------------
// handleImport — HTTP/URL-based servers
// ---------------------------------------------------------------------------

describe("handleImport — URL-based servers", () => {
  it("handles URL-based servers (no command, has url)", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "remote-server": { url: "https://example.com/mcp" },
        })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toContain("remote-server");
    expect(out).toMatch(/https:\/\/example\.com\/mcp|remote-server/);
  });
});

// ---------------------------------------------------------------------------
// handleImport — adapter read errors
// ---------------------------------------------------------------------------

describe("handleImport — adapter errors", () => {
  it("continues with other clients if one adapter read fails", async () => {
    const lines: string[] = [];
    const failingAdapter: ConfigAdapter = {
      clientId: "claude-desktop",
      read: vi.fn().mockRejectedValue(new Error("Permission denied")),
      addServer: vi.fn(),
      removeServer: vi.fn(),
      read: vi.fn().mockRejectedValue(new Error("Permission denied")),
    };
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) => {
        if (clientId === "claude-desktop") return failingAdapter;
        return makeAdapter("cursor", { "postgres": { command: "npx" } });
      }),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    // Should still find cursor's servers
    expect(out).toContain("postgres");
  });
});

// ---------------------------------------------------------------------------
// checkFirstRun — store exists (early return)
// ---------------------------------------------------------------------------

describe("checkFirstRun — store exists", () => {
  it("returns immediately without output when store already exists", async () => {
    const outputMock = vi.fn();
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn(),
      output: outputMock,
    });
    await checkFirstRun(deps);
    expect(outputMock).not.toHaveBeenCalled();
    expect(deps.detectClients).not.toHaveBeenCalled();
  });

  it("does not check for clients or adapters when store exists", async () => {
    const detectClientsMock = vi.fn().mockResolvedValue(["claude-desktop"]);
    const getAdapterMock = vi.fn();
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(true),
      detectClients: detectClientsMock,
      getAdapter: getAdapterMock,
    });
    await checkFirstRun(deps);
    expect(detectClientsMock).not.toHaveBeenCalled();
    expect(getAdapterMock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// checkFirstRun — store doesn't exist, servers found
// ---------------------------------------------------------------------------

describe("checkFirstRun — store doesn't exist, servers found", () => {
  it("shows a hint message mentioning the count of servers", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "filesystem": { command: "npx" },
          "github": { command: "npx" },
        })
      ),
      output: (t) => lines.push(t),
    });
    await checkFirstRun(deps);
    const out = lines.join("\n");
    expect(out).toMatch(/2/);
    expect(out).toMatch(/mcp server/i);
  });

  it("shows a hint mentioning `mcpm import` command", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      output: (t) => lines.push(t),
    });
    await checkFirstRun(deps);
    const out = lines.join("\n");
    expect(out).toMatch(/mcpm import/);
  });

  it("does NOT auto-import — only shows the hint", async () => {
    const addToStoreMock = vi.fn();
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      addToStore: addToStoreMock,
    });
    await checkFirstRun(deps);
    expect(addToStoreMock).not.toHaveBeenCalled();
  });

  it("counts servers across multiple clients for the hint", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) => {
        if (clientId === "claude-desktop") {
          return makeAdapter("claude-desktop", {
            "filesystem": { command: "npx" },
            "github": { command: "npx" },
          });
        }
        return makeAdapter("cursor", { "postgres": { command: "npx" } });
      }),
      output: (t) => lines.push(t),
    });
    await checkFirstRun(deps);
    const out = lines.join("\n");
    // 3 total servers across two clients
    expect(out).toMatch(/3/);
  });
});

// ---------------------------------------------------------------------------
// checkFirstRun — store doesn't exist, no servers
// ---------------------------------------------------------------------------

describe("checkFirstRun — store doesn't exist, no servers", () => {
  it("produces no output when no servers are found on first run", async () => {
    const outputMock = vi.fn();
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter("claude-desktop", {})),
      output: outputMock,
    });
    await checkFirstRun(deps);
    expect(outputMock).not.toHaveBeenCalled();
  });

  it("produces no output when no clients are detected on first run", async () => {
    const outputMock = vi.fn();
    const deps = makeDeps({
      storeExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue([]),
      output: outputMock,
    });
    await checkFirstRun(deps);
    expect(outputMock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// handleImport — de-duplication across clients
// ---------------------------------------------------------------------------

describe("handleImport — de-duplication across clients", () => {
  it("treats servers with the same name from different clients as one entry", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    // Same server name "filesystem" in both claude-desktop and cursor
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) => {
        return makeAdapter(clientId, { "filesystem": { command: "npx" } });
      }),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      addToStore: addToStoreMock,
    });
    await handleImport({}, deps);
    // Should import only 1 unique server (filesystem), even though it appears in 2 clients
    expect(addToStoreMock).toHaveBeenCalledTimes(1);
    // The imported server should include both clients
    const imported: InstalledServer = addToStoreMock.mock.calls[0][0];
    expect(imported.name).toBe("filesystem");
    expect(imported.clients).toContain("claude-desktop");
    expect(imported.clients).toContain("cursor");
  });
});

// ---------------------------------------------------------------------------
// handleImport — immutability check
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handleImport — trust assessment (#23)
// ---------------------------------------------------------------------------

describe("handleImport — trust assessment (#23)", () => {
  // A name one edit away from a known popular server triggers a HIGH
  // typosquatting finding in scanTier1 → drives the trust level below "safe".
  const TYPOSQUAT_NAME = "io.github.modelcontextprotocol/servers-githubb";

  it("records a trustScore on every imported server", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      addToStore: addToStoreMock,
    });
    await handleImport({}, deps);
    const imported: InstalledServer = addToStoreMock.mock.calls[0][0];
    expect(typeof imported.trustScore).toBe("number");
  });

  it("runs scanTier1 on each discovered server before importing", async () => {
    const scanSpy = vi.fn(scanTier1);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      scanTier1: scanSpy,
    });
    await handleImport({}, deps);
    expect(scanSpy).toHaveBeenCalledTimes(1);
    // scanTier1 must receive the discovered server name so typosquatting works.
    const arg = scanSpy.mock.calls[0][0];
    expect(arg.server.name).toBe("filesystem");
  });

  it("surfaces a low-trust warning for a typosquatting server", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { [TYPOSQUAT_NAME]: { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/security finding/i);
    expect(out).toMatch(/severity/i);
    expect(out).toContain(TYPOSQUAT_NAME);
  });

  it("records the (low) trustScore for a typosquatting server", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { [TYPOSQUAT_NAME]: { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      addToStore: addToStoreMock,
    });
    await handleImport({}, deps);
    const imported: InstalledServer = addToStoreMock.mock.calls[0][0];
    // A HIGH finding deducts from staticScan; the score must reflect that.
    const clean = computeTrustScore({
      findings: [],
      healthCheckPassed: null,
      hasExternalScanner: false,
      registryMeta: {},
    });
    expect(imported.trustScore).toBeLessThan(clean.score);
  });

  it("does NOT warn for a clean server", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", { "filesystem": { command: "npx" } })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const out = lines.join("\n");
    expect(out).not.toMatch(/security finding/i);
    expect(out).not.toMatch(/low trust/i);
  });

  it("scans env var names and runtime args of the imported entry", async () => {
    const scanSpy = vi.fn(scanTier1);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "srv": {
            command: "npx",
            args: ["--flag", "value"],
            env: { API_KEY: "x", ENDPOINT: "y" },
          },
        })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      scanTier1: scanSpy,
    });
    await handleImport({}, deps);
    const entry = scanSpy.mock.calls[0][0];
    const pkg = entry.server.packages[0];
    const envNames = pkg.environmentVariables.map((e) => e.name);
    expect(envNames).toContain("API_KEY");
    expect(envNames).toContain("ENDPOINT");
    expect(pkg.runtimeArguments).toEqual(["--flag", "value"]);
  });
});

// ---------------------------------------------------------------------------
// handleImport — install-script shape findings (F4)
// ---------------------------------------------------------------------------

describe("handleImport — install-script shape findings (F4)", () => {
  // toServerEntry emits registryType "unknown" (imports cannot reliably infer
  // the registry from a bare command string), so the npm launcher-shape LOW
  // finding never fires here — but the dangerous-flag check runs for EVERY
  // registryType, giving imported configs the same audit visibility.
  it("does not emit the npx launcher-shape finding for imported servers ('unknown' registryType)", async () => {
    const scanSpy = vi.fn(scanTier1);
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "filesystem": { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] },
        })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      scanTier1: scanSpy,
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const findings = scanSpy.mock.results[0].value;
    expect(findings.filter((f) => f.type === "install-script")).toEqual([]);
    expect(lines.join("\n")).not.toMatch(/security finding/i);
  });

  it("flags a dangerous declared runtime argument on an imported server (medium install-script)", async () => {
    const scanSpy = vi.fn(scanTier1);
    const lines: string[] = [];
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "hooked": { command: "node", args: ["--require=./hook.js"] },
        })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      scanTier1: scanSpy,
      output: (t) => lines.push(t),
    });
    await handleImport({}, deps);
    const installScript = scanSpy.mock.results[0].value.filter(
      (f) => f.type === "install-script"
    );
    expect(installScript).toHaveLength(1);
    expect(installScript[0]).toMatchObject({
      severity: "medium",
      location: "runtime argument: --require=./hook.js",
    });
    expect(installScript[0].message).toContain('"--require"');
    expect(lines.join("\n")).toMatch(/security finding/i);
  });
});

// ---------------------------------------------------------------------------
// handleImport — immutability
// ---------------------------------------------------------------------------

describe("handleImport — immutability", () => {
  it("passes a new InstalledServer object to addToStore (not mutated)", async () => {
    const addToStoreMock = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "filesystem": { command: "npx", args: ["--path", "/"] },
        })
      ),
      getInstalledServers: vi.fn().mockResolvedValue([]),
      confirm: vi.fn().mockResolvedValue(true),
      addToStore: addToStoreMock,
    });
    await handleImport({}, deps);
    const server: InstalledServer = addToStoreMock.mock.calls[0][0];
    // Mutating the returned object must not affect anything
    const originalName = server.name;
    (server as { name: string }).name = "mutated";
    expect(originalName).toBe("filesystem");
  });
});
