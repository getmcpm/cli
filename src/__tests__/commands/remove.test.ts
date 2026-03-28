/**
 * Tests for src/commands/remove.ts
 *
 * TDD — RED phase first: all tests should fail before implementation exists.
 * All external dependencies (config adapters, detector, store, prompts) are mocked.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Types matching the handler interface
// ---------------------------------------------------------------------------

interface RemoveDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  removeFromStore: (name: string) => Promise<void>;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

interface RemoveOptions {
  yes?: boolean;
  client?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAdapter(
  clientId: ClientId,
  servers: Record<string, McpServerEntry> = {}
): ConfigAdapter {
  return {
    clientId,
    read: vi.fn().mockResolvedValue(servers),
    listServers: vi.fn().mockResolvedValue(servers),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
  };
}

function makeDeps(overrides: Partial<RemoveDeps> = {}): RemoveDeps {
  return {
    detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    getAdapter: vi.fn().mockImplementation((id: ClientId) =>
      makeAdapter(id, { "my-server": { command: "npx", args: ["-y", "my-server"] } })
    ),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    removeFromStore: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Import the handler (will fail until implementation exists)
// ---------------------------------------------------------------------------

import { removeHandler } from "../../commands/remove.js";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("removeHandler — server found in one client", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("detects installed clients", async () => {
    const deps = makeDeps();
    await removeHandler("my-server", {}, deps);
    expect(deps.detectClients).toHaveBeenCalledOnce();
  });

  it("reads each client's config to check for the server", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx", args: ["-y", "my-server"] },
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await removeHandler("my-server", {}, deps);
    expect(adapter.listServers).toHaveBeenCalledWith("/fake/claude-desktop/config.json");
  });

  it("asks for confirmation before removing", async () => {
    const deps = makeDeps();
    await removeHandler("my-server", {}, deps);
    expect(deps.confirm).toHaveBeenCalledOnce();
    expect(deps.confirm).toHaveBeenCalledWith(
      expect.stringContaining("my-server")
    );
  });

  it("removes the server from the adapter when confirmed", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx", args: ["-y", "my-server"] },
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      confirm: vi.fn().mockResolvedValue(true),
    });
    await removeHandler("my-server", {}, deps);
    expect(adapter.removeServer).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "my-server"
    );
  });

  it("removes from store after removing from adapter", async () => {
    const deps = makeDeps({ confirm: vi.fn().mockResolvedValue(true) });
    await removeHandler("my-server", {}, deps);
    expect(deps.removeFromStore).toHaveBeenCalledWith("my-server");
  });

  it("outputs success message mentioning the client", async () => {
    const deps = makeDeps({ confirm: vi.fn().mockResolvedValue(true) });
    await removeHandler("my-server", {}, deps);
    const calls = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(calls).toMatch(/my-server/);
    expect(calls).toMatch(/claude-desktop/);
  });

  it("does NOT remove when user declines confirmation", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      confirm: vi.fn().mockResolvedValue(false),
    });
    await removeHandler("my-server", {}, deps);
    expect(adapter.removeServer).not.toHaveBeenCalled();
    expect(deps.removeFromStore).not.toHaveBeenCalled();
  });

  it("outputs cancellation message when user declines", async () => {
    const deps = makeDeps({ confirm: vi.fn().mockResolvedValue(false) });
    await removeHandler("my-server", {}, deps);
    const calls = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(calls).toMatch(/cancel/i);
  });
});

describe("removeHandler — --yes flag skips confirmation", () => {
  it("does not call confirm when --yes is set", async () => {
    const deps = makeDeps();
    await removeHandler("my-server", { yes: true }, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
  });

  it("still removes the server when --yes is set", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await removeHandler("my-server", { yes: true }, deps);
    expect(adapter.removeServer).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "my-server"
    );
    expect(deps.removeFromStore).toHaveBeenCalledWith("my-server");
  });
});

describe("removeHandler — server not found in any client", () => {
  it("throws an error when server is not found in any client", async () => {
    const adapter = makeAdapter("claude-desktop", {}); // empty — no servers
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await expect(removeHandler("ghost-server", {}, deps)).rejects.toThrow(
      /ghost-server.*not found/i
    );
  });

  it("does not call removeFromStore when server is not found", async () => {
    const adapter = makeAdapter("claude-desktop", {});
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await removeHandler("ghost-server", {}, deps).catch(() => {});
    expect(deps.removeFromStore).not.toHaveBeenCalled();
  });
});

describe("removeHandler — server found in multiple clients", () => {
  function makeMultiClientDeps(serverName = "shared-server") {
    const claudeAdapter = makeAdapter("claude-desktop", {
      [serverName]: { command: "npx", args: ["-y", serverName] },
    });
    const cursorAdapter = makeAdapter("cursor", {
      [serverName]: { url: "http://localhost:3000" },
    });
    return makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => {
        if (id === "claude-desktop") return claudeAdapter;
        if (id === "cursor") return cursorAdapter;
        return makeAdapter(id, {});
      }),
      confirm: vi.fn().mockResolvedValue(true),
    });
  }

  it("removes from all clients that have the server", async () => {
    const deps = makeMultiClientDeps("shared-server");
    await removeHandler("shared-server", { yes: true }, deps);

    const claudeAdapter = deps.getAdapter("claude-desktop");
    const cursorAdapter = deps.getAdapter("cursor");
    expect(claudeAdapter.removeServer).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "shared-server"
    );
    expect(cursorAdapter.removeServer).toHaveBeenCalledWith(
      "/fake/cursor/config.json",
      "shared-server"
    );
  });

  it("removes from store once even when found in multiple clients", async () => {
    const deps = makeMultiClientDeps("shared-server");
    await removeHandler("shared-server", { yes: true }, deps);
    expect(deps.removeFromStore).toHaveBeenCalledOnce();
    expect(deps.removeFromStore).toHaveBeenCalledWith("shared-server");
  });

  it("mentions all affected clients in the confirmation message", async () => {
    const deps = makeMultiClientDeps("shared-server");
    await removeHandler("shared-server", {}, deps);
    const confirmMsg = (deps.confirm as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(confirmMsg).toMatch(/claude-desktop/);
    expect(confirmMsg).toMatch(/cursor/);
  });
});

describe("removeHandler — --client filter", () => {
  it("only removes from the specified client", async () => {
    const claudeAdapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const cursorAdapter = makeAdapter("cursor", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => {
        if (id === "claude-desktop") return claudeAdapter;
        if (id === "cursor") return cursorAdapter;
        return makeAdapter(id, {});
      }),
    });

    await removeHandler("my-server", { client: "cursor" }, deps);

    expect(cursorAdapter.removeServer).toHaveBeenCalled();
    expect(claudeAdapter.removeServer).not.toHaveBeenCalled();
  });

  it("throws if the specified --client is not installed", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    });
    await expect(
      removeHandler("my-server", { client: "vscode" }, deps)
    ).rejects.toThrow(/vscode.*not.*installed/i);
  });

  it("throws if server not found in the specified client", async () => {
    const adapter = makeAdapter("cursor", {}); // cursor has no servers
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => {
        if (id === "cursor") return adapter;
        return makeAdapter(id, { "my-server": { command: "npx" } });
      }),
    });
    await expect(
      removeHandler("my-server", { client: "cursor" }, deps)
    ).rejects.toThrow(/my-server.*not found/i);
  });
});

describe("removeHandler — removeFromStore failure is non-fatal", () => {
  it("still outputs success even if store removal throws (server was already gone)", async () => {
    const deps = makeDeps({
      confirm: vi.fn().mockResolvedValue(true),
      removeFromStore: vi.fn().mockRejectedValue(new Error('Server "my-server" not found')),
    });
    // Should not throw
    await expect(removeHandler("my-server", {}, deps)).resolves.not.toThrow();
    const calls = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(calls).toMatch(/my-server/);
  });
});
