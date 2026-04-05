/**
 * Tests for src/commands/enable.ts
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import { handleEnable } from "../../commands/enable.js";

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
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
    setServerDisabled: vi.fn().mockResolvedValue(undefined),
  };
}

interface EnableDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

function makeDeps(overrides: Partial<EnableDeps> = {}): EnableDeps {
  return {
    detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    getAdapter: vi.fn().mockImplementation((id: ClientId) =>
      makeAdapter(id, { "my-server": { command: "npx", disabled: true } })
    ),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleEnable", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("enables a disabled server", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx", disabled: true },
    });
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });
    await handleEnable("my-server", {}, deps);
    expect(adapter.setServerDisabled).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "my-server",
      false
    );
  });

  it("outputs success message", async () => {
    const deps = makeDeps();
    await handleEnable("my-server", {}, deps);
    const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(output).toMatch(/Enabled.*my-server/);
  });

  it("throws when server not found", async () => {
    const adapter = makeAdapter("claude-desktop", {});
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });
    await expect(handleEnable("ghost", {}, deps)).rejects.toThrow(/not found/i);
  });

  it("reports already enabled when server is not disabled", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });
    await handleEnable("my-server", {}, deps);
    const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(output).toMatch(/already enabled/i);
    expect(adapter.setServerDisabled).not.toHaveBeenCalled();
  });

  it("respects --client filter", async () => {
    const claudeAdapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx", disabled: true },
    });
    const cursorAdapter = makeAdapter("cursor", {
      "my-server": { command: "npx", disabled: true },
    });
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) =>
        id === "claude-desktop" ? claudeAdapter : cursorAdapter
      ),
    });
    await handleEnable("my-server", { client: "cursor" }, deps);
    expect(cursorAdapter.setServerDisabled).toHaveBeenCalled();
    expect(claudeAdapter.setServerDisabled).not.toHaveBeenCalled();
  });

  it("throws when --client is not installed", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    });
    await expect(
      handleEnable("my-server", { client: "vscode" }, deps)
    ).rejects.toThrow(/vscode.*not.*installed/i);
  });

  it("throws when --client is an invalid client id", async () => {
    const deps = makeDeps();
    await expect(
      handleEnable("my-server", { client: "invalid-client" }, deps)
    ).rejects.toThrow(/Unknown client.*invalid-client/);
  });
});
