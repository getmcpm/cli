/**
 * Tests for src/commands/disable.ts
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import { handleDisable } from "../../commands/disable.js";

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

interface DisableDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

function makeDeps(overrides: Partial<DisableDeps> = {}): DisableDeps {
  return {
    detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    getAdapter: vi.fn().mockImplementation((id: ClientId) =>
      makeAdapter(id, { "my-server": { command: "npx", args: ["-y", "my-server"] } })
    ),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleDisable", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("disables a server in the detected client", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });
    await handleDisable("my-server", {}, deps);
    expect(adapter.setServerDisabled).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "my-server",
      true
    );
  });

  it("outputs success message", async () => {
    const deps = makeDeps();
    await handleDisable("my-server", {}, deps);
    const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(output).toMatch(/Disabled.*my-server/);
  });

  it("throws when server not found", async () => {
    const adapter = makeAdapter("claude-desktop", {});
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });
    await expect(handleDisable("ghost", {}, deps)).rejects.toThrow(/not found/i);
  });

  it("reports already disabled when server has disabled: true", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx", disabled: true },
    });
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });
    await handleDisable("my-server", {}, deps);
    const output = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join(" ");
    expect(output).toMatch(/already disabled/i);
    expect(adapter.setServerDisabled).not.toHaveBeenCalled();
  });

  it("respects --client filter", async () => {
    const claudeAdapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const cursorAdapter = makeAdapter("cursor", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) =>
        id === "claude-desktop" ? claudeAdapter : cursorAdapter
      ),
    });
    await handleDisable("my-server", { client: "cursor" }, deps);
    expect(cursorAdapter.setServerDisabled).toHaveBeenCalled();
    expect(claudeAdapter.setServerDisabled).not.toHaveBeenCalled();
  });

  it("throws when --client is not installed", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    });
    await expect(
      handleDisable("my-server", { client: "vscode" }, deps)
    ).rejects.toThrow(/vscode.*not.*installed/i);
  });

  it("throws when --client is an invalid client id", async () => {
    const deps = makeDeps();
    await expect(
      handleDisable("my-server", { client: "invalid-client" }, deps)
    ).rejects.toThrow(/Unknown client.*invalid-client/);
  });

  it("only disables the enabled client when mixed state", async () => {
    const claudeAdapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx", disabled: true },
    });
    const cursorAdapter = makeAdapter("cursor", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) =>
        id === "claude-desktop" ? claudeAdapter : cursorAdapter
      ),
    });
    await handleDisable("my-server", {}, deps);
    expect(claudeAdapter.setServerDisabled).not.toHaveBeenCalled();
    expect(cursorAdapter.setServerDisabled).toHaveBeenCalledWith(
      "/fake/cursor/config.json",
      "my-server",
      true
    );
  });

  it("disables across multiple clients", async () => {
    const claudeAdapter = makeAdapter("claude-desktop", {
      "my-server": { command: "npx" },
    });
    const cursorAdapter = makeAdapter("cursor", {
      "my-server": { command: "npx" },
    });
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) =>
        id === "claude-desktop" ? claudeAdapter : cursorAdapter
      ),
    });
    await handleDisable("my-server", {}, deps);
    expect(claudeAdapter.setServerDisabled).toHaveBeenCalled();
    expect(cursorAdapter.setServerDisabled).toHaveBeenCalled();
  });
});
