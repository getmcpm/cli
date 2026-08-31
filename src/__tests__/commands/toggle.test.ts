/**
 * Tests for src/commands/toggle.ts (handleToggleServer, shared by `mcpm
 * disable`/`mcpm enable`).
 *
 * Minimal coverage focused on the #23 follow-up: BaseAdapter.read() now
 * drops an entry that fails Zod shape validation. Without also listening for
 * read()'s onSkip callback, a present-but-malformed entry reads as absent and
 * `mcpm disable`/`mcpm enable` would report "not found" — even though
 * setServerDisabled() (which operates on the raw config) would still find
 * and toggle it.
 */

import { describe, it, expect, vi } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter } from "../../config/adapters/index.js";
import { handleToggleServer, type ToggleDeps } from "../../commands/toggle.js";

function makeDeps(overrides: Partial<ToggleDeps> = {}): ToggleDeps {
  return {
    detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    getAdapter: vi.fn(),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    output: vi.fn(),
    ...overrides,
  };
}

describe("handleToggleServer — well-formed entry", () => {
  it("disables a server that is currently enabled", async () => {
    const adapter: ConfigAdapter = {
      clientId: "claude-desktop",
      read: vi.fn().mockResolvedValue({ srv: { command: "npx", args: [] } }),
      addServer: vi.fn().mockResolvedValue(undefined),
      removeServer: vi.fn().mockResolvedValue(undefined),
      setServerDisabled: vi.fn().mockResolvedValue(undefined),
      replaceServer: vi.fn().mockResolvedValue(undefined),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await handleToggleServer("srv", true, {}, deps);

    expect(adapter.setServerDisabled).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "srv",
      true,
    );
  });

  it("throws when the server is not found in any client", async () => {
    const adapter: ConfigAdapter = {
      clientId: "claude-desktop",
      read: vi.fn().mockResolvedValue({}),
      addServer: vi.fn().mockResolvedValue(undefined),
      removeServer: vi.fn().mockResolvedValue(undefined),
      setServerDisabled: vi.fn().mockResolvedValue(undefined),
      replaceServer: vi.fn().mockResolvedValue(undefined),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await expect(handleToggleServer("ghost", true, {}, deps)).rejects.toThrow(/not found/i);
  });
});

describe("handleToggleServer — server present but malformed (#23)", () => {
  it("still toggles a server whose entry failed shape validation", async () => {
    const adapter: ConfigAdapter = {
      clientId: "claude-desktop",
      read: vi.fn().mockImplementation(async (_path: string, onSkip?: (name: string) => void) => {
        onSkip?.("broken-server");
        return {};
      }),
      addServer: vi.fn().mockResolvedValue(undefined),
      removeServer: vi.fn().mockResolvedValue(undefined),
      setServerDisabled: vi.fn().mockResolvedValue(undefined),
      replaceServer: vi.fn().mockResolvedValue(undefined),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await handleToggleServer("broken-server", true, {}, deps);

    expect(adapter.setServerDisabled).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "broken-server",
      true,
    );
  });

  // The real BaseAdapter.setServerDisabled() rejects a non-object raw entry
  // (see base-read-validation.test.ts) rather than corrupting it. This
  // asserts handleToggleServer PROPAGATES that error to the caller instead
  // of swallowing it — a loud failure, not a silent no-op or corruption.
  it("propagates setServerDisabled's error instead of swallowing it", async () => {
    const adapter: ConfigAdapter = {
      clientId: "claude-desktop",
      read: vi.fn().mockImplementation(async (_path: string, onSkip?: (name: string) => void) => {
        onSkip?.("broken-server");
        return {};
      }),
      addServer: vi.fn().mockResolvedValue(undefined),
      removeServer: vi.fn().mockResolvedValue(undefined),
      setServerDisabled: vi.fn().mockRejectedValue(new Error("not a valid object")),
      replaceServer: vi.fn().mockResolvedValue(undefined),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await expect(handleToggleServer("broken-server", true, {}, deps)).rejects.toThrow(
      /not a valid object/,
    );
  });
});
