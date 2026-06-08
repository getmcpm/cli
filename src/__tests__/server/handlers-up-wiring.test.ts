/**
 * Wiring test for handleMcpUp — proves the MCP (untrusted-caller) surface hands
 * handleUp the locked-down options. Unlike handlers-up.test.ts (which runs the REAL
 * handleUp), this mocks handleUp and captures exactly what handleMcpUp passes, so
 * deleting any lockdown option (e.g. `minTrustFloor`) makes this test fail — the
 * gap review finding H2/M2 flagged (the wiring was otherwise unguarded).
 */

import { describe, it, expect, vi } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ServerDeps } from "../../server/handlers.js";

// Capture the options handleMcpUp passes to handleUp without executing the real one.
const handleUpSpy = vi.fn().mockResolvedValue(undefined);
vi.mock("../../commands/up.js", () => ({ handleUp: handleUpSpy }));

// Imported after vi.mock so the spy is in effect.
const { handleMcpUp } = await import("../../server/handlers.js");

function makeServerDeps(): ServerDeps {
  return {
    registrySearch: vi.fn().mockResolvedValue([]),
    registryGetServer: vi.fn(),
    detectClients: vi
      .fn<() => Promise<ClientId[]>>()
      .mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn(),
    getConfigPath: vi.fn().mockReturnValue("/mock/config.json"),
    scanTier1: vi.fn().mockReturnValue([]),
    computeTrustScore: vi.fn(),
    addToStore: vi.fn().mockResolvedValue(undefined),
    removeFromStore: vi.fn().mockResolvedValue(undefined),
  };
}

describe("handleMcpUp — MCP surface lockdown wiring", () => {
  it("hands handleUp the locked-down options (no ambient env, no URL servers, hard trust floor)", async () => {
    handleUpSpy.mockClear();

    await handleMcpUp({}, makeServerDeps());

    expect(handleUpSpy).toHaveBeenCalledTimes(1);
    const opts = handleUpSpy.mock.calls[0][0];
    expect(opts.allowProcessEnv).toBe(false);
    expect(opts.allowEnvFile).toBe(false);
    expect(opts.allowUrlServers).toBe(false);
    // HARD_TRUST_FLOOR (issue #24). Deleting `minTrustFloor` from handleMcpUp's
    // handleUp call fails here even though the rest of the suite stays green.
    expect(opts.minTrustFloor).toBe(25);
    expect(opts.ci).toBe(true);
  });
});
