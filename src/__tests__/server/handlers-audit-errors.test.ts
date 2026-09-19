/**
 * #92 — the `mcpm_audit` MCP tool must STATE why a server could not be scored.
 *
 * The catch pushed a `{score: 0, maxPossible: 80, level: "risky"}` placeholder
 * and NOTHING else, so an agent reading the result could not distinguish a
 * genuinely risky server from one whose registry metadata simply did not load.
 * stderr is not a channel this surface has: the calling agent never sees it.
 *
 * The placeholder score is deliberately unchanged — existing consumers keep
 * working — and `error` is stated on EVERY row (null on success) so the field's
 * presence is not itself a signal a consumer has to infer.
 */

import { describe, it, expect, vi } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ServerDeps } from "../../server/handlers.js";
import { handleAudit } from "../../server/handlers.js";
import {
  NetworkError,
  NotFoundError,
  RegistryError,
  ValidationError,
} from "../../registry/errors.js";

function makeDeps(getServer: ServerDeps["registryGetServer"]): ServerDeps {
  return {
    registrySearch: vi.fn().mockResolvedValue([]),
    registryGetServer: getServer,
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn().mockReturnValue({
      clientId: "claude-desktop" as ClientId,
      read: vi.fn().mockResolvedValue({ "io.github.test/srv": { command: "npx", args: [] } }),
      addServer: vi.fn(),
      removeServer: vi.fn(),
      setServerDisabled: vi.fn(),
    }),
    getConfigPath: vi.fn().mockReturnValue("/mock/config.json"),
    scanTier1: vi.fn().mockReturnValue([]),
    computeTrustScore: vi.fn().mockReturnValue({
      score: 62,
      maxPossible: 80,
      level: "safe",
      breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 7 },
    }),
    addToStore: vi.fn(),
    removeFromStore: vi.fn(),
  };
}

type AuditRow = { name: string; client: string; error: string | null };

describe("mcpm_audit — per-server registry error (#92)", () => {
  it.each([
    ["a 404", () => new NotFoundError("io.github.test/srv"), /delisted/i],
    ["an unparseable body", () => new ValidationError("bad shape"), /could not parse/i],
    ["a network failure", () => new NetworkError("boom", new Error("ECONNREFUSED")), /unavailable/i],
    ["a 500", () => new RegistryError("server error", 500), /HTTP 500/],
  ])("states %s on the row instead of only a risky placeholder", async (_l, makeErr, expected) => {
    const deps = makeDeps(vi.fn().mockRejectedValue(makeErr()));
    const result = (await handleAudit(deps)) as { results: AuditRow[] };

    expect(result.results).toHaveLength(1);
    const row = result.results[0]!;
    expect(row.error).toMatch(expected);
    // The placeholder score is UNCHANGED — this is additive, not a re-score.
    expect((row as unknown as { trustScore: { level: string } }).trustScore.level).toBe("risky");
  });

  it("states error: null on a row that scored normally", async () => {
    const deps = makeDeps(
      vi.fn().mockResolvedValue({ server: { name: "io.github.test/srv", version: "1.0.0" } })
    );
    const result = (await handleAudit(deps)) as { results: AuditRow[] };

    expect(result.results[0]!.error).toBeNull();
    // Present, not absent: a consumer must not have to infer success from a
    // missing key.
    expect(Object.hasOwn(result.results[0]!, "error")).toBe(true);
  });
});
