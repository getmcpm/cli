/**
 * Tests for src/commands/outdated.ts — written FIRST per TDD (Red → Green).
 *
 * Strategy:
 * - Inject all external deps via OutdatedDeps
 * - Cover: empty list, all up-to-date, updates available, registry error per-server,
 *   --json output, and that NO cross-version trust claim is made (see the
 *   dedicated describe block at the end).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { InstalledServer } from "../../store/servers.js";
import type { ServerEntry } from "../../registry/types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeInstalled(name: string, version: string): InstalledServer {
  return {
    name,
    version,
    clients: ["claude-desktop"],
    installedAt: "2026-01-01T00:00:00Z",
  };
}

function makeEntry(name: string, version: string): ServerEntry {
  return {
    server: {
      name,
      description: "Test server",
      version,
      repository: { url: "https://github.com/test/server" },
      packages: [
        {
          registryType: "npm",
          identifier: "@test/server",
          version,
          transport: { type: "stdio" },
          environmentVariables: [],
        },
      ],
      remotes: [],
    },
    _meta: {
      "io.modelcontextprotocol.registry/official": {
        status: "active",
        publishedAt: "2026-01-01T00:00:00Z",
        isLatest: true,
      },
    },
  } as ServerEntry;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleOutdated", () => {
  let output: string[];
  let getInstalledServers: ReturnType<typeof vi.fn>;
  let getServer: ReturnType<typeof vi.fn>;
  let scanTier1: ReturnType<typeof vi.fn>;
  let computeTrustScore: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    output = [];
    getInstalledServers = vi.fn();
    getServer = vi.fn();
    scanTier1 = vi.fn().mockReturnValue([]);
    computeTrustScore = vi.fn().mockReturnValue({
      score: 80,
      level: "green",
      breakdown: {},
    });
  });

  async function run(opts: { json?: boolean } = {}) {
    const { handleOutdated } = await import("../../commands/outdated.js");
    await handleOutdated(opts, {
      getInstalledServers,
      getServer,
      scanTier1,
      computeTrustScore,
      output: (t) => output.push(t),
    });
  }

  it("shows 'nothing installed' when server list is empty", async () => {
    getInstalledServers.mockResolvedValue([]);
    await run();
    expect(output.join("")).toContain("No servers installed");
  });

  it("shows 'all up to date' when no new versions exist", async () => {
    getInstalledServers.mockResolvedValue([makeInstalled("io.github.a/srv", "1.0.0")]);
    getServer.mockResolvedValue(makeEntry("io.github.a/srv", "1.0.0"));
    await run();
    expect(output.join("")).toContain("up to date");
  });

  it("lists available updates with old and new versions", async () => {
    getInstalledServers.mockResolvedValue([makeInstalled("io.github.a/srv", "1.0.0")]);
    getServer.mockResolvedValue(makeEntry("io.github.a/srv", "2.0.0"));
    await run();
    const text = output.join("");
    expect(text).toContain("1.0.0");
    expect(text).toContain("2.0.0");
    expect(text).toContain("io.github.a/srv");
  });

  it("shows error row when registry is unavailable for one server but continues others", async () => {
    getInstalledServers.mockResolvedValue([
      makeInstalled("io.github.a/srv", "1.0.0"),
      makeInstalled("io.github.b/srv", "1.0.0"),
    ]);
    getServer
      .mockRejectedValueOnce(new Error("Network error"))
      .mockResolvedValueOnce(makeEntry("io.github.b/srv", "2.0.0"));
    await run();
    const text = output.join("");
    expect(text).toContain("io.github.a/srv");
    expect(text).toContain("unavailable");
    expect(text).toContain("io.github.b/srv");
    expect(text).toContain("2.0.0");
  });

  it("outputs valid JSON array with --json flag", async () => {
    getInstalledServers.mockResolvedValue([makeInstalled("io.github.a/srv", "1.0.0")]);
    getServer.mockResolvedValue(makeEntry("io.github.a/srv", "2.0.0"));
    await run({ json: true });
    const parsed = JSON.parse(output.join("")) as unknown[];
    expect(Array.isArray(parsed)).toBe(true);
    const first = parsed[0] as Record<string, unknown>;
    expect(first).toHaveProperty("name");
    expect(first).toHaveProperty("installedVersion");
    expect(first).toHaveProperty("latestVersion");
  });

  it("handles server with undefined installed trustScore gracefully", async () => {
    const server = makeInstalled("io.github.a/srv", "1.0.0");
    (server as Record<string, unknown>).trustScore = undefined;
    getInstalledServers.mockResolvedValue([server]);
    getServer.mockResolvedValue(makeEntry("io.github.a/srv", "1.0.0"));
    await run();
    expect(output.join("")).toContain("up to date");
  });
});

// ---------------------------------------------------------------------------
// No cross-version trust claim (regression removed 2026-08-12)
// ---------------------------------------------------------------------------

describe("handleOutdated — makes no claim about change since install", () => {
  // These use the REAL scanTier1 and the REAL computeTrustScore, deliberately.
  // The rest of this file mocks computeTrustScore to a single constant, which makes
  // both sides of any comparison equal and would have rendered the removed bug
  // invisible — the same self-concealing shape as the `--min-trust 70` / mocked-65
  // test corrected on 2026-08-12.
  //
  // The old code compared `s.trustScore` (frozen in servers.json) against a fresh
  // score. Measured on an UNCHANGED server, a store record written by `install`
  // with an external scanner held 80 against a fresh comparand of 60 — a permanent
  // false "regression: 80 → 60" on every run, forever.
  async function runReal(installed: InstalledServer, entry: ServerEntry, json = false) {
    const { handleOutdated } = await import("../../commands/outdated.js");
    const { scanTier1 } = await import("../../scanner/tier1.js");
    const { computeTrustScore } = await import("../../scanner/trust-score.js");
    const out: string[] = [];
    await handleOutdated({ json }, {
      getInstalledServers: async () => [installed],
      getServer: async () => entry,
      scanTier1,
      computeTrustScore,
      output: (t) => out.push(t),
    });
    return out.join("\n");
  }

  // An on-disk record as pre-fix mcpm actually wrote it — the extra key still
  // exists in real servers.json files, so feed the shape rather than the type.
  function legacyRecord(score: number): InstalledServer {
    return JSON.parse(JSON.stringify({
      name: "io.github.a/srv",
      version: "1.0.0",
      clients: ["claude-desktop"],
      installedAt: "2026-01-01T00:00:00Z",
      trustScore: score,
    })) as InstalledServer;
  }

  it("says nothing about trust for an up-to-date server, whatever an old servers.json stored", async () => {
    const text = await runReal(legacyRecord(80), makeEntry("io.github.a/srv", "1.0.0"));
    expect(text).toContain("All servers are up to date.");
    expect(text).not.toMatch(/regress/i);
    expect(text).not.toContain("→");
  });

  it("does not surface a row for an unchanged server just because the stored number is higher", async () => {
    // 80 stored vs a fresh score well below it: under the old comparison this row
    // entered the outdated list on `|| r.trustRegression` despite versionChange
    // being "none".
    const text = await runReal(legacyRecord(100), makeEntry("io.github.a/srv", "1.0.0"));
    expect(text).not.toContain("Outdated servers:");
  });

  it("--json publishes no cross-version comparison fields, and keeps the honest ones", async () => {
    const text = await runReal(legacyRecord(80), makeEntry("io.github.a/srv", "2.0.0"), true);
    const rows = JSON.parse(text) as Array<Record<string, unknown>>;
    expect(Object.keys(rows[0])).not.toContain("trustRegression");
    expect(Object.keys(rows[0])).not.toContain("installedTrustScore");
    // The latest version's freshly-scanned figures are honestly computed — an
    // over-eager cleanup must not take these with it.
    expect(rows[0]).toHaveProperty("latestTrustScore");
    expect(rows[0]).toHaveProperty("latestLevel");
    expect(rows[0].versionChange).toBe("major");
  });
});
