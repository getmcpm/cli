/**
 * Tests for src/commands/outdated.ts — written FIRST per TDD (Red → Green).
 *
 * Strategy:
 * - Inject all external deps via OutdatedDeps
 * - Cover: empty list, all up-to-date, updates available, registry error per-server,
 *   trust regression (same version but lower score), --json output, cache bypass
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { InstalledServer } from "../../store/servers.js";
import type { ServerEntry } from "../../registry/types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeInstalled(
  name: string,
  version: string,
  trustScore = 80
): InstalledServer {
  return {
    name,
    version,
    clients: ["claude-desktop"],
    installedAt: "2026-01-01T00:00:00Z",
    trustScore,
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

  it("flags trust regression even when version is unchanged", async () => {
    getInstalledServers.mockResolvedValue([
      makeInstalled("io.github.a/srv", "1.0.0", 90),
    ]);
    getServer.mockResolvedValue(makeEntry("io.github.a/srv", "1.0.0"));
    computeTrustScore.mockReturnValue({ score: 45, level: "red", breakdown: {} });
    await run();
    const text = output.join("");
    expect(text).toContain("io.github.a/srv");
    expect(text.toLowerCase()).toMatch(/trust|score|regress/);
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
