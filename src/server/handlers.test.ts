/**
 * Tests for src/server/handlers.ts
 *
 * All handlers use injectable deps — no network, no filesystem.
 */

import { describe, it, expect, vi } from "vitest";
import {
  handleSearch,
  handleInstall,
  handleInfo,
  handleList,
  handleRemove,
  handleAudit,
  handleSetup,
  extractKeywords,
  type ServerDeps,
} from "./handlers.js";
import type { ServerEntry } from "../registry/types.js";
import type { ClientId } from "../config/paths.js";
import type { TrustScore } from "../scanner/trust-score.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeEntry(name: string, description = "A test server"): ServerEntry {
  return {
    server: {
      name,
      version: "1.0.0",
      description,
      packages: [
        {
          registryType: "npm",
          identifier: `@test/${name.split("/")[1] ?? name}`,
          environmentVariables: [],
        },
      ],
    },
  } as ServerEntry;
}

const GOOD_TRUST: TrustScore = {
  score: 72,
  maxPossible: 80,
  level: "caution",
  breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 7 },
};

const BAD_TRUST: TrustScore = {
  score: 30,
  maxPossible: 80,
  level: "risky",
  breakdown: { healthCheck: 0, staticScan: 20, externalScan: 0, registryMeta: 0 },
};

function makeDeps(overrides: Partial<ServerDeps> = {}): ServerDeps {
  return {
    registrySearch: vi.fn().mockResolvedValue([]),
    registryGetServer: vi.fn().mockRejectedValue(new Error("not found")),
    detectClients: vi.fn().mockResolvedValue(["cursor"] as ClientId[]),
    getAdapter: vi.fn().mockReturnValue({
      clientId: "cursor",
      read: vi.fn().mockResolvedValue({}),
      addServer: vi.fn().mockResolvedValue(undefined),
      removeServer: vi.fn().mockResolvedValue(undefined),
    }),
    getConfigPath: vi.fn().mockReturnValue("/fake/mcp.json"),
    scanTier1: vi.fn().mockReturnValue([]),
    computeTrustScore: vi.fn().mockReturnValue(GOOD_TRUST),
    addToStore: vi.fn().mockResolvedValue(undefined),
    removeFromStore: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// handleSearch
// ---------------------------------------------------------------------------

describe("handleSearch", () => {
  it("returns servers with trust scores", async () => {
    const entries = [makeEntry("io.github.acme/server-a"), makeEntry("io.github.acme/server-b")];
    const deps = makeDeps({ registrySearch: vi.fn().mockResolvedValue(entries) });

    const result = await handleSearch({ query: "test", limit: 20 }, deps);
    const r = result as { servers: Array<{ name: string; trustScore: number }> };
    expect(r.servers).toHaveLength(2);
    expect(r.servers[0].name).toBe("io.github.acme/server-a");
    expect(r.servers[0].trustScore).toBe(72);
  });

  it("returns empty array for no results", async () => {
    const deps = makeDeps();
    const result = await handleSearch({ query: "nonexistent", limit: 20 }, deps);
    const r = result as { servers: unknown[] };
    expect(r.servers).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// handleInstall
// ---------------------------------------------------------------------------

describe("handleInstall", () => {
  it("installs server and returns trust score", async () => {
    const entry = makeEntry("io.github.acme/srv");
    const deps = makeDeps({ registryGetServer: vi.fn().mockResolvedValue(entry) });

    const result = await handleInstall({ name: "io.github.acme/srv" }, deps);
    const r = result as { installed: boolean; clients: string[]; trustScore: TrustScore };
    expect(r.installed).toBe(true);
    expect(r.clients).toContain("cursor");
    expect(r.trustScore.score).toBe(72);
  });

  it("throws when server not found", async () => {
    const deps = makeDeps();
    await expect(handleInstall({ name: "nonexistent" }, deps)).rejects.toThrow();
  });

  it("installs to specific client when specified", async () => {
    const entry = makeEntry("io.github.acme/srv");
    const deps = makeDeps({ registryGetServer: vi.fn().mockResolvedValue(entry) });

    const result = await handleInstall({ name: "io.github.acme/srv", client: "cursor" }, deps);
    const r = result as { clients: string[] };
    expect(r.clients).toEqual(["cursor"]);
  });
});

// ---------------------------------------------------------------------------
// handleInfo
// ---------------------------------------------------------------------------

describe("handleInfo", () => {
  it("returns server details with trust score", async () => {
    const entry = makeEntry("io.github.acme/srv", "Test server description");
    const deps = makeDeps({ registryGetServer: vi.fn().mockResolvedValue(entry) });

    const result = await handleInfo({ name: "io.github.acme/srv" }, deps);
    const r = result as { name: string; description: string; trustScore: TrustScore };
    expect(r.name).toBe("io.github.acme/srv");
    expect(r.description).toBe("Test server description");
    expect(r.trustScore.score).toBe(72);
  });

  it("throws when server not found", async () => {
    const deps = makeDeps();
    await expect(handleInfo({ name: "nonexistent" }, deps)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// handleList
// ---------------------------------------------------------------------------

describe("handleList", () => {
  it("lists servers across clients", async () => {
    const adapter = {
      clientId: "cursor",
      read: vi.fn().mockResolvedValue({ "my-server": { command: "npx", args: ["-y", "srv"] } }),
      addServer: vi.fn(),
      removeServer: vi.fn(),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    const result = await handleList({}, deps);
    const r = result as { servers: Array<{ name: string; client: string }> };
    expect(r.servers).toHaveLength(1);
    expect(r.servers[0].name).toBe("my-server");
    expect(r.servers[0].client).toBe("cursor");
  });

  it("returns empty when no servers installed", async () => {
    const deps = makeDeps();
    const result = await handleList({}, deps);
    const r = result as { servers: unknown[] };
    expect(r.servers).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// handleRemove
// ---------------------------------------------------------------------------

describe("handleRemove", () => {
  it("removes server from client config", async () => {
    const adapter = {
      clientId: "cursor",
      read: vi.fn(),
      addServer: vi.fn(),
      removeServer: vi.fn().mockResolvedValue(undefined),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    const result = await handleRemove({ name: "my-server" }, deps);
    const r = result as { removed: boolean; clients: string[] };
    expect(r.removed).toBe(true);
    expect(r.clients).toContain("cursor");
  });

  it("throws when server not found in any client", async () => {
    const adapter = {
      clientId: "cursor",
      read: vi.fn(),
      addServer: vi.fn(),
      removeServer: vi.fn().mockRejectedValue(new Error("not found")),
    };
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await expect(handleRemove({ name: "nonexistent" }, deps)).rejects.toThrow(/not found/i);
  });
});

// ---------------------------------------------------------------------------
// handleAudit
// ---------------------------------------------------------------------------

describe("handleAudit", () => {
  it("returns trust scores for installed servers", async () => {
    const entry = makeEntry("io.github.acme/srv");
    const adapter = {
      clientId: "cursor",
      read: vi.fn().mockResolvedValue({ "io.github.acme/srv": { command: "npx", args: [] } }),
      addServer: vi.fn(),
      removeServer: vi.fn(),
    };
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      registryGetServer: vi.fn().mockResolvedValue(entry),
    });

    const result = await handleAudit(deps);
    const r = result as { results: Array<{ name: string; trustScore: TrustScore }> };
    expect(r.results).toHaveLength(1);
    expect(r.results[0].trustScore.score).toBe(72);
  });
});

// ---------------------------------------------------------------------------
// handleSetup
// ---------------------------------------------------------------------------

describe("handleSetup", () => {
  it("installs servers matching keywords", async () => {
    const fsEntry = makeEntry("io.github.acme/filesystem");
    const ghEntry = makeEntry("io.github.acme/github");

    const deps = makeDeps({
      registrySearch: vi.fn()
        .mockResolvedValueOnce([fsEntry])
        .mockResolvedValueOnce([ghEntry]),
      registryGetServer: vi.fn()
        .mockImplementation((name: string) => {
          if (name === "io.github.acme/filesystem") return Promise.resolve(fsEntry);
          if (name === "io.github.acme/github") return Promise.resolve(ghEntry);
          return Promise.reject(new Error("not found"));
        }),
    });

    const result = await handleSetup(
      { description: "filesystem and github", minTrustScore: 50 },
      deps
    );
    const r = result as { installed: Array<{ name: string }>; skipped: unknown[] };
    expect(r.installed).toHaveLength(2);
    expect(r.installed[0].name).toBe("io.github.acme/filesystem");
    expect(r.installed[1].name).toBe("io.github.acme/github");
  });

  it("skips servers below trust threshold", async () => {
    const entry = makeEntry("io.github.acme/risky");
    const deps = makeDeps({
      registrySearch: vi.fn().mockResolvedValue([entry]),
      computeTrustScore: vi.fn().mockReturnValue(BAD_TRUST),
    });

    const result = await handleSetup(
      { description: "risky", minTrustScore: 50 },
      deps
    );
    const r = result as { installed: unknown[]; skipped: Array<{ name: string; reason: string }> };
    expect(r.installed).toHaveLength(0);
    expect(r.skipped).toHaveLength(1);
    expect(r.skipped[0].reason).toContain("below minimum");
  });

  it("skips keywords with no results", async () => {
    const deps = makeDeps({ registrySearch: vi.fn().mockResolvedValue([]) });

    const result = await handleSetup(
      { description: "nonexistent", minTrustScore: 50 },
      deps
    );
    const r = result as { installed: unknown[]; skipped: Array<{ reason: string }> };
    expect(r.installed).toHaveLength(0);
    expect(r.skipped).toHaveLength(1);
    expect(r.skipped[0].reason).toContain("No servers found");
  });

  it("throws on empty description", async () => {
    const deps = makeDeps();
    await expect(
      handleSetup({ description: "", minTrustScore: 50 }, deps)
    ).rejects.toThrow(/keyword/i);
  });

  it("returns restart note when servers are installed", async () => {
    const entry = makeEntry("io.github.acme/srv");
    const deps = makeDeps({
      registrySearch: vi.fn().mockResolvedValue([entry]),
      registryGetServer: vi.fn().mockResolvedValue(entry),
    });

    const result = await handleSetup(
      { description: "srv", minTrustScore: 0 },
      deps
    );
    const r = result as { note?: string };
    expect(r.note).toContain("Restart");
  });
});

// ---------------------------------------------------------------------------
// extractKeywords
// ---------------------------------------------------------------------------

describe("extractKeywords", () => {
  it("splits on 'and'", () => {
    expect(extractKeywords("filesystem and github")).toEqual(["filesystem", "github"]);
  });

  it("strips stopwords", () => {
    expect(extractKeywords("I need filesystem access")).toEqual(["filesystem"]);
  });

  it("splits on commas", () => {
    expect(extractKeywords("postgres, sqlite")).toEqual(["postgres", "sqlite"]);
  });

  it("falls back to full string for too many tokens", () => {
    const result = extractKeywords("a b c d e f g h i j");
    expect(result).toHaveLength(1);
  });

  it("returns original for empty after stopword removal", () => {
    expect(extractKeywords("I need to")).toEqual(["I need to"]);
  });

  it("handles single keyword", () => {
    expect(extractKeywords("postgresql")).toEqual(["postgresql"]);
  });
});
