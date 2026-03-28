/**
 * Tests for src/commands/update.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - All external deps (store, registry, config adapters) are injected as mocks.
 * - Test handler directly — not Commander parsing.
 * - Cover: no servers, all up-to-date, one update available, --yes flag, --json,
 *   registry unavailable, trust score change display, config update.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { InstalledServer } from "../../store/servers.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { Finding } from "../../scanner/tier1.js";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter } from "../../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeInstalledServer(overrides: Partial<InstalledServer> = {}): InstalledServer {
  return {
    name: "io.github.test/server-a",
    version: "1.0.0",
    clients: ["claude-desktop"],
    installedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function makeServerEntry(name: string, version = "1.0.0"): ServerEntry {
  return {
    server: {
      name,
      description: "A test server",
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

function makeTrustScore(level: "safe" | "caution" | "risky", score = 75): TrustScore {
  return {
    score,
    maxPossible: 100,
    level,
    breakdown: { healthCheck: 15, staticScan: 40, externalScan: 10, registryMeta: 10 },
  };
}

function makeAdapter(clientId: ClientId): ConfigAdapter {
  return {
    clientId,
    read: vi.fn().mockResolvedValue({}),
    listServers: vi.fn().mockResolvedValue({}),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
  };
}

// ---------------------------------------------------------------------------
// Deps interface
// ---------------------------------------------------------------------------

interface UpdateDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string) => Promise<ServerEntry>;
  addInstalledServer: (server: InstalledServer) => Promise<void>;
  removeInstalledServer: (name: string) => Promise<void>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: {
    findings: Finding[];
    healthCheckPassed: boolean | null;
    hasExternalScanner: boolean;
    registryMeta: Record<string, unknown>;
  }) => TrustScore;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

function makeDeps(overrides: Partial<UpdateDeps> = {}): UpdateDeps {
  return {
    getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer()]),
    getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "1.0.0")),
    addInstalledServer: vi.fn().mockResolvedValue(undefined),
    removeInstalledServer: vi.fn().mockResolvedValue(undefined),
    getAdapter: vi.fn().mockImplementation((id: ClientId) => makeAdapter(id)),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    scanTier1: vi.fn().mockReturnValue([]),
    computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe")),
    confirm: vi.fn().mockResolvedValue(true),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

import { handleUpdate } from "../../commands/update.js";
import type { UpdateOptions } from "../../commands/update.js";

// ---------------------------------------------------------------------------
// No servers installed
// ---------------------------------------------------------------------------

describe("handleUpdate — no servers installed", () => {
  it("outputs a message when no servers are installed", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([]),
      output: (t) => lines.push(t),
    });
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(/no servers installed/i);
  });

  it("does not call getServer when no servers are installed", async () => {
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue([]) });
    await handleUpdate({}, deps);
    expect(deps.getServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// All up to date
// ---------------------------------------------------------------------------

describe("handleUpdate — all up to date", () => {
  it("outputs 'all servers are up to date' when no version changes", async () => {
    // Installed version matches registry version
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ version: "1.0.0" }),
      ]),
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "1.0.0")),
    });
    const lines: string[] = [];
    await handleUpdate({}, { ...deps, output: (t) => lines.push(t) });
    expect(lines.join("\n")).toMatch(/all servers are up to date/i);
  });

  it("does not prompt for confirmation when nothing to update", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "1.0.0")),
    });
    await handleUpdate({}, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
  });

  it("does not call addInstalledServer when all are current", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "1.0.0")),
    });
    await handleUpdate({}, deps);
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Update available
// ---------------------------------------------------------------------------

describe("handleUpdate — one update available", () => {
  function makeUpdateDeps() {
    return makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
      ]),
      getServer: vi.fn().mockResolvedValue(
        makeServerEntry("io.github.test/server-a", "1.1.0")
      ),
    });
  }

  it("shows the old and new version in the output", async () => {
    const lines: string[] = [];
    const deps = { ...makeUpdateDeps(), output: (t: string) => lines.push(t) };
    await handleUpdate({}, deps);
    const out = lines.join("\n");
    expect(out).toContain("1.0.0");
    expect(out).toContain("1.1.0");
  });

  it("shows the server name in the output", async () => {
    const lines: string[] = [];
    const deps = { ...makeUpdateDeps(), output: (t: string) => lines.push(t) };
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toContain("io.github.test/server-a");
  });

  it("prompts for confirmation before updating", async () => {
    const deps = makeUpdateDeps();
    await handleUpdate({}, deps);
    expect(deps.confirm).toHaveBeenCalledOnce();
  });

  it("updates the store record with new version when confirmed", async () => {
    const deps = makeUpdateDeps();
    await handleUpdate({}, deps);
    expect(deps.removeInstalledServer).toHaveBeenCalledWith("io.github.test/server-a");
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-a", version: "1.1.0" })
    );
  });

  it("does NOT update when user declines confirmation", async () => {
    const deps = makeUpdateDeps();
    deps.confirm = vi.fn().mockResolvedValue(false);
    await handleUpdate({}, deps);
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });

  it("outputs cancellation note when user declines", async () => {
    const lines: string[] = [];
    const deps = { ...makeUpdateDeps(), confirm: vi.fn().mockResolvedValue(false), output: (t: string) => lines.push(t) };
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(/cancel|skipp/i);
  });

  it("runs trust scan on the new version", async () => {
    const deps = makeUpdateDeps();
    await handleUpdate({}, deps);
    expect(deps.scanTier1).toHaveBeenCalled();
    expect(deps.computeTrustScore).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// --yes flag skips confirmation
// ---------------------------------------------------------------------------

describe("handleUpdate — --yes flag", () => {
  it("does not call confirm when --yes is set", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "2.0.0")),
    });
    await handleUpdate({ yes: true }, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
  });

  it("still updates the store when --yes is set", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "2.0.0")),
    });
    await handleUpdate({ yes: true }, deps);
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ version: "2.0.0" })
    );
  });
});

// ---------------------------------------------------------------------------
// --json flag
// ---------------------------------------------------------------------------

describe("handleUpdate — --json flag", () => {
  it("outputs valid JSON when --json is set and updates available", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "2.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ json: true, yes: true }, deps);
    const parsed = JSON.parse(lines.join("\n"));
    expect(Array.isArray(parsed)).toBe(true);
  });

  it("JSON output includes name, oldVersion, newVersion, updated", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "2.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ json: true, yes: true }, deps);
    const parsed = JSON.parse(lines.join("\n")) as Array<{
      name: string;
      oldVersion: string;
      newVersion: string;
      updated: boolean;
    }>;
    expect(parsed[0]).toMatchObject({
      name: "io.github.test/server-a",
      oldVersion: "1.0.0",
      newVersion: "2.0.0",
      updated: true,
    });
  });

  it("JSON output marks updated: false for up-to-date servers", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "1.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ json: true }, deps);
    const parsed = JSON.parse(lines.join("\n")) as Array<{ updated: boolean }>;
    expect(parsed[0].updated).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Registry unavailable (graceful)
// ---------------------------------------------------------------------------

describe("handleUpdate — registry unavailable", () => {
  it("shows error note for server when registry fails", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(new Error("Network failure")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(/error|unavailable|failed|could not/i);
  });

  it("does not call addInstalledServer when registry fails", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(new Error("Network failure")),
    });
    await handleUpdate({}, deps);
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });

  it("continues with other servers when one fails", async () => {
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
        makeInstalledServer({ name: "io.github.test/server-b", version: "1.0.0" }),
      ]),
      getServer: vi.fn()
        .mockRejectedValueOnce(new Error("Network failure"))
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-b", "2.0.0")),
    });
    await handleUpdate({ yes: true }, deps);
    // Second server should be updated
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-b", version: "2.0.0" })
    );
  });
});

// ---------------------------------------------------------------------------
// Trust score display on update
// ---------------------------------------------------------------------------

describe("handleUpdate — trust score on update", () => {
  it("shows trust level in the output after update", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a", "2.0.0")),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe", 80)),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ yes: true }, deps);
    expect(lines.join("\n")).toMatch(/safe/i);
  });
});

// ---------------------------------------------------------------------------
// Multiple servers — some up to date, some not
// ---------------------------------------------------------------------------

describe("handleUpdate — multiple servers mixed state", () => {
  it("only updates servers with newer versions", async () => {
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
        makeInstalledServer({ name: "io.github.test/server-b", version: "2.0.0" }),
      ]),
      getServer: vi.fn()
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-a", "1.1.0")) // has update
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-b", "2.0.0")), // up to date
    });
    await handleUpdate({ yes: true }, deps);
    expect(deps.addInstalledServer).toHaveBeenCalledOnce();
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-a", version: "1.1.0" })
    );
  });

  it("outputs a summary of what was updated", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
        makeInstalledServer({ name: "io.github.test/server-b", version: "2.0.0" }),
      ]),
      getServer: vi.fn()
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-a", "1.1.0"))
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-b", "2.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ yes: true }, deps);
    const out = lines.join("\n");
    expect(out).toContain("server-a");
  });
});
