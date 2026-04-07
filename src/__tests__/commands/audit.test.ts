/**
 * Tests for src/commands/audit.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - All external deps (store, registry, scanner) are injected as mocks.
 * - Test handler directly — not Commander parsing.
 * - Cover: 0 servers, safe/caution/risky mix, registry unavailable, --json, exit codes,
 *   Tier 2 available vs not, --fix behavior.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { InstalledServer } from "../../store/servers.js";
import type { ServerEntry } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { ClientId } from "../../config/paths.js";

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
    breakdown: {
      healthCheck: 15,
      staticScan: 40,
      externalScan: 10,
      registryMeta: 10,
    },
  };
}

// ---------------------------------------------------------------------------
// Deps interface (mirrors the handler's injectable deps)
// ---------------------------------------------------------------------------

interface AuditDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string) => Promise<ServerEntry>;
  scanTier1: (entry: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: {
    findings: Finding[];
    healthCheckPassed: boolean | null;
    hasExternalScanner: boolean;
    registryMeta: Record<string, unknown>;
  }) => TrustScore;
  output: (text: string) => void;
  getAdapter: (clientId: ClientId) => { removeServer: (configPath: string, name: string) => Promise<void> };
  getConfigPath: (clientId: ClientId) => string;
  removeFromStore: (name: string) => Promise<void>;
  confirm: (message: string) => Promise<boolean>;
}

function makeDeps(overrides: Partial<AuditDeps> = {}): AuditDeps {
  return {
    getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer()]),
    getServer: vi.fn().mockResolvedValue(makeServerEntry("io.github.test/server-a")),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe")),
    output: vi.fn(),
    getAdapter: vi.fn().mockReturnValue({ removeServer: vi.fn().mockResolvedValue(undefined) }),
    getConfigPath: vi.fn().mockReturnValue("/tmp/config.json"),
    removeFromStore: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Import the handler
// ---------------------------------------------------------------------------

import { handleAudit } from "../../commands/audit.js";
import type { AuditOptions } from "../../commands/audit.js";

// ---------------------------------------------------------------------------
// No servers installed
// ---------------------------------------------------------------------------

describe("handleAudit — no servers installed", () => {
  it("outputs a helpful message when no servers are installed", async () => {
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue([]) });
    const lines: string[] = [];
    await handleAudit({}, { ...deps, output: (t) => lines.push(t) });
    expect(lines.join("\n")).toMatch(/no servers installed/i);
    expect(lines.join("\n")).toMatch(/mcpm install/i);
  });

  it("does not call getServer when no servers are installed", async () => {
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue([]) });
    await handleAudit({}, deps);
    expect(deps.getServer).not.toHaveBeenCalled();
  });

  it("does not call scanTier1 when no servers are installed", async () => {
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue([]) });
    await handleAudit({}, deps);
    expect(deps.scanTier1).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Basic scanning with one server
// ---------------------------------------------------------------------------

describe("handleAudit — single server", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("calls getInstalledServers to get the list", async () => {
    const deps = makeDeps();
    await handleAudit({}, deps);
    expect(deps.getInstalledServers).toHaveBeenCalledOnce();
  });

  it("calls getServer for each installed server", async () => {
    const deps = makeDeps();
    await handleAudit({}, deps);
    expect(deps.getServer).toHaveBeenCalledWith("io.github.test/server-a");
  });

  it("calls scanTier1 with the fetched server entry", async () => {
    const entry = makeServerEntry("io.github.test/server-a");
    const deps = makeDeps({ getServer: vi.fn().mockResolvedValue(entry) });
    await handleAudit({}, deps);
    expect(deps.scanTier1).toHaveBeenCalledWith(entry);
  });

  it("checks scanner availability exactly once (not per server)", async () => {
    const servers = [makeInstalledServer(), makeInstalledServer({ name: "io.github.test/server-b" })];
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue(servers) });
    await handleAudit({}, deps);
    expect(deps.checkScannerAvailable).toHaveBeenCalledOnce();
  });

  it("calls computeTrustScore with healthCheckPassed = null", async () => {
    const deps = makeDeps();
    await handleAudit({}, deps);
    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({ healthCheckPassed: null })
    );
  });

  it("outputs a table containing server name, score, level, and findings columns", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/server/i);
    expect(out).toMatch(/score/i);
    expect(out).toMatch(/level/i);
    expect(out).toMatch(/findings/i);
  });

  it("includes the server name in the output table", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({}, deps);
    expect(lines.join("\n")).toContain("io.github.test/server-a");
  });
});

// ---------------------------------------------------------------------------
// Tier 2 scanner available
// ---------------------------------------------------------------------------

describe("handleAudit — Tier 2 scanner available", () => {
  it("calls scanTier2 for each server when scanner is available", async () => {
    const deps = makeDeps({ checkScannerAvailable: vi.fn().mockResolvedValue(true) });
    await handleAudit({}, deps);
    expect(deps.scanTier2).toHaveBeenCalledWith("io.github.test/server-a");
  });

  it("does NOT call scanTier2 when scanner is unavailable", async () => {
    const deps = makeDeps({ checkScannerAvailable: vi.fn().mockResolvedValue(false) });
    await handleAudit({}, deps);
    expect(deps.scanTier2).not.toHaveBeenCalled();
  });

  it("passes hasExternalScanner = true to computeTrustScore when scanner available", async () => {
    const deps = makeDeps({ checkScannerAvailable: vi.fn().mockResolvedValue(true) });
    await handleAudit({}, deps);
    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({ hasExternalScanner: true })
    );
  });

  it("passes hasExternalScanner = false to computeTrustScore when scanner unavailable", async () => {
    const deps = makeDeps({ checkScannerAvailable: vi.fn().mockResolvedValue(false) });
    await handleAudit({}, deps);
    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({ hasExternalScanner: false })
    );
  });

  it("merges tier1 and tier2 findings when both run", async () => {
    const tier1Finding: Finding = { severity: "high", type: "secrets", message: "API key", location: "description" };
    const tier2Finding: Finding = { severity: "medium", type: "prompt-injection", message: "Injected", location: "tool" };
    const deps = makeDeps({
      checkScannerAvailable: vi.fn().mockResolvedValue(true),
      scanTier1: vi.fn().mockReturnValue([tier1Finding]),
      scanTier2: vi.fn().mockResolvedValue([tier2Finding]),
    });
    await handleAudit({}, deps);
    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({
        findings: [tier1Finding, tier2Finding],
      })
    );
  });
});

// ---------------------------------------------------------------------------
// Registry unavailable (graceful degradation)
// ---------------------------------------------------------------------------

describe("handleAudit — registry unavailable for one server", () => {
  it("skips server gracefully when getServer throws", async () => {
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a" }),
        makeInstalledServer({ name: "io.github.test/server-b" }),
      ]),
      getServer: vi.fn()
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-a"))
        .mockRejectedValueOnce(new Error("Network failure")),
    });
    const lines: string[] = [];
    await handleAudit({}, { ...deps, output: (t) => lines.push(t) });
    // Should still output something (not throw)
    expect(lines.length).toBeGreaterThan(0);
  });

  it("shows a registry error note for the failed server", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(new Error("Network failure")),
    });
    const lines: string[] = [];
    await handleAudit({}, { ...deps, output: (t) => lines.push(t) });
    const out = lines.join("\n");
    expect(out).toMatch(/registry|unavailable|error|failed/i);
  });

  it("still scans the successful server when one fails", async () => {
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a" }),
        makeInstalledServer({ name: "io.github.test/server-b" }),
      ]),
      getServer: vi.fn()
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-a"))
        .mockRejectedValueOnce(new Error("Network failure")),
    });
    await handleAudit({}, deps);
    expect(deps.scanTier1).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// Mixed results — safe, caution, risky
// ---------------------------------------------------------------------------

describe("handleAudit — safe/caution/risky mix", () => {
  function makeMultiServerDeps() {
    const servers = [
      makeInstalledServer({ name: "io.github.test/server-safe" }),
      makeInstalledServer({ name: "io.github.test/server-caution" }),
      makeInstalledServer({ name: "io.github.test/server-risky" }),
    ];

    return makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue(servers),
      getServer: vi.fn().mockImplementation((name: string) =>
        Promise.resolve(makeServerEntry(name))
      ),
      computeTrustScore: vi.fn()
        .mockReturnValueOnce(makeTrustScore("safe", 80))
        .mockReturnValueOnce(makeTrustScore("caution", 55))
        .mockReturnValueOnce(makeTrustScore("risky", 30)),
    });
  }

  it("outputs summary with correct server counts", async () => {
    const lines: string[] = [];
    const deps = { ...makeMultiServerDeps(), output: (t: string) => lines.push(t) };
    await handleAudit({}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/3.*server/i);
    expect(out).toMatch(/1.*safe/i);
    expect(out).toMatch(/1.*caution/i);
    expect(out).toMatch(/1.*risky/i);
  });

  it("shows all server names in the output", async () => {
    const lines: string[] = [];
    const deps = { ...makeMultiServerDeps(), output: (t: string) => lines.push(t) };
    await handleAudit({}, deps);
    const out = lines.join("\n");
    expect(out).toContain("server-safe");
    expect(out).toContain("server-caution");
    expect(out).toContain("server-risky");
  });
});

// ---------------------------------------------------------------------------
// Summary line
// ---------------------------------------------------------------------------

describe("handleAudit — summary line", () => {
  it("outputs a summary line with total count", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({}, deps);
    expect(lines.join("\n")).toMatch(/1.*server.*scanned/i);
  });
});

// ---------------------------------------------------------------------------
// --json flag
// ---------------------------------------------------------------------------

describe("handleAudit — --json flag", () => {
  it("outputs valid JSON array when --json is set", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({ json: true }, deps);
    const parsed = JSON.parse(lines.join("\n"));
    expect(Array.isArray(parsed)).toBe(true);
  });

  it("JSON output includes name, score, level, findings", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({ json: true }, deps);
    const parsed = JSON.parse(lines.join("\n")) as Array<{
      name: string;
      score: number;
      level: string;
      findings: unknown[];
    }>;
    expect(parsed[0]).toMatchObject({
      name: "io.github.test/server-a",
      score: expect.any(Number),
      level: expect.stringMatching(/safe|caution|risky/),
      findings: expect.any(Array),
    });
  });

  it("JSON mode does not output table characters", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({ json: true }, deps);
    const out = lines.join("\n");
    expect(out).not.toContain("─");
    expect(out).not.toContain("│");
  });
});

// ---------------------------------------------------------------------------
// Exit code behavior
// ---------------------------------------------------------------------------

describe("handleAudit — exit code", () => {
  it("returns exit code 0 when all servers are safe", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe")),
    });
    const exitCode = await handleAudit({}, deps);
    expect(exitCode).toBe(0);
  });

  it("returns exit code 0 when all servers are caution level", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("caution")),
    });
    const exitCode = await handleAudit({}, deps);
    expect(exitCode).toBe(0);
  });

  it("returns exit code 1 when any server is risky", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
    });
    const exitCode = await handleAudit({}, deps);
    expect(exitCode).toBe(1);
  });

  it("returns exit code 0 when no servers are installed", async () => {
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue([]) });
    const exitCode = await handleAudit({}, deps);
    expect(exitCode).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Findings count display
// ---------------------------------------------------------------------------

describe("handleAudit — findings display", () => {
  it("shows finding count in the table for servers with findings", async () => {
    const findings: Finding[] = [
      { severity: "high", type: "secrets", message: "API key exposed", location: "description" },
      { severity: "low", type: "exfil-args", message: "Suspicious arg", location: "env" },
    ];
    const lines: string[] = [];
    const deps = makeDeps({
      scanTier1: vi.fn().mockReturnValue(findings),
      output: (t) => lines.push(t),
    });
    await handleAudit({}, deps);
    const out = lines.join("\n");
    // Should show "2" findings in table
    expect(out).toContain("2");
  });

  it("shows 0 findings for clean servers", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      scanTier1: vi.fn().mockReturnValue([]),
      output: (t) => lines.push(t),
    });
    await handleAudit({}, deps);
    const out = lines.join("\n");
    expect(out).toContain("0");
  });
});

// ---------------------------------------------------------------------------
// --fix flag
// ---------------------------------------------------------------------------

describe("handleAudit — --fix", () => {
  // 1. No-op when --fix not set
  it("does not call getAdapter or removeFromStore when --fix is not set", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
    });
    await handleAudit({}, deps);
    expect(deps.getAdapter).not.toHaveBeenCalled();
    expect(deps.removeFromStore).not.toHaveBeenCalled();
  });

  // 2. Default threshold 50 — score 49 removed, score 50 not removed
  it("removes server with score 49 and keeps server with score 50 (default threshold)", async () => {
    const servers = [
      makeInstalledServer({ name: "io.github.test/below", clients: ["claude-desktop"] }),
      makeInstalledServer({ name: "io.github.test/at-threshold", clients: ["claude-desktop"] }),
    ];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue(servers),
      getServer: vi.fn().mockImplementation((name: string) =>
        Promise.resolve(makeServerEntry(name))
      ),
      computeTrustScore: vi.fn()
        .mockReturnValueOnce(makeTrustScore("risky", 49))
        .mockReturnValueOnce(makeTrustScore("caution", 50)),
    });
    await handleAudit({ fix: true, yes: true }, deps);
    expect(deps.removeFromStore).toHaveBeenCalledWith("io.github.test/below");
    expect(deps.removeFromStore).not.toHaveBeenCalledWith("io.github.test/at-threshold");
  });

  // 3. --min-trust overrides default — removes score-65 server
  it("removes server below custom --min-trust threshold", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("caution", 65)),
    });
    await handleAudit({ fix: true, minTrust: 70, yes: true }, deps);
    expect(deps.removeFromStore).toHaveBeenCalledWith("io.github.test/server-a");
  });

  // 4. Confirmation respected — confirm returns false → no removals
  it("does not remove servers when confirmation is declined", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
      confirm: vi.fn().mockResolvedValue(false),
    });
    const lines: string[] = [];
    await handleAudit({ fix: true }, { ...deps, output: (t) => lines.push(t) });
    expect(deps.removeFromStore).not.toHaveBeenCalled();
    expect(lines.join("\n")).toMatch(/cancel/i);
  });

  // 5. --yes bypasses confirm — confirm mock not called
  it("skips confirmation prompt when --yes is set", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
    });
    await handleAudit({ fix: true, yes: true }, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
    expect(deps.removeFromStore).toHaveBeenCalledWith("io.github.test/server-a");
  });

  // 6. Per-client error isolation — first client throws, second succeeds
  it("reports server as removed when at least one client removal succeeds", async () => {
    const removeServerFirst = vi.fn().mockRejectedValue(new Error("write failed"));
    const removeServerSecond = vi.fn().mockResolvedValue(undefined);
    const server = makeInstalledServer({
      name: "io.github.test/server-a",
      clients: ["claude-desktop", "cursor"],
    });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
      getAdapter: vi.fn()
        .mockReturnValueOnce({ removeServer: removeServerFirst })
        .mockReturnValueOnce({ removeServer: removeServerSecond }),
    });
    const lines: string[] = [];
    await handleAudit({ fix: true, yes: true }, { ...deps, output: (t) => lines.push(t) });
    expect(deps.removeFromStore).toHaveBeenCalledWith("io.github.test/server-a");
    const out = lines.join("\n");
    // One client failed, one succeeded — should report the partial failure
    expect(out).toMatch(/failed|error/i);
  });

  // 7. Per-server error isolation — first candidate fails all, second succeeds
  it("continues processing remaining candidates when one candidate fails all clients", async () => {
    const servers = [
      makeInstalledServer({ name: "io.github.test/server-fail", clients: ["claude-desktop"] }),
      makeInstalledServer({ name: "io.github.test/server-ok", clients: ["claude-desktop"] }),
    ];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue(servers),
      getServer: vi.fn().mockImplementation((name: string) =>
        Promise.resolve(makeServerEntry(name))
      ),
      computeTrustScore: vi.fn()
        .mockReturnValueOnce(makeTrustScore("risky", 20))
        .mockReturnValueOnce(makeTrustScore("risky", 20)),
      getAdapter: vi.fn()
        .mockReturnValueOnce({ removeServer: vi.fn().mockRejectedValue(new Error("disk error")) })
        .mockReturnValueOnce({ removeServer: vi.fn().mockResolvedValue(undefined) }),
    });
    await handleAudit({ fix: true, yes: true }, deps);
    expect(deps.removeFromStore).toHaveBeenCalledWith("io.github.test/server-ok");
    expect(deps.removeFromStore).not.toHaveBeenCalledWith("io.github.test/server-fail");
  });

  // 8. Registry-error servers excluded from candidates
  it("does not attempt to remove servers that have a registry error", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      getServer: vi.fn().mockRejectedValue(new Error("Registry down")),
    });
    await handleAudit({ fix: true, yes: true }, deps);
    expect(deps.removeFromStore).not.toHaveBeenCalled();
  });

  // 9. removeFromStore not called when all client removals fail
  it("does not call removeFromStore when all client removals fail", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
      getAdapter: vi.fn().mockReturnValue({
        removeServer: vi.fn().mockRejectedValue(new Error("permission denied")),
      }),
    });
    await handleAudit({ fix: true, yes: true }, deps);
    expect(deps.removeFromStore).not.toHaveBeenCalled();
  });

  // 10. getAdapter called for each clientId in server's clients list
  it("calls getAdapter for each client in the server's clients list", async () => {
    const server = makeInstalledServer({
      name: "io.github.test/server-a",
      clients: ["claude-desktop", "cursor", "vscode"],
    });
    const mockRemoveServer = vi.fn().mockResolvedValue(undefined);
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
      getAdapter: vi.fn().mockReturnValue({ removeServer: mockRemoveServer }),
    });
    await handleAudit({ fix: true, yes: true }, deps);
    expect(deps.getAdapter).toHaveBeenCalledTimes(3);
    expect(deps.getAdapter).toHaveBeenCalledWith("claude-desktop");
    expect(deps.getAdapter).toHaveBeenCalledWith("cursor");
    expect(deps.getAdapter).toHaveBeenCalledWith("vscode");
  });

  // 11. JSON output shape with --fix
  it("emits { servers, fix: { threshold, removed, failed } } when --fix and --json", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
    });
    const lines: string[] = [];
    await handleAudit({ fix: true, json: true, yes: true }, { ...deps, output: (t) => lines.push(t) });
    const parsed = JSON.parse(lines.join("\n")) as {
      servers: unknown[];
      fix: { threshold: number; removed: string[]; failed: string[] };
    };
    expect(Array.isArray(parsed.servers)).toBe(true);
    expect(parsed.fix).toBeDefined();
    expect(typeof parsed.fix.threshold).toBe("number");
    expect(Array.isArray(parsed.fix.removed)).toBe(true);
    expect(Array.isArray(parsed.fix.failed)).toBe(true);
    expect(parsed.fix.removed).toContain("io.github.test/server-a");
  });

  // 12. Non-fix JSON output unchanged (bare array regression guard)
  it("keeps bare JSON array output when --json is set without --fix", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleAudit({ json: true }, deps);
    const parsed = JSON.parse(lines.join("\n"));
    expect(Array.isArray(parsed)).toBe(true);
  });

  // 13. Exit code 1 when fix has failures
  it("returns exit code 1 when some client removals failed", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
      getAdapter: vi.fn().mockReturnValue({
        removeServer: vi.fn().mockRejectedValue(new Error("permission denied")),
      }),
    });
    const exitCode = await handleAudit({ fix: true, yes: true }, deps);
    expect(exitCode).toBe(1);
  });

  // 14. Exit code 0 when fix removes all risky servers successfully (self-healing gate)
  it("returns exit code 0 when fix successfully removes all risky servers", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("risky", 20)),
    });
    const exitCode = await handleAudit({ fix: true, yes: true }, deps);
    expect(exitCode).toBe(0);
  });

  // 15. --fix --json without --yes throws
  it("throws when --fix --json is used without --yes", async () => {
    const deps = makeDeps();
    await expect(handleAudit({ fix: true, json: true }, deps)).rejects.toThrow(
      /--fix --json requires --yes/i
    );
  });

  // 16. --min-trust without --fix throws
  it("throws when --min-trust is used without --fix", async () => {
    const deps = makeDeps();
    await expect(handleAudit({ minTrust: 70 }, deps)).rejects.toThrow(
      /--min-trust requires --fix/i
    );
  });

  // 17. No candidates → outputs "nothing to fix", no removals
  it("outputs nothing-to-fix message and skips removals when no servers are below threshold", async () => {
    const server = makeInstalledServer({ name: "io.github.test/server-a", clients: ["claude-desktop"] });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([server]),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe", 80)),
    });
    const lines: string[] = [];
    await handleAudit({ fix: true, yes: true }, { ...deps, output: (t) => lines.push(t) });
    expect(deps.removeFromStore).not.toHaveBeenCalled();
    expect(lines.join("\n")).toMatch(/nothing to fix/i);
  });
});
