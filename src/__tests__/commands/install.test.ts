/**
 * Tests for src/commands/install.ts
 *
 * TDD — RED phase: all tests written before implementation.
 * All external dependencies (registry, config, scanner, store, prompts) are mocked.
 *
 * Coverage target: 90%+
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import type { ServerEntry } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../../scanner/trust-score.js";
import type { InstalledServer } from "../../store/servers.js";

// ---------------------------------------------------------------------------
// Import under test (will fail until implementation exists)
// ---------------------------------------------------------------------------

import {
  handleInstall,
  resolveInstallEntry,
  formatTrustScore,
  validateIdentifier,
  validateRuntimeArgs,
  validateRemoteUrl,
  type InstallDeps,
  type InstallOptions,
} from "../../commands/install.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeServerEntry(overrides: Partial<ServerEntry["server"]> = {}): ServerEntry {
  return {
    server: {
      name: "io.github.test/my-server",
      version: "1.2.3",
      description: "A test MCP server",
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
      remotes: [],
      ...overrides,
    },
    _meta: {
      "io.modelcontextprotocol.registry/official": {
        status: "active",
        publishedAt: "2024-01-01T00:00:00Z",
        isLatest: true,
      },
    },
  };
}

function makeGreenTrustScore(): TrustScore {
  return {
    score: 82,
    maxPossible: 100,
    level: "safe",
    breakdown: {
      healthCheck: 15,
      staticScan: 40,
      externalScan: 20,
      registryMeta: 7,
    },
  };
}

function makeYellowTrustScore(): TrustScore {
  return {
    score: 55,
    maxPossible: 80,
    level: "caution",
    breakdown: {
      healthCheck: 15,
      staticScan: 30,
      externalScan: 0,
      registryMeta: 10,
    },
  };
}

function makeRedTrustScore(): TrustScore {
  return {
    score: 35,
    maxPossible: 80,
    level: "risky",
    breakdown: {
      healthCheck: 0,
      staticScan: 30,
      externalScan: 0,
      registryMeta: 5,
    },
  };
}

function makeAdapter(
  clientId: ClientId,
  servers: Record<string, McpServerEntry> = {}
): ConfigAdapter {
  return {
    clientId,
    read: vi.fn().mockResolvedValue(servers),
    listServers: vi.fn().mockResolvedValue(servers),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
  };
}

function makeDeps(overrides: Partial<InstallDeps> = {}): InstallDeps {
  return {
    registryClient: {
      getServer: vi.fn().mockResolvedValue(makeServerEntry()),
    },
    detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    getAdapter: vi.fn().mockImplementation((id: ClientId) => makeAdapter(id)),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    scanTier1: vi.fn().mockReturnValue([] as Finding[]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([] as Finding[]),
    computeTrustScore: vi.fn().mockReturnValue(makeGreenTrustScore()),
    addToStore: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    promptEnvVars: vi.fn().mockResolvedValue({} as Record<string, string>),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Happy path — GREEN trust score
// ---------------------------------------------------------------------------

describe("handleInstall — happy path (GREEN trust score)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("fetches server metadata from registry", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.registryClient.getServer).toHaveBeenCalledWith("io.github.test/my-server");
  });

  it("runs tier-1 scanner on fetched metadata", async () => {
    const serverEntry = makeServerEntry();
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(serverEntry) },
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.scanTier1).toHaveBeenCalledWith(serverEntry);
  });

  it("checks if tier-2 scanner is available", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.checkScannerAvailable).toHaveBeenCalled();
  });

  it("computes trust score with findings and metadata", async () => {
    const findings: Finding[] = [];
    const serverEntry = makeServerEntry();
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(serverEntry) },
      scanTier1: vi.fn().mockReturnValue(findings),
      checkScannerAvailable: vi.fn().mockResolvedValue(false),
    });
    await handleInstall("io.github.test/my-server", {}, deps);

    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({
        findings,
        hasExternalScanner: false,
        healthCheckPassed: null,
      }) satisfies Partial<TrustScoreInput>
    );
  });

  it("displays trust score output", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    // Should display score numbers
    expect(allOutput).toMatch(/82/);
  });

  it("detects installed clients", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.detectClients).toHaveBeenCalled();
  });

  it("asks for install confirmation", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.confirm).toHaveBeenCalled();
  });

  it("writes server config via adapter.addServer", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(adapter.addServer).toHaveBeenCalledWith(
      "/fake/claude-desktop/config.json",
      "io.github.test/my-server",
      expect.objectContaining({ command: "npx" })
    );
  });

  it("records in store via addToStore", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.addToStore).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "io.github.test/my-server",
        version: "1.2.3",
        clients: ["claude-desktop"],
      }) satisfies Partial<InstalledServer>
    );
  });

  it("outputs a success message", async () => {
    const deps = makeDeps();
    await handleInstall("io.github.test/my-server", {}, deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/install/i);
    expect(allOutput).toMatch(/my-server/);
  });
});

// ---------------------------------------------------------------------------
// Trust score: YELLOW caution
// ---------------------------------------------------------------------------

describe("handleInstall — YELLOW trust score", () => {
  it("displays caution message for yellow trust score", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeYellowTrustScore()),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/caution/i);
  });

  it("still prompts for confirmation on yellow", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeYellowTrustScore()),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.confirm).toHaveBeenCalled();
  });

  it("proceeds with install if user confirms on yellow", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      computeTrustScore: vi.fn().mockReturnValue(makeYellowTrustScore()),
      confirm: vi.fn().mockResolvedValue(true),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(adapter.addServer).toHaveBeenCalled();
  });

  it("aborts on yellow if user declines confirmation", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      computeTrustScore: vi.fn().mockReturnValue(makeYellowTrustScore()),
      confirm: vi.fn().mockResolvedValue(false),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(deps.addToStore).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Trust score: RED risky
// ---------------------------------------------------------------------------

describe("handleInstall — RED trust score", () => {
  it("displays strong warning for red trust score", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeRedTrustScore()),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/risk|danger|warn/i);
  });

  it("prompts with explicit warning for red trust score", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeRedTrustScore()),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    const confirmCall = (deps.confirm as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(confirmCall).toMatch(/risk|danger|understand/i);
  });

  it("aborts if user declines RED confirmation", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      computeTrustScore: vi.fn().mockReturnValue(makeRedTrustScore()),
      confirm: vi.fn().mockResolvedValue(false),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(deps.addToStore).not.toHaveBeenCalled();
  });

  it("outputs cancellation message when declined on RED", async () => {
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(makeRedTrustScore()),
      confirm: vi.fn().mockResolvedValue(false),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/cancel|abort/i);
  });

  it("proceeds with install when user confirms RED with explicit yes", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      computeTrustScore: vi.fn().mockReturnValue(makeRedTrustScore()),
      confirm: vi.fn().mockResolvedValue(true),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(adapter.addServer).toHaveBeenCalled();
  });

  it("skips RED confirmation prompt with --yes flag", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      computeTrustScore: vi.fn().mockReturnValue(makeRedTrustScore()),
      confirm: vi.fn().mockResolvedValue(false), // would decline if asked
    });
    // With --yes, confirm should NOT be called (skip all prompts)
    await handleInstall("io.github.test/my-server", { yes: true }, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
    expect(adapter.addServer).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// --client flag
// ---------------------------------------------------------------------------

describe("handleInstall — --client flag", () => {
  it("installs only to the specified client", async () => {
    const claudeAdapter = makeAdapter("claude-desktop");
    const cursorAdapter = makeAdapter("cursor");
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => {
        if (id === "claude-desktop") return claudeAdapter;
        if (id === "cursor") return cursorAdapter;
        return makeAdapter(id);
      }),
    });

    await handleInstall("io.github.test/my-server", { client: "cursor" }, deps);

    expect(cursorAdapter.addServer).toHaveBeenCalled();
    expect(claudeAdapter.addServer).not.toHaveBeenCalled();
  });

  it("throws if specified --client is not installed", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    });
    await expect(
      handleInstall("io.github.test/my-server", { client: "vscode" }, deps)
    ).rejects.toThrow(/vscode.*not.*install/i);
  });

  it("records only the specified client in the store", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => makeAdapter(id)),
    });

    await handleInstall("io.github.test/my-server", { client: "claude-desktop" }, deps);

    expect(deps.addToStore).toHaveBeenCalledWith(
      expect.objectContaining({ clients: ["claude-desktop"] })
    );
  });
});

// ---------------------------------------------------------------------------
// --force flag
// ---------------------------------------------------------------------------

describe("handleInstall — --force flag", () => {
  it("throws if server already installed and --force not set", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "io.github.test/my-server": { command: "npx", args: ["-y", "@test/my-server"] },
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await expect(
      handleInstall("io.github.test/my-server", {}, deps)
    ).rejects.toThrow(/already install/i);
  });

  it("overwrites existing server when --force is set", async () => {
    const adapter = makeAdapter("claude-desktop", {
      "io.github.test/my-server": { command: "npx", args: ["-y", "@test/my-server"] },
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await expect(
      handleInstall("io.github.test/my-server", { force: true }, deps)
    ).resolves.not.toThrow();
    expect(adapter.addServer).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Server with no packages and no remotes
// ---------------------------------------------------------------------------

describe("handleInstall — server with no install path", () => {
  it("throws error when server has no packages and no remotes", async () => {
    const deps = makeDeps({
      registryClient: {
        getServer: vi.fn().mockResolvedValue(
          makeServerEntry({ packages: [], remotes: [] })
        ),
      },
    });
    await expect(
      handleInstall("io.github.test/my-server", {}, deps)
    ).rejects.toThrow(/no install/i);
  });
});

// ---------------------------------------------------------------------------
// Env var prompting
// ---------------------------------------------------------------------------

describe("handleInstall — env var prompting", () => {
  it("prompts for required env vars from the server package", async () => {
    const serverEntry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [
            { name: "API_KEY", description: "Your API key", isRequired: true, isSecret: true },
          ],
          runtimeArguments: [],
        },
      ],
    });
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(serverEntry) },
      promptEnvVars: vi.fn().mockResolvedValue({ API_KEY: "secret-value" }),
    });
    await handleInstall("io.github.test/my-server", {}, deps);

    expect(deps.promptEnvVars).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ name: "API_KEY" }),
      ])
    );
  });

  it("includes resolved env vars in the installed config entry", async () => {
    const serverEntry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [
            { name: "API_KEY", isRequired: true, isSecret: true },
          ],
          runtimeArguments: [],
        },
      ],
    });
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(serverEntry) },
      getAdapter: vi.fn().mockReturnValue(adapter),
      promptEnvVars: vi.fn().mockResolvedValue({ API_KEY: "secret-value" }),
    });
    await handleInstall("io.github.test/my-server", {}, deps);

    expect(adapter.addServer).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.objectContaining({ env: { API_KEY: "secret-value" } })
    );
  });

  it("skips env var prompting with --yes when no vars are required", async () => {
    const deps = makeDeps({ yes: true } as Partial<InstallOptions> & Partial<InstallDeps>);
    deps.promptEnvVars = vi.fn().mockResolvedValue({});
    await handleInstall("io.github.test/my-server", { yes: true }, deps);
    // promptEnvVars may still be called with empty array — that's fine
    // but for servers with no env vars, no prompts should appear
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    // Just verify it didn't throw and completed successfully
    expect(deps.addToStore).toHaveBeenCalled();
    void allOutput;
  });
});

// ---------------------------------------------------------------------------
// --skip-health-check flag
// ---------------------------------------------------------------------------

describe("handleInstall — --skip-health-check flag", () => {
  it("passes healthCheckPassed=null when --skip-health-check is set", async () => {
    const deps = makeDeps();
    await handleInstall(
      "io.github.test/my-server",
      { skipHealthCheck: true },
      deps
    );
    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({ healthCheckPassed: null })
    );
  });
});

// ---------------------------------------------------------------------------
// --json output
// ---------------------------------------------------------------------------

describe("handleInstall — --json flag", () => {
  it("outputs valid JSON when --json flag is set", async () => {
    const capturedOutput: string[] = [];
    const deps = makeDeps({
      output: (text: string) => capturedOutput.push(text),
    });
    await handleInstall("io.github.test/my-server", { json: true }, deps);
    const jsonString = capturedOutput.join("\n");
    expect(() => JSON.parse(jsonString)).not.toThrow();
  });

  it("JSON output includes server name and clients installed", async () => {
    const capturedOutput: string[] = [];
    const deps = makeDeps({
      output: (text: string) => capturedOutput.push(text),
    });
    await handleInstall("io.github.test/my-server", { json: true }, deps);
    const result = JSON.parse(capturedOutput.join("\n")) as Record<string, unknown>;
    expect(result).toMatchObject({
      name: "io.github.test/my-server",
      clients: expect.arrayContaining(["claude-desktop"]),
    });
  });

  it("JSON output includes trust score", async () => {
    const capturedOutput: string[] = [];
    const deps = makeDeps({
      output: (text: string) => capturedOutput.push(text),
    });
    await handleInstall("io.github.test/my-server", { json: true }, deps);
    const result = JSON.parse(capturedOutput.join("\n")) as Record<string, unknown>;
    expect(result).toHaveProperty("trustScore");
  });
});

// ---------------------------------------------------------------------------
// resolveInstallEntry — pure function
// ---------------------------------------------------------------------------

describe("resolveInstallEntry — npm package", () => {
  it("produces npx command for npm packages", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.command).toBe("npx");
    expect(entry.args).toEqual(expect.arrayContaining(["-y", "@test/my-server"]));
  });

  it("includes runtime arguments in the args array", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: ["--verbose", "--port=3000"],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.args).toContain("--verbose");
    expect(entry.args).toContain("--port=3000");
  });
});

describe("resolveInstallEntry — pypi package", () => {
  it("produces uvx command for pypi packages", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "pypi",
          identifier: "my-python-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.command).toBe("uvx");
    expect(entry.args).toContain("my-python-server");
  });
});

describe("resolveInstallEntry — docker/oci package", () => {
  it("produces docker run command for oci packages", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "oci",
          identifier: "my-org/my-server:latest",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.command).toBe("docker");
    expect(entry.args).toEqual(
      expect.arrayContaining(["run", "--rm", "-i", "my-org/my-server:latest"])
    );
  });
});

describe("resolveInstallEntry — HTTP remote (Cursor prefers HTTP)", () => {
  it("produces url entry for Cursor when HTTP remote is available", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "cursor");
    expect(entry.url).toBe("https://api.example.com/mcp");
    expect(entry.command).toBeUndefined();
  });

  it("uses npm package for Cursor when no HTTP remote available", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
      remotes: [],
    });
    const entry = resolveInstallEntry(server, "cursor");
    expect(entry.command).toBe("npx");
    expect(entry.url).toBeUndefined();
  });

  it("non-Cursor clients use npm even when HTTP remote is available", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [],
        },
      ],
    });

    for (const clientId of ["claude-desktop", "vscode", "windsurf"] as ClientId[]) {
      const entry = resolveInstallEntry(server, clientId);
      expect(entry.command).toBe("npx");
      expect(entry.url).toBeUndefined();
    }
  });
});

describe("resolveInstallEntry — fallback priority: npm → pypi → oci", () => {
  it("prefers npm over pypi when both present", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "pypi",
          identifier: "my-python-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.command).toBe("npx");
  });

  it("falls back to pypi when no npm present", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "oci",
          identifier: "my-org/my-server:latest",
          environmentVariables: [],
          runtimeArguments: [],
        },
        {
          registryType: "pypi",
          identifier: "my-python-server",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.command).toBe("uvx");
  });

  it("falls back to docker when only oci present", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "oci",
          identifier: "my-org/my-server:latest",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "claude-desktop");
    expect(entry.command).toBe("docker");
  });
});

describe("resolveInstallEntry — error on no install path", () => {
  it("throws error when no packages and no remotes", () => {
    const server = makeServerEntry({ packages: [], remotes: [] });
    expect(() => resolveInstallEntry(server, "claude-desktop")).toThrow(
      /no install/i
    );
  });

  it("throws error when no packages and remotes but client is not Cursor", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [],
        },
      ],
    });
    // Non-Cursor clients cannot use HTTP remotes (they need stdio)
    expect(() => resolveInstallEntry(server, "claude-desktop")).toThrow(/no install/i);
  });

  it("cursor can install HTTP-only server (no packages)", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "cursor");
    expect(entry.url).toBe("https://api.example.com/mcp");
  });
});

describe("resolveInstallEntry — immutability", () => {
  it("returns a new object and does not mutate the server entry", () => {
    const server = makeServerEntry();
    const originalPackages = server.server.packages;
    resolveInstallEntry(server, "claude-desktop");
    expect(server.server.packages).toBe(originalPackages);
  });
});

// ---------------------------------------------------------------------------
// formatTrustScore — display formatting
// ---------------------------------------------------------------------------

describe("formatTrustScore", () => {
  it("returns a string containing the score numbers", () => {
    const trustScore = makeGreenTrustScore();
    const output = formatTrustScore(trustScore);
    expect(output).toMatch(/82/);
    expect(output).toMatch(/100/);
  });

  it("contains bar characters for visual representation", () => {
    const trustScore = makeGreenTrustScore();
    const output = formatTrustScore(trustScore);
    // Should contain block characters (full or empty) for the bar
    expect(output).toMatch(/[█░▓▒]/);
  });

  it("contains SAFE label for green trust score", () => {
    const trustScore = makeGreenTrustScore();
    const output = formatTrustScore(trustScore);
    // Strip ANSI codes for testing
    const stripped = output.replace(/\x1B\[[0-9;]*m/g, "");
    expect(stripped).toMatch(/safe/i);
  });

  it("contains CAUTION label for yellow trust score", () => {
    const trustScore = makeYellowTrustScore();
    const output = formatTrustScore(trustScore);
    const stripped = output.replace(/\x1B\[[0-9;]*m/g, "");
    expect(stripped).toMatch(/caution/i);
  });

  it("contains RISKY label for red trust score", () => {
    const trustScore = makeRedTrustScore();
    const output = formatTrustScore(trustScore);
    const stripped = output.replace(/\x1B\[[0-9;]*m/g, "");
    expect(stripped).toMatch(/risky/i);
  });

  it("includes breakdown details in the output", () => {
    const trustScore = makeGreenTrustScore();
    const output = formatTrustScore(trustScore);
    const stripped = output.replace(/\x1B\[[0-9;]*m/g, "");
    // Should show some breakdown info
    expect(stripped).toMatch(/tool|health|scan|package|publisher/i);
  });
});

// ---------------------------------------------------------------------------
// Tier-2 scanner integration
// ---------------------------------------------------------------------------

describe("handleInstall — tier-2 scanner integration", () => {
  it("runs tier-2 scan when scanner is available", async () => {
    const tier2Findings: Finding[] = [
      { severity: "medium", type: "prompt-injection", message: "Possible injection", location: "external scan" },
    ];
    const deps = makeDeps({
      checkScannerAvailable: vi.fn().mockResolvedValue(true),
      scanTier2: vi.fn().mockResolvedValue(tier2Findings),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.scanTier2).toHaveBeenCalledWith("io.github.test/my-server");
  });

  it("does not run tier-2 scan when scanner is not available", async () => {
    const deps = makeDeps({
      checkScannerAvailable: vi.fn().mockResolvedValue(false),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.scanTier2).not.toHaveBeenCalled();
  });

  it("passes combined tier1+tier2 findings to computeTrustScore when scanner available", async () => {
    const tier1Findings: Finding[] = [
      { severity: "low", type: "typosquatting", message: "Possible typosquat", location: "server name" },
    ];
    const tier2Findings: Finding[] = [
      { severity: "high", type: "prompt-injection", message: "External finding", location: "external scan" },
    ];
    const deps = makeDeps({
      scanTier1: vi.fn().mockReturnValue(tier1Findings),
      checkScannerAvailable: vi.fn().mockResolvedValue(true),
      scanTier2: vi.fn().mockResolvedValue(tier2Findings),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(deps.computeTrustScore).toHaveBeenCalledWith(
      expect.objectContaining({
        findings: expect.arrayContaining([
          expect.objectContaining({ severity: "low", type: "typosquatting" }),
          expect.objectContaining({ severity: "high", type: "prompt-injection" }),
        ]),
        hasExternalScanner: true,
      })
    );
  });
});

// ---------------------------------------------------------------------------
// Registry fetch failure
// ---------------------------------------------------------------------------

describe("handleInstall — registry errors", () => {
  it("propagates registry fetch errors", async () => {
    const deps = makeDeps({
      registryClient: {
        getServer: vi.fn().mockRejectedValue(new Error("Server not found")),
      },
    });
    await expect(
      handleInstall("does-not-exist/server", {}, deps)
    ).rejects.toThrow("Server not found");
  });
});

// ---------------------------------------------------------------------------
// Multiple clients — all selected
// ---------------------------------------------------------------------------

describe("handleInstall — multiple clients", () => {
  it("installs to all detected clients when none specified", async () => {
    const claudeAdapter = makeAdapter("claude-desktop");
    const cursorAdapter = makeAdapter("cursor");
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => {
        if (id === "claude-desktop") return claudeAdapter;
        if (id === "cursor") return cursorAdapter;
        return makeAdapter(id);
      }),
    });

    await handleInstall("io.github.test/my-server", {}, deps);

    expect(claudeAdapter.addServer).toHaveBeenCalled();
    expect(cursorAdapter.addServer).toHaveBeenCalled();
  });

  it("records all installed clients in the store", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) => makeAdapter(id)),
    });

    await handleInstall("io.github.test/my-server", {}, deps);

    expect(deps.addToStore).toHaveBeenCalledWith(
      expect.objectContaining({
        clients: expect.arrayContaining(["claude-desktop", "cursor"]),
      })
    );
  });
});

// ---------------------------------------------------------------------------
// No installed clients
// ---------------------------------------------------------------------------

describe("handleInstall — no clients detected", () => {
  it("throws error when no clients are detected", async () => {
    const deps = makeDeps({
      detectClients: vi.fn().mockResolvedValue([] as ClientId[]),
    });
    await expect(
      handleInstall("io.github.test/my-server", {}, deps)
    ).rejects.toThrow(/no.*client|client.*not.*found/i);
  });
});

// ---------------------------------------------------------------------------
// resolveInstallEntry — HTTP remote with headers for Cursor
// ---------------------------------------------------------------------------

describe("resolveInstallEntry — HTTP remote with headers", () => {
  it("includes headers object in the entry for Cursor when remote has headers", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [
            { name: "Authorization", isRequired: true, isSecret: true },
            { name: "X-API-Version", isRequired: false },
          ],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "cursor");
    expect(entry.url).toBe("https://api.example.com/mcp");
    expect(entry.headers).toBeDefined();
    expect(entry.headers).toHaveProperty("Authorization");
    expect(entry.headers).toHaveProperty("X-API-Version");
  });

  it("does not include headers key when remote has no headers", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "cursor");
    expect(entry.url).toBe("https://api.example.com/mcp");
    expect(entry.headers).toBeUndefined();
  });

  it("uses SSE remote type for Cursor when available", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "sse",
          url: "https://api.example.com/sse",
          headers: [],
        },
      ],
    });
    const entry = resolveInstallEntry(server, "cursor");
    expect(entry.url).toBe("https://api.example.com/sse");
  });
});

// ---------------------------------------------------------------------------
// validateIdentifier — security: reject malicious package identifiers
// ---------------------------------------------------------------------------

describe("validateIdentifier — npm", () => {
  it("accepts valid scoped npm packages", () => {
    expect(() => validateIdentifier("@modelcontextprotocol/server-filesystem", "npm")).not.toThrow();
  });

  it("accepts valid unscoped npm packages", () => {
    expect(() => validateIdentifier("my-server", "npm")).not.toThrow();
  });

  it("rejects npm identifiers with shell metacharacters", () => {
    expect(() => validateIdentifier("my-server; rm -rf /", "npm")).toThrow(/malicious/i);
  });

  it("rejects npm identifiers with backticks", () => {
    expect(() => validateIdentifier("`whoami`", "npm")).toThrow(/malicious/i);
  });

  it("rejects npm identifiers with path traversal", () => {
    expect(() => validateIdentifier("../../etc/passwd", "npm")).toThrow(/malicious/i);
  });
});

describe("validateIdentifier — pypi", () => {
  it("accepts valid pypi package names", () => {
    expect(() => validateIdentifier("mcp-server-filesystem", "pypi")).not.toThrow();
  });

  it("accepts mixed-case pypi package names", () => {
    expect(() => validateIdentifier("MyServer", "pypi")).not.toThrow();
  });

  it("rejects pypi identifiers with shell metacharacters", () => {
    expect(() => validateIdentifier("server && curl http://evil.com", "pypi")).toThrow(/malicious/i);
  });
});

describe("validateIdentifier — oci", () => {
  it("accepts valid OCI image references with tag", () => {
    expect(() => validateIdentifier("my-org/my-server:latest", "oci")).not.toThrow();
  });

  it("rejects OCI identifiers with shell metacharacters", () => {
    expect(() => validateIdentifier("myimage:latest; id", "oci")).toThrow(/malicious/i);
  });

  it("rejects OCI identifiers without a tag", () => {
    expect(() => validateIdentifier("my-org/my-server", "oci")).toThrow(/malicious/i);
  });
});

describe("validateIdentifier — unknown registry type", () => {
  it("does not throw for unknown registry types (no pattern to match)", () => {
    expect(() => validateIdentifier("anything goes", "custom")).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// validateRuntimeArgs — security: reject dangerous flags
// ---------------------------------------------------------------------------

describe("validateRuntimeArgs", () => {
  it("accepts normal runtime arguments", () => {
    expect(() => validateRuntimeArgs(["--port=3000", "--verbose"])).not.toThrow();
  });

  it("rejects --eval flag", () => {
    expect(() => validateRuntimeArgs(["--eval=process.exit()"])).toThrow(/dangerous/i);
  });

  it("rejects --require flag", () => {
    expect(() => validateRuntimeArgs(["--require", "/tmp/malicious.js"])).toThrow(/dangerous/i);
  });

  it("rejects --inspect flag", () => {
    expect(() => validateRuntimeArgs(["--inspect=0.0.0.0:9229"])).toThrow(/dangerous/i);
  });

  it("rejects -e flag (shorthand for --eval)", () => {
    expect(() => validateRuntimeArgs(["-e", "require('child_process').exec('id')"])).toThrow(/dangerous/i);
  });

  it("rejects --import flag", () => {
    expect(() => validateRuntimeArgs(["--import=/tmp/malicious.mjs"])).toThrow(/dangerous/i);
  });

  it("rejects arguments containing path traversal (..)", () => {
    expect(() => validateRuntimeArgs(["../../etc/passwd"])).toThrow(/dangerous/i);
  });

  it("accepts empty array", () => {
    expect(() => validateRuntimeArgs([])).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// resolveInstallEntry — injection validation is called
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// validateRemoteUrl — security: reject non-http/https URLs
// ---------------------------------------------------------------------------

describe("validateRemoteUrl", () => {
  it("accepts https URLs", () => {
    expect(() => validateRemoteUrl("https://api.example.com/mcp")).not.toThrow();
  });

  it("accepts http URLs", () => {
    expect(() => validateRemoteUrl("http://localhost:3000/mcp")).not.toThrow();
  });

  it("rejects file:// URLs", () => {
    expect(() => validateRemoteUrl("file:///etc/passwd")).toThrow(/http or https/i);
  });

  it("rejects javascript: URLs", () => {
    expect(() => validateRemoteUrl("javascript:alert(1)")).toThrow(/http or https/i);
  });

  it("rejects data: URLs", () => {
    expect(() => validateRemoteUrl("data:text/html,<script>alert(1)</script>")).toThrow(/http or https/i);
  });

  it("rejects totally invalid URLs", () => {
    expect(() => validateRemoteUrl("not a url at all")).toThrow(/invalid remote url/i);
  });
});

// ---------------------------------------------------------------------------
// resolveInstallEntry — URL validation is called for HTTP remotes
// ---------------------------------------------------------------------------

describe("resolveInstallEntry — remote URL validation", () => {
  it("accepts a valid https remote URL for Cursor", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "cursor")).not.toThrow();
  });

  it("throws for a file:// remote URL for Cursor", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "file:///etc/passwd",
          headers: [],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "cursor")).toThrow(/http or https/i);
  });

  it("throws for a javascript: remote URL for Cursor", () => {
    const server = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "javascript:alert(1)",
          headers: [],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "cursor")).toThrow(/http or https/i);
  });
});

describe("resolveInstallEntry — identifier validation", () => {
  it("throws for a malicious npm identifier", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/server; rm -rf /",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "claude-desktop")).toThrow(/malicious/i);
  });

  it("throws for a dangerous runtime arg in npm package", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [],
          runtimeArguments: ["--eval=evil()"],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "claude-desktop")).toThrow(/dangerous/i);
  });

  it("throws for a malicious pypi identifier", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "pypi",
          identifier: "server && curl http://evil.com",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "claude-desktop")).toThrow(/malicious/i);
  });

  it("throws for a malicious oci identifier", () => {
    const server = makeServerEntry({
      packages: [
        {
          registryType: "oci",
          identifier: "myimage:latest; id",
          environmentVariables: [],
          runtimeArguments: [],
        },
      ],
    });
    expect(() => resolveInstallEntry(server, "claude-desktop")).toThrow(/malicious/i);
  });
});

// ---------------------------------------------------------------------------
// handleInstall — env vars merged into entry correctly
// ---------------------------------------------------------------------------

describe("handleInstall — no env vars on server", () => {
  it("does not include env field when no env vars resolved", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      promptEnvVars: vi.fn().mockResolvedValue({}),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    expect(adapter.addServer).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      expect.not.objectContaining({ env: expect.anything() })
    );
  });
});

// ---------------------------------------------------------------------------
// handleInstall — --force + overwrite path
// ---------------------------------------------------------------------------

describe("handleInstall — --force on already installed server", () => {
  it("calls addServer even if server exists when --force is set", async () => {
    const existingEntry: McpServerEntry = { command: "npx", args: ["-y", "@test/my-server"] };
    const adapter = makeAdapter("claude-desktop", {
      "io.github.test/my-server": existingEntry,
    });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await handleInstall("io.github.test/my-server", { force: true }, deps);
    expect(adapter.addServer).toHaveBeenCalled();
    expect(deps.addToStore).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// formatTrustScore — edge cases
// ---------------------------------------------------------------------------

describe("formatTrustScore — edge cases", () => {
  it("handles score of 0 gracefully (all empty bar)", () => {
    const score: TrustScore = {
      score: 0,
      maxPossible: 80,
      level: "risky",
      breakdown: { healthCheck: 0, staticScan: 0, externalScan: 0, registryMeta: 0 },
    };
    const result = formatTrustScore(score);
    expect(result).toMatch(/0\/80/);
    const stripped = result.replace(/\x1B\[[0-9;]*m/g, "");
    expect(stripped).toMatch(/risky/i);
  });

  it("handles maximum score of 100/100 (all full bar)", () => {
    const score: TrustScore = {
      score: 100,
      maxPossible: 100,
      level: "safe",
      breakdown: { healthCheck: 30, staticScan: 40, externalScan: 20, registryMeta: 10 },
    };
    const result = formatTrustScore(score);
    expect(result).toMatch(/100\/100/);
    const stripped = result.replace(/\x1B\[[0-9;]*m/g, "");
    expect(stripped).toMatch(/safe/i);
  });

  it("shows external scan score when available", () => {
    const score: TrustScore = {
      score: 100,
      maxPossible: 100,
      level: "safe",
      breakdown: { healthCheck: 30, staticScan: 40, externalScan: 20, registryMeta: 10 },
    };
    const result = formatTrustScore(score);
    const stripped = result.replace(/\x1B\[[0-9;]*m/g, "");
    // External scan score > 0 means it should show "passed"
    expect(stripped).toMatch(/passed/i);
  });

  it("shows failed or skipped when healthCheck is 0", () => {
    const score: TrustScore = {
      score: 40,
      maxPossible: 80,
      level: "caution",
      breakdown: { healthCheck: 0, staticScan: 35, externalScan: 0, registryMeta: 5 },
    };
    const result = formatTrustScore(score);
    const stripped = result.replace(/\x1B\[[0-9;]*m/g, "");
    expect(stripped).toMatch(/failed|skipped/i);
  });
});

// ---------------------------------------------------------------------------
// Plaintext secret warning (FINDING-08)
// ---------------------------------------------------------------------------

describe("handleInstall — plaintext secret warning", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("emits a plaintext storage warning when a secret env var is written", async () => {
    const serverEntry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          runtimeArguments: [],
          environmentVariables: [
            { name: "API_KEY", description: "The API key", isRequired: true, isSecret: true },
          ],
        },
      ],
    });
    const lines: string[] = [];
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(serverEntry) },
      promptEnvVars: vi.fn().mockResolvedValue({ API_KEY: "sk-supersecret" }),
      output: (t) => lines.push(t),
    });
    await handleInstall("io.github.test/my-server", {}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/plaintext|chmod|permissions/i);
  });

  it("does not emit plaintext warning when no secret env vars are present", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInstall("io.github.test/my-server", {}, deps);
    const out = lines.join("\n");
    expect(out).not.toMatch(/plaintext/i);
  });

  it("does not emit plaintext warning in --json mode", async () => {
    const serverEntry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          runtimeArguments: [],
          environmentVariables: [
            { name: "API_KEY", description: "The API key", isRequired: true, isSecret: true },
          ],
        },
      ],
    });
    const lines: string[] = [];
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(serverEntry) },
      promptEnvVars: vi.fn().mockResolvedValue({ API_KEY: "sk-supersecret" }),
      output: (t) => lines.push(t),
    });
    await handleInstall("io.github.test/my-server", { yes: true, json: true }, deps);
    // In JSON mode, all lines should be parseable JSON (no warning text)
    const out = lines.join("\n");
    expect(out).not.toMatch(/plaintext/i);
  });
});
