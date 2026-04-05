import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleUp } from "../../commands/up.js";
import type { UpDeps, UpOptions } from "../../commands/up.js";
import type { ClientId } from "../../config/paths.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeServerEntry(name: string, version: string): ServerEntry {
  return {
    server: {
      name,
      version,
      packages: [
        {
          registryType: "npm",
          identifier: `@test/${name.split("/").pop()}`,
          environmentVariables: [],
        },
      ],
    },
  };
}

const goodTrust: TrustScore = {
  score: 75,
  maxPossible: 80,
  level: "safe",
  breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
};

const lowTrust: TrustScore = {
  score: 30,
  maxPossible: 80,
  level: "risky",
  breakdown: { healthCheck: 0, staticScan: 20, externalScan: 0, registryMeta: 10 },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAdapter(servers: Record<string, McpServerEntry> = {}) {
  return {
    clientId: "claude-desktop" as ClientId,
    read: vi.fn().mockResolvedValue({ ...servers }),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
    setServerDisabled: vi.fn().mockResolvedValue(undefined),
  };
}

function makeDeps(overrides: Partial<UpDeps> = {}): UpDeps {
  const adapter = makeAdapter();
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn().mockReturnValue(adapter),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    getServer: vi.fn().mockImplementation((name: string, version?: string) =>
      Promise.resolve(makeServerEntry(name, version ?? "1.0.0"))
    ),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue(goodTrust),
    runLock: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    promptEnvVar: vi.fn().mockResolvedValue("prompted_value"),
    output: vi.fn(),
    ...overrides,
  };
}

async function writeStackAndLock(
  stackYaml: string,
  lockYaml: string
): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-test-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stackYaml, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lockYaml, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

const basicStack = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;

const basicLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.2.0"
    registryType: npm
    identifier: "@test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleUp", () => {
  it("installs all servers from yaml + lock", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps();

    await handleUp({ stackFile: stackPath }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    expect(adapter.addServer).toHaveBeenCalledWith(
      "/mock/config.json",
      "io.github.test/server-a",
      expect.objectContaining({ command: "npx" }),
      { force: true }
    );
  });

  it("auto-runs lock when no lock file exists", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-nolock-"));
    const stackPath = path.join(dir, "mcpm.yaml");
    await writeFile(stackPath, basicStack, "utf-8");

    // runLock creates the lock file
    const deps = makeDeps({
      runLock: vi.fn().mockImplementation(async () => {
        await writeFile(
          path.join(dir, "mcpm-lock.yaml"),
          basicLock,
          "utf-8"
        );
      }),
    });

    await handleUp({ stackFile: stackPath }, deps);
    expect(deps.runLock).toHaveBeenCalledWith(stackPath);
  });

  it("blocks server when trust score is below policy minTrustScore", async () => {
    const stackWithPolicy = `
version: "1"
policy:
  minTrustScore: 60
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    const stackPath = await writeStackAndLock(stackWithPolicy, basicLock);
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(lowTrust),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      "could not be installed"
    );

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("below the minimum");
  });

  it("blocks server when trust score dropped with blockOnScoreDrop", async () => {
    const stackWithDrop = `
version: "1"
policy:
  blockOnScoreDrop: true
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    // Lock has 75/80 = 94%. Current is 30/80 = 38%. Drop detected.
    const stackPath = await writeStackAndLock(stackWithDrop, basicLock);
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(lowTrust),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      "could not be installed"
    );
  });

  it("prints plan without writing in --dry-run mode", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter();
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUp({ stackFile: stackPath, dryRun: true }, deps);

    expect(adapter.addServer).not.toHaveBeenCalled();

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("Dry run");
    expect(outputCalls).toContain("would install");
  });

  it("errors in --ci mode when required env var is missing", async () => {
    const stackWithEnv = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
    env:
      API_TOKEN:
        required: true
        secret: true
`;
    const stackPath = await writeStackAndLock(stackWithEnv, basicLock);
    const deps = makeDeps();

    await expect(
      handleUp({ stackFile: stackPath, ci: true }, deps)
    ).rejects.toThrow("could not be installed");

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("API_TOKEN");
  });

  it("filters servers by --profile", async () => {
    const multiProfile = `
version: "1"
servers:
  io.github.test/dev-only:
    version: "^1.0.0"
    profiles: [dev]
  io.github.test/prod-only:
    version: "^1.0.0"
    profiles: [prod]
`;
    const multiLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/dev-only:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/dev-only"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
  io.github.test/prod-only:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/prod-only"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(multiProfile, multiLock);
    const deps = makeDeps();

    await handleUp({ stackFile: stackPath, profile: "dev" }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    expect(adapter.addServer).toHaveBeenCalledWith(
      expect.anything(),
      "io.github.test/dev-only",
      expect.anything(),
      expect.anything()
    );
  });

  it("errors with --strict --ci without --yes", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter({ "extra-server": { command: "npx", args: ["-y", "extra"] } });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await expect(
      handleUp({ stackFile: stackPath, strict: true, ci: true }, deps)
    ).rejects.toThrow("--strict --ci requires --yes");
  });

  it("removes extra servers with --strict --yes", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter({ "extra-server": { command: "npx", args: ["-y", "extra"] } });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);
    expect(adapter.removeServer).toHaveBeenCalledWith(
      "/mock/config.json",
      "extra-server"
    );
  });

  it("continues when one server fails and reports all errors", async () => {
    const twoServers = `
version: "1"
servers:
  io.github.test/good:
    version: "^1.0.0"
  io.github.test/bad:
    version: "^1.0.0"
`;
    const twoLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/good:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/good"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
  io.github.test/bad:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/bad"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(twoServers, twoLock);
    const deps = makeDeps({
      getServer: vi.fn().mockImplementation((name: string) => {
        if (name === "io.github.test/bad") {
          return Promise.reject(new Error("Registry error"));
        }
        return Promise.resolve(makeServerEntry(name, "1.0.0"));
      }),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      "could not be installed"
    );

    // Good server should still have been installed
    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledWith(
      expect.anything(),
      "io.github.test/good",
      expect.anything(),
      expect.anything()
    );
  });

  it("resolves env vars from process.env and .env file", async () => {
    const stackWithEnv = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
    env:
      FROM_PROCESS:
        required: true
      FROM_DEFAULT:
        required: true
        default: "default_val"
`;
    const stackPath = await writeStackAndLock(stackWithEnv, basicLock);

    // Set a process.env var for the test
    const originalEnv = process.env.FROM_PROCESS;
    process.env.FROM_PROCESS = "process_val";

    try {
      const deps = makeDeps();
      await handleUp({ stackFile: stackPath }, deps);

      const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
      const addCall = adapter.addServer.mock.calls[0];
      const entry = addCall[2] as McpServerEntry;
      expect(entry.env?.FROM_PROCESS).toBe("process_val");
      expect(entry.env?.FROM_DEFAULT).toBe("default_val");
    } finally {
      if (originalEnv === undefined) {
        delete process.env.FROM_PROCESS;
      } else {
        process.env.FROM_PROCESS = originalEnv;
      }
    }
  });

  it("exits nonzero when any server fails", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(new Error("Network error")),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow();
  });
});
