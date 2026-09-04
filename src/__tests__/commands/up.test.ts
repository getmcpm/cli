import { describe, it, expect, vi, beforeEach } from "vitest";
import { handleUp } from "../../commands/up.js";
import type { UpDeps, UpOptions } from "../../commands/up.js";
import type { ClientId } from "../../config/paths.js";
import type { ServerEntry } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
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

  // M2: the MCP surface passes a hard trust floor; a low-trust server must be
  // blocked even when the stack file declares no policy (the caller controls the
  // stack, so a missing/zero policy must not bypass the floor).
  it("blocks a server below minTrustFloor even with no stack policy (M2)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({ computeTrustScore: vi.fn().mockReturnValue(lowTrust) });

    await expect(
      handleUp({ stackFile: stackPath, minTrustFloor: 50 }, deps)
    ).rejects.toThrow(/could not be installed/);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).not.toHaveBeenCalled();
  });

  // TODOS #33: the floor is documented as immune to caller-supplied values.
  // `MCPM_EXTERNAL_SCANNER` names an arbitrary executable, so its 20 points ARE
  // caller-supplied — a two-line script printing `{"findings":[]}` used to lift a
  // blocked server over the floor. This trust score is the reproduction: two
  // critical tier-1 findings zero the static bucket, the fake scanner banks the
  // full external bucket, and the RAW total clears a floor of 25.
  it("blocks on mcpm-native evidence, ignoring an unverifiable scanner's credit (#33)", async () => {
    const gamedTrust: TrustScore = {
      score: 35,
      maxPossible: 100,
      level: "risky",
      breakdown: { healthCheck: 15, staticScan: 0, externalScan: 20, registryMeta: 0 },
    };
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({ computeTrustScore: vi.fn().mockReturnValue(gamedTrust) });

    // Guard the premise: without the fix this score passes the gate outright.
    expect(gamedTrust.score).toBeGreaterThanOrEqual(25);

    await expect(
      handleUp({ stackFile: stackPath, minTrustFloor: 25 }, deps)
    ).rejects.toThrow(/could not be installed/);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).not.toHaveBeenCalled();

    // The message must report the figure actually compared, and say why it
    // differs from the score shown everywhere else — otherwise "35/100 is below
    // 25" reads as a bug to whoever hits it.
    const out = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(out).toContain("15/80");
    expect(out).toContain("do not count toward the floor");
    expect(out).not.toContain("35/100");
  });

  // The floor still passes a server whose OWN evidence clears it, and says
  // nothing about scanners when none was credited.
  it("admits a server that clears the floor without any external credit (#33)", async () => {
    const honestTrust: TrustScore = {
      score: 55,
      maxPossible: 80,
      level: "caution",
      breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 0 },
    };
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({ computeTrustScore: vi.fn().mockReturnValue(honestTrust) });

    await handleUp({ stackFile: stackPath, minTrustFloor: 25 }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
  });

  // E9a: the registry itself pulled this listing → fail closed, install nothing.
  it("blocks a server the registry marks DELETED (E9a)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deleted = {
      ...makeServerEntry("io.github.test/server-a", "1.2.0"),
      _meta: { "io.modelcontextprotocol.registry/official": { status: "deleted" } },
    } as ServerEntry;
    const deps = makeDeps({ getServer: vi.fn().mockResolvedValue(deleted) });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(/could not be installed/);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).not.toHaveBeenCalled();
  });

  it("does NOT block a DEPRECATED server (advisory only — installs) (E9a)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deprecated = {
      ...makeServerEntry("io.github.test/server-a", "1.2.0"),
      _meta: { "io.modelcontextprotocol.registry/official": { status: "deprecated" } },
    } as ServerEntry;
    const deps = makeDeps({ getServer: vi.fn().mockResolvedValue(deprecated) });

    await handleUp({ stackFile: stackPath }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalled();
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

  // TODOS #41: the drop check must compare dropCheckNativeScore, not
  // nativeTrustScore — the latter would falsely read this as a drop.
  it("does not false-positive a drop from an incidental external-only registryMeta collateral (#41)", async () => {
    const stackWithDrop = `
version: "1"
policy:
  blockOnScoreDrop: true
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    // Locked baseline: no scanner, native evidence 15 + 40 + 10 = 65/80 = 81%.
    const lockWithBaseline = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.2.0"
    registryType: npm
    identifier: "@test/server-a"
    trust:
      score: 65
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(stackWithDrop, lockWithBaseline);

    // Current: mcpm's own evidence is UNCHANGED (health 15 + static 40 = 55),
    // but an external-only critical incidentally fired THIS run, collaterally
    // zeroing the displayed registryMeta bucket. nativeRegistryMeta stays 10 —
    // nothing NATIVE caused the cap.
    const currentWithIncidentalExternalCollateral: TrustScore = {
      score: 55, // 15 + 40 + 0 (externalScan, critical) + 0 (registryMeta, collateral)
      maxPossible: 100,
      level: "caution",
      breakdown: {
        healthCheck: 15,
        staticScan: 40,
        externalScan: 0,
        registryMeta: 0,
        nativeRegistryMeta: 10,
      },
    };
    const deps = makeDeps({
      computeTrustScore: vi.fn().mockReturnValue(currentWithIncidentalExternalCollateral),
    });

    // nativeTrustScore(current) = 55/80 = 69% < locked 81% would falsely block.
    // dropCheckNativeScore(current) = 65/80 = 81% == locked 81%, so it proceeds.
    await handleUp({ stackFile: stackPath }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
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

  // Issue #22: the MCP mcpm_up surface wires `confirm: async () => false` so it
  // never auto-confirms destructive actions on the no-human-in-loop path. This
  // proves that a refusing confirm callback declines strict-mode removals.
  it("does NOT remove extra servers when confirm refuses (non-CI strict)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter({ "extra-server": { command: "npx", args: ["-y", "extra"] } });
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      confirm: vi.fn().mockResolvedValue(false),
    });

    await handleUp({ stackFile: stackPath, strict: true }, deps);
    expect(adapter.removeServer).not.toHaveBeenCalled();
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

  // Fix #1: when every client write fails (e.g. all configs read-only), the
  // server must be reported as failed — not silently "installed".
  it("reports failure (not installed) when all client writes throw", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter();
    adapter.addServer = vi.fn().mockRejectedValue(new Error("EACCES: read-only config"));
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      "could not be installed"
    );

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("could not write to any client");
    expect(outputCalls).toContain("EACCES");
    // Summary must not claim an install happened.
    expect(outputCalls).toMatch(/0 installed/);
  });

  // Fix #1: partial failure (one of two clients fails) still installs but
  // surfaces a warning rather than swallowing the error.
  it("installs with a warning when some clients fail", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const okAdapter = makeAdapter();
    const badAdapter = makeAdapter();
    badAdapter.addServer = vi.fn().mockRejectedValue(new Error("EROFS"));
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue([
        "claude-desktop",
        "cursor",
      ]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) =>
        id === "cursor" ? badAdapter : okAdapter
      ),
    });

    await handleUp({ stackFile: stackPath }, deps);

    expect(okAdapter.addServer).toHaveBeenCalledTimes(1);
    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("warning: failed on");
    expect(outputCalls).toContain("cursor");
    expect(outputCalls).toMatch(/1 installed/);
  });

  // Fix #2: removed servers must be counted as "removed", not inflate the
  // "N installed" summary.
  it("counts strict-removed servers as removed, not installed", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter({
      "io.github.test/server-a": { command: "npx", args: ["-y", "server-a"] },
      "extra-server": { command: "npx", args: ["-y", "extra"] },
    });
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);

    expect(adapter.removeServer).toHaveBeenCalledWith("/mock/config.json", "extra-server");
    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    // server-a installs (1), extra-server is removed (1) — not 2 installed.
    expect(outputCalls).toMatch(/1 installed/);
    expect(outputCalls).toContain("1 removed");
  });

  // Fix #3: --strict --yes in interactive (non-CI) mode must honor --yes and
  // NOT prompt via confirm.
  it("does not prompt for strict removal when --yes is passed (non-CI)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter({ "extra-server": { command: "npx", args: ["-y", "extra"] } });
    const confirm = vi.fn().mockResolvedValue(true);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      confirm,
    });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);

    expect(confirm).not.toHaveBeenCalled();
    expect(adapter.removeServer).toHaveBeenCalledWith("/mock/config.json", "extra-server");
  });

  // M4a (PR #66): the up path now validates stack-file `url:` servers before writing.
  // These exercise processUrlServer end-to-end (previously untested at this level).
  const urlStack = (url: string) => `
version: "1"
servers:
  io.github.test/remote:
    url: "${url}"
`;

  it("installs a valid https url: server to Cursor (with H9 consent)", async () => {
    const stackPath = await writeStackAndLock(urlStack("https://api.example.com/mcp"), basicLock);
    const adapter = makeAdapter();
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["cursor"]),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    // H9: url servers run UNGUARDED and are now deny-by-default; opt in to
    // reach the install path this test exercises.
    await handleUp({ stackFile: stackPath, allowUnguarded: true }, deps);

    expect(adapter.addServer).toHaveBeenCalledWith(
      "/mock/config.json",
      "io.github.test/remote",
      { url: "https://api.example.com/mcp" },
      { force: true }
    );
  });

  it("blocks a url: server with a non-loopback plaintext-http URL (M4a)", async () => {
    const stackPath = await writeStackAndLock(urlStack("http://10.0.0.5/mcp"), basicLock);
    const adapter = makeAdapter();
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["cursor"]),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(/could not be installed/);
    expect(adapter.addServer).not.toHaveBeenCalled();
  });

  it("blocks a url: server with a non-http(s) scheme", async () => {
    const stackPath = await writeStackAndLock(urlStack("file:///etc/passwd"), basicLock);
    const adapter = makeAdapter();
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["cursor"]),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(/could not be installed/);
    expect(adapter.addServer).not.toHaveBeenCalled();
  });

  // Regression: --dry-run is read-only — an invalid URL must NOT throw or exit
  // non-zero; it is previewed as "would reject".
  it("dry-run does not fail on an invalid url: server (regression)", async () => {
    const stackPath = await writeStackAndLock(urlStack("http://10.0.0.5/mcp"), basicLock);
    const adapter = makeAdapter();
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["cursor"]),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    // H9: opt in so the dry-run reaches URL validation (the behavior under
    // test) rather than the unguarded deny-gate.
    await expect(
      handleUp({ stackFile: stackPath, dryRun: true, allowUnguarded: true }, deps)
    ).resolves.toBeUndefined();
    expect(adapter.addServer).not.toHaveBeenCalled();

    const out = (deps.output as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]).join("\n");
    expect(out).toMatch(/would reject URL/);
  });
});

// ---------------------------------------------------------------------------
// F4 — release-age + install-script policy gates
// ---------------------------------------------------------------------------

describe("handleUp — release-age and install-script policy gates (F4)", () => {
  // Fixed clock — these tests never read the wall clock.
  const NOW = new Date("2026-06-10T00:00:00Z").getTime();
  const HOUR_MS = 60 * 60 * 1000;

  /** Entry whose official meta carries the given publishedAt; undefined drops _meta entirely. */
  function entryPublishedAt(
    name: string,
    version: string,
    publishedAt: string | undefined
  ): ServerEntry {
    const base = makeServerEntry(name, version);
    if (publishedAt === undefined) return base;
    return {
      ...base,
      _meta: {
        "io.modelcontextprotocol.registry/official": {
          status: "active",
          publishedAt,
          isLatest: true,
        },
      },
    };
  }

  function makeAgeDeps(
    publishedAt: string | undefined,
    overrides: Partial<UpDeps> = {}
  ): UpDeps {
    return makeDeps({
      getServer: vi.fn().mockImplementation((name: string, version?: string) =>
        Promise.resolve(entryPublishedAt(name, version ?? "1.0.0", publishedAt))
      ),
      now: () => NOW,
      ...overrides,
    });
  }

  function joinedOutput(deps: UpDeps): string {
    return (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
  }

  function findingsPassedToScore(deps: UpDeps): Finding[] {
    const spy = deps.computeTrustScore as ReturnType<typeof vi.fn>;
    return spy.mock.calls[0][0].findings;
  }

  const agePolicyStack = (hours: number) => `
version: "1"
policy:
  minReleaseAgeHours: ${hours}
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;

  // TODOS #33 follow-on. The release-age finding is `medium` with no `source`, so
  // it deducts from staticScan -- a bucket the hard floor counts. On the MCP
  // surface the caller supplies the stack file, `minReleaseAgeHours: 0` is
  // schema-valid, and suppressing that finding RAISES the score the floor
  // compares. Reproduced before the fix: native 20 -> 25 against a floor of 25,
  // i.e. the F4 poisoned-republish penalty disarmed by the party it catches.
  it("ignores policy.minReleaseAgeHours whenever a hard trust floor is in effect", async () => {
    const fresh = new Date(NOW - 2 * HOUR_MS).toISOString();
    const withFloor = makeAgeDeps(fresh);
    await expect(
      handleUp(
        { stackFile: await writeStackAndLock(agePolicyStack(0), basicLock), minTrustFloor: 25 },
        withFloor,
      )
    ).rejects.toThrow(/could not be installed/);

    // The finding the attacker's policy tried to suppress is present anyway.
    expect(findingsPassedToScore(withFloor).some((f) => f.type === "release-cooldown")).toBe(true);

    // And the CLI (no floor) still honours the knob -- this is an
    // untrusted-surface lockdown, not a removal of the feature.
    const noFloor = makeAgeDeps(fresh);
    await handleUp(
      { stackFile: await writeStackAndLock(agePolicyStack(0), basicLock) },
      noFloor,
    );
    expect(findingsPassedToScore(noFloor).some((f) => f.type === "release-cooldown")).toBe(false);
  });

  // TODOS #33 follow-on: an admitted server must not advertise a figure that did
  // not clear the floor. Before this, a floor of 25 admitted on 25/80 while the
  // line read `trust: 45/100`.
  it("reports the native figure on admission when a floor excluded scanner credit", async () => {
    const withCredit: TrustScore = {
      score: 45,
      maxPossible: 100,
      level: "caution",
      breakdown: { healthCheck: 15, staticScan: 10, externalScan: 20, registryMeta: 0 },
    };
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({ computeTrustScore: vi.fn().mockReturnValue(withCredit) });

    await handleUp({ stackFile: stackPath, minTrustFloor: 25 }, deps);

    const out = joinedOutput(deps);
    expect(out).toContain("25/80 against the floor");
    expect(out).toContain("45/100 with the external scanner");
  });

  it("blocks a fresh release when policy.minReleaseAgeHours is set", async () => {
    const stackPath = await writeStackAndLock(agePolicyStack(24), basicLock);
    const adapter = makeAdapter();
    const deps = makeAgeDeps(new Date(NOW - 2 * HOUR_MS).toISOString(), {
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      /could not be installed/
    );
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(joinedOutput(deps)).toContain("minimum release age");
  });

  it("blocks an ABSENT publish timestamp when the policy is armed (fail-closed)", async () => {
    const stackPath = await writeStackAndLock(agePolicyStack(24), basicLock);
    const adapter = makeAdapter();
    const deps = makeAgeDeps(undefined, {
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      /could not be installed/
    );
    expect(adapter.addServer).not.toHaveBeenCalled();
    const out = joinedOutput(deps);
    expect(out).toContain("unverifiable age");
    expect(out).toContain("missing from registry metadata");
  });

  it("blocks a future publish timestamp with the dedicated reason variant", async () => {
    const stackPath = await writeStackAndLock(agePolicyStack(24), basicLock);
    const deps = makeAgeDeps(new Date(NOW + 1 * HOUR_MS).toISOString());

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      /could not be installed/
    );
    expect(joinedOutput(deps)).toContain("in the future");
  });

  it("applies the soft cooldown penalty without a policy, and absent stays clean", async () => {
    // Fresh release, NO policy → installs, but the medium release-cooldown
    // finding lands in the score input (the unconditional soft penalty).
    const freshPath = await writeStackAndLock(basicStack, basicLock);
    const freshDeps = makeAgeDeps(new Date(NOW - 2 * HOUR_MS).toISOString());
    await handleUp({ stackFile: freshPath }, freshDeps);
    const freshFindings = findingsPassedToScore(freshDeps);
    expect(
      freshFindings.some(
        (f) => f.type === "release-cooldown" && f.severity === "medium"
      )
    ).toBe(true);

    // Absent timestamp, NO policy → neither finding nor block (score fail-open).
    const absentPath = await writeStackAndLock(basicStack, basicLock);
    const absentDeps = makeAgeDeps(undefined);
    await handleUp({ stackFile: absentPath }, absentDeps);
    const absentFindings = findingsPassedToScore(absentDeps);
    expect(absentFindings.some((f) => f.type === "release-cooldown")).toBe(false);
  });

  it("threads policy.minReleaseAgeHours as the assessment threshold", async () => {
    // 48h-old release: aged under the 24h default, fresh under a 72h policy.
    const stackPath = await writeStackAndLock(agePolicyStack(72), basicLock);
    const deps = makeAgeDeps(new Date(NOW - 48 * HOUR_MS).toISOString());

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      /could not be installed/
    );
    expect(joinedOutput(deps)).toContain("minimum release age");
  });

  it("blocks launchers with install-script findings when blockInstallScripts is set", async () => {
    const scriptPolicyStack = `
version: "1"
policy:
  blockInstallScripts: true
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    const installScriptFinding = {
      severity: "low" as const,
      type: "install-script" as const,
      message:
        'This launcher runs install scripts: "@test/server-a" is launched via "npx -y", which executes npm lifecycle scripts on first run',
      location: "package: @test/server-a",
    };

    const blockedPath = await writeStackAndLock(scriptPolicyStack, basicLock);
    const blockedDeps = makeAgeDeps(undefined, {
      scanTier1: vi.fn().mockReturnValue([installScriptFinding]),
    });
    await expect(handleUp({ stackFile: blockedPath }, blockedDeps)).rejects.toThrow(
      /could not be installed/
    );
    expect(joinedOutput(blockedDeps)).toContain(
      "resolves to a launcher that runs install scripts"
    );

    // Without the policy flag the same finding does not block.
    const openPath = await writeStackAndLock(basicStack, basicLock);
    const openDeps = makeAgeDeps(undefined, {
      scanTier1: vi.fn().mockReturnValue([installScriptFinding]),
    });
    await handleUp({ stackFile: openPath }, openDeps);
    expect(joinedOutput(openDeps)).toMatch(/1 installed/);
  });

  it("does not block under blockInstallScripts when the scan finds no install-script launcher", async () => {
    // Pins that hasInstallScriptFindings reflects the actual scan results —
    // a hardcoded `true` would block every server in a script-blocking stack.
    const scriptPolicyStack = `
version: "1"
policy:
  blockInstallScripts: true
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    const stackPath = await writeStackAndLock(scriptPolicyStack, basicLock);
    const adapter = makeAdapter();
    const deps = makeAgeDeps(undefined, {
      getAdapter: vi.fn().mockReturnValue(adapter),
      scanTier1: vi.fn().mockReturnValue([]),
    });

    await handleUp({ stackFile: stackPath }, deps);
    expect(adapter.addServer).toHaveBeenCalled();
    expect(joinedOutput(deps)).toMatch(/1 installed/);
  });

  // UPGRADE TRANSITION (deliberate, documented): pre-F4 lockfile snapshots lack
  // the new install-script deduction, so blockOnScoreDrop fires after upgrading
  // until `mcpm lock` is re-run — the reason must carry the remediation hint.
  it("blocks with the re-lock remediation hint when a pre-F4 snapshot drops", async () => {
    const dropStack = `
version: "1"
policy:
  blockOnScoreDrop: true
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    // Locked pre-F4 at 75/80 (94%); re-score with the -2 launcher deduction → 73/80 (91%).
    const stackPath = await writeStackAndLock(dropStack, basicLock);
    const deps = makeAgeDeps(undefined, {
      scanTier1: vi.fn().mockReturnValue([
        {
          severity: "low",
          type: "install-script",
          message:
            'This launcher runs install scripts: "@test/server-a" is launched via "npx -y", which executes npm lifecycle scripts on first run',
          location: "package: @test/server-a",
        },
      ]),
      computeTrustScore: vi.fn().mockReturnValue({
        ...goodTrust,
        score: 73,
      }),
    });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(
      /could not be installed/
    );
    const out = joinedOutput(deps);
    expect(out).toContain("dropped");
    expect(out).toContain("re-run");
    expect(out).toContain("mcpm lock");
  });

  it("still blocks in --dry-run when the armed policy fails (exit-1 preview)", async () => {
    const stackPath = await writeStackAndLock(agePolicyStack(24), basicLock);
    const adapter = makeAdapter();
    const deps = makeAgeDeps(new Date(NOW - 2 * HOUR_MS).toISOString(), {
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await expect(
      handleUp({ stackFile: stackPath, dryRun: true }, deps)
    ).rejects.toThrow(/could not be installed/);
    expect(adapter.addServer).not.toHaveBeenCalled();
  });

  it("evaluates minTrustFloor before the release-age policy gate (ordering regression)", async () => {
    const stackPath = await writeStackAndLock(agePolicyStack(24), basicLock);
    const deps = makeAgeDeps(new Date(NOW - 2 * HOUR_MS).toISOString(), {
      computeTrustScore: vi.fn().mockReturnValue(lowTrust),
    });

    await expect(
      handleUp({ stackFile: stackPath, minTrustFloor: 50 }, deps)
    ).rejects.toThrow(/could not be installed/);
    const out = joinedOutput(deps);
    expect(out).toContain("below the required floor");
    expect(out).not.toContain("minimum release age");
  });

  it("falls back to Date.now when deps.now is omitted (old release, no crash)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({
      getServer: vi.fn().mockImplementation((name: string, version?: string) =>
        Promise.resolve(
          entryPublishedAt(name, version ?? "1.0.0", "2025-01-15T00:00:00Z")
        )
      ),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    expect(findingsPassedToScore(deps).some((f) => f.type === "release-cooldown")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// #59 (was #23's deferred sub-gap): --strict must not silently leave a
// malformed, undeclared entry behind while reporting a clean reconciliation.
// The fail-safe direction is kept — it is NOT deleted — but it is reported.
// ---------------------------------------------------------------------------

describe("handleUp --strict — malformed undeclared entry", () => {
  it("reports it instead of silently leaving it, and does NOT delete it", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter();
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      async (_p: string, onSkip?: (n: string) => void) => {
        onSkip?.("broken-extra");
        return {};
      }
    );
    const lines: string[] = [];
    const recorded: Array<{ name: string; status: string }> = [];
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
      recordResult: (r: { name: string; status: string }) => recorded.push(r),
    });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);

    // Fail-safe: never delete an entry mcpm could not read.
    expect(adapter.removeServer).not.toHaveBeenCalledWith("/mock/config.json", "broken-extra");
    // But say so — silence was the bug, not the refusal to delete.
    expect(lines.join("\n")).toContain("broken-extra");
    expect(lines.join("\n")).toMatch(/does not match the expected shape/);
    // And say so on the MACHINE-READABLE channel too: `recordResult` is the
    // mcpm_up MCP surface's only signal — that surface has no stderr an agent
    // can see, which is the whole reason v0.34.0 added `skipped` fields.
    expect(recorded).toContainEqual({ name: "broken-extra", status: "skipped" });
  });

  it("sanitizes a config-supplied name before it reaches the terminal", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter();
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      async (_p: string, onSkip?: (n: string) => void) => {
        onSkip?.("ev\u001b]0;PWNED\u0007il");
        return {};
      }
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);

    expect(lines.join("\n")).toContain("PWNED");
    expect(lines.join("\n")).not.toContain("\u001b");
  });

  it("says nothing about a DECLARED server whose entry is malformed", async () => {
    // --strict only reconciles servers absent from mcpm.yaml. Reporting a
    // declared one as "not in mcpm.yaml" would be a false statement.
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter();
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      async (_p: string, onSkip?: (n: string) => void) => {
        onSkip?.("io.github.test/server-a"); // the DECLARED name
        return {};
      }
    );
    const lines: string[] = [];
    const recorded: Array<{ name: string; status: string }> = [];
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
      recordResult: (r: { name: string; status: string }) => recorded.push(r),
    });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);

    expect(lines.join("\n")).not.toMatch(/not in mcpm\.yaml.*does not match the expected shape/);
    expect(recorded).not.toContainEqual({
      name: "io.github.test/server-a",
      status: "skipped",
    });
  });

  it("still removes a well-formed undeclared entry (negative control)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const adapter = makeAdapter({ "extra-server": { command: "npx", args: ["-y", "extra"] } });
    const deps = makeDeps({ getAdapter: vi.fn().mockReturnValue(adapter) });

    await handleUp({ stackFile: stackPath, strict: true, yes: true }, deps);

    expect(adapter.removeServer).toHaveBeenCalledWith("/mock/config.json", "extra-server");
  });
});
