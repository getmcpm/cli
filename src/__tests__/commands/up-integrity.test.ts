/**
 * Tests for the H11 integrity drift pass in `mcpm up` (slice 1, WARN-only).
 *
 * Covers:
 * - integrity differs → ⚠ INTEGRITY DRIFT line output with identifier+npmVersion
 *   and the honest "registry's published record, not the code your agent runs" clause
 * - integrity equal → no drift output, install proceeds normally
 * - fresh undefined for N servers → exactly ONE offline batch line (not N)
 * - npm server with absent npmIntegrity baseline → exactly ONE absent-baseline line, no fetch
 * - fetchNpmIntegrity called N times via Promise.all (not serially)
 * - drift NEVER changes ServerResult or summary counts (WARN-only)
 * - output does NOT contain "serving different bytes" (honesty boundary)
 */

import { describe, it, expect, vi } from "vitest";
import { handleUp } from "../../commands/up.js";
import type { UpDeps } from "../../commands/up.js";
import type { ClientId } from "../../config/paths.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import type { NpmIntegritySnapshot } from "../../registry/npm-integrity.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SRI_OLD = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const SRI_NEW = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";

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
    promptEnvVar: vi.fn().mockResolvedValue("v"),
    output: vi.fn(),
    fetchNpmIntegrity: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Stack + lock file helpers
// ---------------------------------------------------------------------------

async function writeStackAndLock(stackYaml: string, lockYaml: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-integrity-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stackYaml, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lockYaml, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

/** Build a single-server stack+lock with an npmIntegrity snapshot. */
function makeStackAndLock(
  serverName: string,
  npmVersion: string,
  integrity: string | undefined
): { stack: string; lock: string } {
  const stack = `
version: "1"
servers:
  ${serverName}:
    version: "1.0.0"
`;
  const npmIntegrityBlock =
    integrity !== undefined
      ? `    npmIntegrity:\n      npmVersion: "${npmVersion}"\n      integrity: "${integrity}"\n`
      : "";

  const lock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  ${serverName}:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/${serverName.split("/").pop()}"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
${npmIntegrityBlock}`;

  return { stack, lock };
}

function collectOutput(deps: UpDeps): string {
  return (deps.output as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]).join("\n");
}

// ---------------------------------------------------------------------------
// Tests: integrity drift detection
// ---------------------------------------------------------------------------

describe("handleUp — H11 integrity drift pass (WARN-only)", () => {
  it("emits ⚠ INTEGRITY DRIFT when npm published record changed", async () => {
    const { stack, lock } = makeStackAndLock(
      "io.github.test/server-a",
      "1.0.0",
      SRI_OLD
    );
    const stackPath = await writeStackAndLock(stack, lock);

    const deps = makeDeps({
      // Fresh integrity differs from locked
      fetchNpmIntegrity: vi.fn().mockResolvedValue({
        npmVersion: "1.0.0",
        integrity: SRI_NEW,
      } as NpmIntegritySnapshot),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);
    expect(output).toContain("INTEGRITY DRIFT");
    expect(output).toContain("@test/server-a");
    expect(output).toContain("1.0.0");
  });

  it("drift output includes the honest 'registry's published record' clause", async () => {
    const { stack, lock } = makeStackAndLock(
      "io.github.test/server-a",
      "1.0.0",
      SRI_OLD
    );
    const stackPath = await writeStackAndLock(stack, lock);

    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({
        npmVersion: "1.0.0",
        integrity: SRI_NEW,
      } as NpmIntegritySnapshot),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);
    // Must include the honest qualification
    expect(output).toMatch(/registry'?s published record/i);
    expect(output).toMatch(/not the code your agent runs/i);
  });

  it("drift output does NOT contain 'serving different bytes' (forbidden copy)", async () => {
    const { stack, lock } = makeStackAndLock(
      "io.github.test/server-a",
      "1.0.0",
      SRI_OLD
    );
    const stackPath = await writeStackAndLock(stack, lock);

    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({
        npmVersion: "1.0.0",
        integrity: SRI_NEW,
      } as NpmIntegritySnapshot),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);
    expect(output).not.toMatch(/serving different bytes/i);
  });

  it("emits no drift output when integrity is equal", async () => {
    const { stack, lock } = makeStackAndLock(
      "io.github.test/server-a",
      "1.0.0",
      SRI_OLD
    );
    const stackPath = await writeStackAndLock(stack, lock);

    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({
        npmVersion: "1.0.0",
        integrity: SRI_OLD, // same as locked
      } as NpmIntegritySnapshot),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);
    expect(output).not.toContain("INTEGRITY DRIFT");
    // Install still proceeds
    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
  });

  it("integrity drift is WARN-only — install status and summary counts unchanged", async () => {
    const { stack, lock } = makeStackAndLock(
      "io.github.test/server-a",
      "1.0.0",
      SRI_OLD
    );
    const stackPath = await writeStackAndLock(stack, lock);

    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({
        npmVersion: "1.0.0",
        integrity: SRI_NEW,
      } as NpmIntegritySnapshot),
    });

    // Must NOT throw (no block)
    await expect(handleUp({ stackFile: stackPath }, deps)).resolves.toBeUndefined();

    const output = collectOutput(deps);
    // Summary: 1 installed, 0 blocked
    expect(output).toMatch(/1 installed/);
    expect(output).not.toMatch(/1 blocked/);
  });

  // ---------------------------------------------------------------------------
  // Offline batch: N servers offline → exactly ONE batch line, not N
  // ---------------------------------------------------------------------------

  it("emits exactly ONE offline batch line when N servers are unreachable", async () => {
    const stack = `
version: "1"
servers:
  io.github.test/server-a:
    version: "1.0.0"
  io.github.test/server-b:
    version: "1.0.0"
`;
    const lock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
    npmIntegrity:
      npmVersion: "1.0.0"
      integrity: "${SRI_OLD}"
  io.github.test/server-b:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/server-b"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
    npmIntegrity:
      npmVersion: "1.0.0"
      integrity: "${SRI_OLD}"
`;

    const stackPath = await writeStackAndLock(stack, lock);

    // Both fetches return undefined (could not verify — outage OR a 200 lacking
    // a comparable dist.integrity; the copy must NOT assert "unreachable").
    const deps = makeDeps({
      getServer: vi.fn().mockImplementation((name: string, version?: string) =>
        Promise.resolve(makeServerEntry(name, version ?? "1.0.0"))
      ),
      fetchNpmIntegrity: vi.fn().mockResolvedValue(undefined),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);

    // Exactly ONE batch "could not verify" line (not one per server).
    const offlineMatches = (output.match(/could not verify npm integrity/g) ?? []).length;
    expect(offlineMatches).toBe(1);
    // The batch line mentions 2 server(s)
    expect(output).toMatch(/2 server\(s\)/);
    // It must NOT assert a benign cause it cannot prove.
    expect(output).not.toMatch(/unreachable/i);
  });

  // ---------------------------------------------------------------------------
  // Absent baseline: N servers without npmIntegrity → exactly ONE batch line
  // ---------------------------------------------------------------------------

  it("emits exactly ONE absent-baseline line for N npm servers lacking npmIntegrity", async () => {
    const stack = `
version: "1"
servers:
  io.github.test/server-a:
    version: "1.0.0"
  io.github.test/server-b:
    version: "1.0.0"
`;
    // Lock entries have NO npmIntegrity
    const lock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
  io.github.test/server-b:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/server-b"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;

    const stackPath = await writeStackAndLock(stack, lock);

    const fetchNpmIntegrity = vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot);
    const deps = makeDeps({ fetchNpmIntegrity });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);

    // Exactly ONE absent-baseline line
    const absentMatches = (output.match(/integrity baseline missing/g) ?? []).length;
    expect(absentMatches).toBe(1);
    expect(output).toMatch(/2 npm server\(s\)/);

    // fetchNpmIntegrity must NOT have been called for absent-baseline servers
    expect(fetchNpmIntegrity).not.toHaveBeenCalled();
  });

  // ---------------------------------------------------------------------------
  // Promise.all: fetchNpmIntegrity called N times (not serially)
  // ---------------------------------------------------------------------------

  it("calls fetchNpmIntegrity N times (once per checkable server) in parallel", async () => {
    const stack = `
version: "1"
servers:
  io.github.test/server-a:
    version: "1.0.0"
  io.github.test/server-b:
    version: "1.0.0"
`;
    const lock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
    npmIntegrity:
      npmVersion: "1.0.0"
      integrity: "${SRI_OLD}"
  io.github.test/server-b:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/server-b"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
    npmIntegrity:
      npmVersion: "1.0.0"
      integrity: "${SRI_OLD}"
`;
    const stackPath = await writeStackAndLock(stack, lock);

    const fetchNpmIntegrity = vi.fn().mockResolvedValue({
      npmVersion: "1.0.0",
      integrity: SRI_OLD,
    } as NpmIntegritySnapshot);

    const deps = makeDeps({
      getServer: vi.fn().mockImplementation((name: string, version?: string) =>
        Promise.resolve(makeServerEntry(name, version ?? "1.0.0"))
      ),
      fetchNpmIntegrity,
    });

    await handleUp({ stackFile: stackPath }, deps);

    // Must be called exactly N=2 times (once per checkable server)
    expect(fetchNpmIntegrity).toHaveBeenCalledTimes(2);
    // Called with npmIntegrity.npmVersion (the npm coordinate), not locked.version
    expect(fetchNpmIntegrity).toHaveBeenCalledWith("@test/server-a", "1.0.0");
    expect(fetchNpmIntegrity).toHaveBeenCalledWith("@test/server-b", "1.0.0");
  });

  // ---------------------------------------------------------------------------
  // format-only advisory
  // ---------------------------------------------------------------------------

  it("emits a format-only advisory when algorithms don't overlap", async () => {
    // locked: sha1-only; fresh: sha512-only → "format-only"
    const SHA1_SRI = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const SHA512_SRI = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";

    const { stack, lock } = makeStackAndLock("io.github.test/server-a", "1.0.0", SHA1_SRI);
    const stackPath = await writeStackAndLock(stack, lock);

    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({
        npmVersion: "1.0.0",
        integrity: SHA512_SRI,
      } as NpmIntegritySnapshot),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const output = collectOutput(deps);
    expect(output).toMatch(/integrity format/i);
    expect(output).not.toContain("INTEGRITY DRIFT");
  });
});

// ---------------------------------------------------------------------------
// Schema back-compat: old lockfile without npmIntegrity still parses fine
// ---------------------------------------------------------------------------

describe("LockFileSchema — backward compatibility with old lockfiles (no npmIntegrity)", () => {
  it("old lockfile YAML without npmIntegrity parses successfully", async () => {
    const { LockFileSchema } = await import("../../stack/schema.js");
    const { parse: parseYaml } = await import("yaml");

    const oldLock = `
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

    const result = LockFileSchema.safeParse(parseYaml(oldLock));
    expect(result.success).toBe(true);
    if (result.success) {
      const server = result.data.servers["io.github.test/server-a"];
      if ("version" in server) {
        // npmIntegrity is absent (undefined) — backward compat
        expect((server as Record<string, unknown>).npmIntegrity).toBeUndefined();
        // lockfileVersion unchanged
        expect(result.data.lockfileVersion).toBe(1);
      }
    }
  });

  it("new lockfile with npmIntegrity also parses successfully", async () => {
    const { LockFileSchema } = await import("../../stack/schema.js");

    const newLock = {
      lockfileVersion: 1,
      lockedAt: "2026-04-05T10:00:00Z",
      servers: {
        "io.github.test/server-a": {
          version: "1.2.0",
          registryType: "npm",
          identifier: "@test/server-a",
          trust: {
            score: 75,
            maxPossible: 80,
            level: "safe",
            assessedAt: "2026-04-05T10:00:00Z",
          },
          npmIntegrity: {
            npmVersion: "1.0.0",
            integrity: SRI_OLD,
          },
        },
      },
    };

    const result = LockFileSchema.safeParse(newLock);
    expect(result.success).toBe(true);
  });
});
