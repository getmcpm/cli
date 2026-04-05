import { describe, it, expect, vi } from "vitest";
import { handleLock } from "../../commands/lock.js";
import type { LockDeps, LockOptions } from "../../commands/lock.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import { parse as parseYaml } from "yaml";
import { LockFileSchema } from "../../stack/schema.js";
import { writeFile, mkdir } from "fs/promises";
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
          identifier: `@test/${name}`,
          environmentVariables: [],
        },
      ],
    },
  };
}

const defaultTrustScore: TrustScore = {
  score: 75,
  maxPossible: 80,
  level: "safe",
  breakdown: {
    healthCheck: 15,
    staticScan: 40,
    externalScan: 0,
    registryMeta: 10,
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDeps(overrides: Partial<LockDeps> = {}): LockDeps {
  return {
    getServerVersions: vi.fn().mockResolvedValue([
      { version: "1.0.0" },
      { version: "1.1.0" },
      { version: "1.2.0" },
      { version: "2.0.0" },
    ]),
    getServer: vi.fn().mockImplementation((name: string, version?: string) =>
      Promise.resolve(makeServerEntry(name, version ?? "1.2.0"))
    ),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue(defaultTrustScore),
    writeLockFile: vi.fn().mockResolvedValue(undefined),
    output: vi.fn(),
    ...overrides,
  };
}

async function writeTempStackFile(
  content: string
): Promise<string> {
  const dir = await import("fs/promises").then((fs) =>
    fs.mkdtemp(path.join(os.tmpdir(), "mcpm-lock-test-"))
  );
  const filePath = path.join(dir, "mcpm.yaml");
  await writeFile(filePath, content, "utf-8");
  return filePath;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleLock", () => {
  it("resolves versions and writes a valid lock file", async () => {
    const stackPath = await writeTempStackFile(`
version: "1"
servers:
  io.github.test/my-server:
    version: "^1.0.0"
`);

    const deps = makeDeps();
    await handleLock({ stackFile: stackPath }, deps);

    expect(deps.writeLockFile).toHaveBeenCalledTimes(1);
    const [lockPath, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(lockPath).toContain("mcpm-lock.yaml");

    const parsed = parseYaml(content);
    const result = LockFileSchema.safeParse(parsed);
    expect(result.success).toBe(true);
    if (result.success) {
      const locked = result.data.servers["io.github.test/my-server"];
      expect("version" in locked).toBe(true);
      if ("version" in locked) {
        expect(locked.version).toBe("1.2.0"); // ^1.0.0 → highest 1.x
      }
    }
  });

  it("resolves semver ranges using getServerVersions", async () => {
    const stackPath = await writeTempStackFile(`
version: "1"
servers:
  io.github.test/server-a:
    version: "~1.0.0"
`);

    const deps = makeDeps({
      getServerVersions: vi.fn().mockResolvedValue([
        { version: "1.0.0" },
        { version: "1.0.5" },
        { version: "1.1.0" },
      ]),
    });

    await handleLock({ stackFile: stackPath }, deps);

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    const locked = parsed.servers["io.github.test/server-a"];
    expect(locked.version).toBe("1.0.5"); // ~1.0.0 → highest 1.0.x
  });

  it("pins URL entries directly without version resolution", async () => {
    const stackPath = await writeTempStackFile(`
version: "1"
servers:
  my-internal:
    url: "https://internal.company.com/mcp"
`);

    const deps = makeDeps();
    await handleLock({ stackFile: stackPath }, deps);

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    const locked = parsed.servers["my-internal"];
    expect(locked.url).toBe("https://internal.company.com/mcp");
    expect(locked.version).toBeUndefined();
    // No registry calls for URL entries
    expect(deps.getServerVersions).not.toHaveBeenCalled();
  });

  it("includes trust score snapshot in lock file", async () => {
    const stackPath = await writeTempStackFile(`
version: "1"
servers:
  io.github.test/scored:
    version: "1.0.0"
`);

    const deps = makeDeps();
    await handleLock({ stackFile: stackPath }, deps);

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    const locked = parsed.servers["io.github.test/scored"];
    expect(locked.trust).toBeDefined();
    expect(locked.trust.score).toBe(75);
    expect(locked.trust.maxPossible).toBe(80);
    expect(locked.trust.level).toBe("safe");
  });

  it("throws when mcpm.yaml does not exist", async () => {
    const deps = makeDeps();
    await expect(
      handleLock({ stackFile: "/nonexistent/mcpm.yaml" }, deps)
    ).rejects.toThrow("Stack file not found");
  });

  it("continues resolving other servers when one fails", async () => {
    const stackPath = await writeTempStackFile(`
version: "1"
servers:
  io.github.test/good-server:
    version: "^1.0.0"
  io.github.test/bad-server:
    version: "^1.0.0"
`);

    let callCount = 0;
    const deps = makeDeps({
      getServerVersions: vi.fn().mockImplementation((name: string) => {
        callCount++;
        if (name === "io.github.test/bad-server") {
          return Promise.reject(new Error("Network timeout"));
        }
        return Promise.resolve([
          { version: "1.0.0" },
          { version: "1.2.0" },
        ]);
      }),
      getServer: vi.fn().mockImplementation((name: string) => {
        if (name === "io.github.test/bad-server") {
          return Promise.reject(new Error("Network timeout"));
        }
        return Promise.resolve(makeServerEntry(name, "1.2.0"));
      }),
    });

    await handleLock({ stackFile: stackPath }, deps);

    // Lock file should contain the good server
    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    expect(parsed.servers["io.github.test/good-server"]).toBeDefined();
    expect(parsed.servers["io.github.test/bad-server"]).toBeUndefined();

    // Error reported in output
    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("bad-server");
    expect(outputCalls).toContain("failed");
  });
});
