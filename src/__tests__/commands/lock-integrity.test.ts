/**
 * Tests for npm integrity snapshot capture in `mcpm lock` (H11 slice 1).
 *
 * Covers:
 * - npm pkg with concrete pkg.version → snapshot attached
 * - pkg.version absent / "latest" / dist-tag / range → fetch NOT called, snapshot omitted
 * - Regression C1: server.version !== pkg.version → fetch uses pkg.version
 * - fetch returns undefined → snapshot omitted, lock still succeeds
 * - non-npm registryType → fetchNpmIntegrity not called
 */

import { describe, it, expect, vi } from "vitest";
import { handleLock } from "../../commands/lock.js";
import type { LockDeps } from "../../commands/lock.js";
import type { ServerEntry } from "../../registry/types.js";
import type { NpmIntegritySnapshot } from "../../registry/npm-integrity.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import { parse as parseYaml } from "yaml";
import { LockFileSchema } from "../../stack/schema.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const TEST_SRI = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

function makeServerEntryWithPkg(
  name: string,
  serverVersion: string,
  pkgVersion: string,
  registryType = "npm"
): ServerEntry {
  return {
    server: {
      name,
      version: serverVersion,
      packages: [
        {
          registryType,
          identifier: `@test/${name.split("/").pop()}`,
          version: pkgVersion,
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
  breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function writeTempStack(content: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-lock-integrity-test-"));
  const filePath = path.join(dir, "mcpm.yaml");
  await writeFile(filePath, content, "utf-8");
  return filePath;
}

function makeDeps(
  serverEntry: ServerEntry,
  overrides: Partial<LockDeps> = {}
): LockDeps {
  return {
    getServerVersions: vi.fn().mockResolvedValue([{ version: "1.0.0" }]),
    getServer: vi.fn().mockResolvedValue(serverEntry),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue(defaultTrustScore),
    writeLockFile: vi.fn().mockResolvedValue(undefined),
    output: vi.fn(),
    fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: TEST_SRI } as NpmIntegritySnapshot),
    ...overrides,
  };
}

const basicStack = `
version: "1"
servers:
  io.github.test/my-server:
    version: "1.0.0"
`;

// ---------------------------------------------------------------------------
// Tests: snapshot captured for concrete npm pkg.version
// ---------------------------------------------------------------------------

describe("handleLock — npm integrity snapshot capture", () => {
  it("attaches npmIntegrity snapshot when pkg.version is a concrete semver", async () => {
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "1.0.0");
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    // fetchNpmIntegrity must have been called with the npm coordinate
    expect(deps.fetchNpmIntegrity).toHaveBeenCalledWith(
      "@test/my-server",
      "1.0.0"
    );

    // Lock file must contain npmIntegrity
    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    const locked = parsed.servers["io.github.test/my-server"];
    expect(locked.npmIntegrity).toBeDefined();
    expect(locked.npmIntegrity.npmVersion).toBe("1.0.0");
    expect(locked.npmIntegrity.integrity).toBe(TEST_SRI);
  });

  // Regression C1: server.version is the MCP server version; pkg.version is the npm coordinate.
  // If pkg.version is "latest" but server.version is "1.0.0", we must NOT feed
  // server.version to fetchNpmIntegrity — that would 404 under the npm per-version endpoint.
  it("C1 regression: uses pkg.version (not server.version) for fetch when they differ", async () => {
    // Real-world fixture: server.version = "1.0.0" (the MCP release version),
    // but pkg.version = "latest" (the npm dist-tag). The snapshot must be omitted
    // (not fetched with the server version "1.0.0").
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "latest");
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    // fetchNpmIntegrity must NOT be called with "1.0.0" (the server version)
    // because pkg.version is "latest" (not a concrete semver)
    expect(deps.fetchNpmIntegrity).not.toHaveBeenCalled();

    // No npmIntegrity in lock
    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    expect(parsed.servers["io.github.test/my-server"].npmIntegrity).toBeUndefined();
  });

  it("omits npmIntegrity when pkg.version is absent", async () => {
    const entry: ServerEntry = {
      server: {
        name: "io.github.test/my-server",
        version: "1.0.0",
        packages: [
          {
            registryType: "npm",
            identifier: "@test/my-server",
            // no version field
            environmentVariables: [],
          },
        ],
      },
    };
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    expect(deps.fetchNpmIntegrity).not.toHaveBeenCalled();

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    expect(parsed.servers["io.github.test/my-server"].npmIntegrity).toBeUndefined();
  });

  it("omits npmIntegrity when pkg.version is a range (^1.0.0)", async () => {
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "^1.0.0");
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    expect(deps.fetchNpmIntegrity).not.toHaveBeenCalled();

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    expect(parsed.servers["io.github.test/my-server"].npmIntegrity).toBeUndefined();
  });

  it("omits npmIntegrity when pkg.version is a tilde range (~1.0.0)", async () => {
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "~1.0.0");
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    expect(deps.fetchNpmIntegrity).not.toHaveBeenCalled();
  });

  it("omits npmIntegrity when fetchNpmIntegrity returns undefined — lock still succeeds", async () => {
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "1.0.0");
    const deps = makeDeps(entry, {
      fetchNpmIntegrity: vi.fn().mockResolvedValue(undefined),
    });
    const stackPath = await writeTempStack(basicStack);

    // Must NOT throw
    await expect(handleLock({ stackFile: stackPath }, deps)).resolves.toBeUndefined();

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const parsed = parseYaml(content);
    // snapshot omitted, but lock was still written
    expect(parsed.servers["io.github.test/my-server"]).toBeDefined();
    expect(parsed.servers["io.github.test/my-server"].npmIntegrity).toBeUndefined();
  });

  it("does NOT call fetchNpmIntegrity for non-npm registryType", async () => {
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "1.0.0", "pypi");
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    expect(deps.fetchNpmIntegrity).not.toHaveBeenCalled();
  });

  it("produces a lockfile that still satisfies LockFileSchema when npmIntegrity is present", async () => {
    const entry = makeServerEntryWithPkg("io.github.test/my-server", "1.0.0", "1.0.0");
    const deps = makeDeps(entry);
    const stackPath = await writeTempStack(basicStack);

    await handleLock({ stackFile: stackPath }, deps);

    const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
    const result = LockFileSchema.safeParse(parseYaml(content));
    expect(result.success).toBe(true);
    // Ensure lockfileVersion is still 1
    if (result.success) {
      expect(result.data.lockfileVersion).toBe(1);
    }
  });
});
