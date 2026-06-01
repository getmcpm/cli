/**
 * Phase 2 tests: `--secrets keychain` placeholder writes for install + up,
 * and the deriveKeychainId helper. Verifies the security invariant that, in
 * keychain mode, no plaintext secret is written into a client config.
 */

import { describe, it, expect, vi } from "vitest";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";
import { handleInstall, type InstallDeps } from "../../commands/install.js";
import { handleUp, type UpDeps } from "../../commands/up.js";
import { deriveKeychainId } from "../../store/keychain.js";
import type { ClientId } from "../../config/paths.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";

// ---------------------------------------------------------------------------
// deriveKeychainId
// ---------------------------------------------------------------------------

describe("deriveKeychainId", () => {
  it("replaces '/' and unsafe chars so registry ids become valid keychain ids", () => {
    expect(deriveKeychainId("io.github.owner/repo-mcp")).toBe("io.github.owner_repo-mcp");
  });

  it("preserves already-safe chars and is deterministic", () => {
    expect(deriveKeychainId("a.b_c-d")).toBe("a.b_c-d");
    expect(deriveKeychainId("x/y")).toBe(deriveKeychainId("x/y"));
  });

  it("never produces a '/', so placeholder round-trips correctly", () => {
    expect(deriveKeychainId("io.github.owner/repo")).not.toContain("/");
  });
});

// ---------------------------------------------------------------------------
// install --secrets keychain
// ---------------------------------------------------------------------------

function installServerEntry(): ServerEntry {
  return {
    server: {
      name: "io.github.test/my-server",
      version: "1.0.0",
      description: "test",
      packages: [
        {
          registryType: "npm",
          identifier: "@test/my-server",
          environmentVariables: [
            { name: "API_KEY", isSecret: true },
            { name: "REGION", isSecret: false },
          ],
          runtimeArguments: [],
        },
      ],
      remotes: [],
    },
    _meta: {
      "io.modelcontextprotocol.registry/official": {
        status: "active",
        publishedAt: "2024-01-01T00:00:00Z",
        isLatest: true,
      },
    },
  } as ServerEntry;
}

function installAdapter(): ConfigAdapter {
  return {
    clientId: "claude-desktop",
    read: vi.fn().mockResolvedValue({}),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
    setServerDisabled: vi.fn().mockResolvedValue(undefined),
    replaceServer: vi.fn().mockResolvedValue(undefined),
  };
}

function installDeps(adapter: ConfigAdapter, over: Partial<InstallDeps> = {}): InstallDeps {
  return {
    registryClient: { getServer: vi.fn().mockResolvedValue(installServerEntry()) },
    detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    getAdapter: vi.fn().mockReturnValue(adapter),
    getConfigPath: vi.fn().mockReturnValue("/fake/config.json"),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue({
      score: 82,
      maxPossible: 100,
      level: "safe",
      breakdown: { healthCheck: 15, staticScan: 40, externalScan: 20, registryMeta: 7 },
    } as TrustScore),
    addToStore: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    promptEnvVars: vi.fn().mockResolvedValue({ API_KEY: "sk-xyz", REGION: "us-east" }),
    output: vi.fn(),
    ...over,
  };
}

function writtenEntry(adapter: ConfigAdapter): McpServerEntry {
  return (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0][2] as McpServerEntry;
}

describe("install --secrets keychain", () => {
  const id = deriveKeychainId("io.github.test/my-server");

  it("encrypts secret vars + writes placeholders; non-secrets stay inline", async () => {
    const adapter = installAdapter();
    const setSecret = vi.fn().mockResolvedValue(undefined);
    await handleInstall(
      "io.github.test/my-server",
      { yes: true, secrets: "keychain" },
      installDeps(adapter, { setSecret })
    );

    expect(setSecret).toHaveBeenCalledWith(id, "API_KEY", "sk-xyz");
    expect(setSecret).not.toHaveBeenCalledWith(id, "REGION", expect.anything());

    const entry = writtenEntry(adapter);
    expect(entry.env?.API_KEY).toBe(`mcpm:keychain:${id}/API_KEY`);
    expect(entry.env?.REGION).toBe("us-east");
  });

  it("never writes the plaintext secret into the config in keychain mode", async () => {
    const adapter = installAdapter();
    await handleInstall(
      "io.github.test/my-server",
      { yes: true, secrets: "keychain" },
      installDeps(adapter, { setSecret: vi.fn().mockResolvedValue(undefined) })
    );
    expect(JSON.stringify(writtenEntry(adapter))).not.toContain("sk-xyz");
  });

  it("plaintext mode (default) writes inline and does not call setSecret", async () => {
    const adapter = installAdapter();
    const setSecret = vi.fn();
    await handleInstall(
      "io.github.test/my-server",
      { yes: true },
      installDeps(adapter, { setSecret })
    );
    expect(writtenEntry(adapter).env?.API_KEY).toBe("sk-xyz");
    expect(setSecret).not.toHaveBeenCalled();
  });

  it("throws if keychain mode is requested without a setSecret dep", async () => {
    const adapter = installAdapter();
    await expect(
      handleInstall(
        "io.github.test/my-server",
        { yes: true, secrets: "keychain" },
        installDeps(adapter)
      )
    ).rejects.toThrow(/keychain/i);
  });
});

// ---------------------------------------------------------------------------
// up --secrets keychain
// ---------------------------------------------------------------------------

function upServerEntry(name: string, version: string): ServerEntry {
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
  } as ServerEntry;
}

function upAdapter(): ConfigAdapter {
  return {
    clientId: "claude-desktop",
    read: vi.fn().mockResolvedValue({}),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
    setServerDisabled: vi.fn().mockResolvedValue(undefined),
    replaceServer: vi.fn().mockResolvedValue(undefined),
  };
}

function upDeps(adapter: ConfigAdapter, over: Partial<UpDeps> = {}): UpDeps {
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn().mockReturnValue(adapter),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    getServer: vi
      .fn()
      .mockImplementation((name: string, v?: string) =>
        Promise.resolve(upServerEntry(name, v ?? "1.0.0"))
      ),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue({
      score: 75,
      maxPossible: 80,
      level: "safe",
      breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
    } as TrustScore),
    runLock: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    promptEnvVar: vi.fn().mockResolvedValue("prompted-secret"),
    output: vi.fn(),
    ...over,
  };
}

async function writeStackAndLock(stackYaml: string, lockYaml: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-p2-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stackYaml, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lockYaml, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

// Use an unusual env var name so the host environment can't accidentally supply it.
const stackWithSecret = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
    env:
      SERVER_A_SECRET:
        secret: true
        required: true
`;

const lockA = `
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

describe("up --secrets keychain", () => {
  it("rejects keychain mode under --ci (won't persist secrets on a CI runner)", async () => {
    await expect(
      handleUp({ secrets: "keychain", ci: true }, upDeps(upAdapter()))
    ).rejects.toThrow(/ci/i);
  });

  it("encrypts the secret env var and writes a placeholder into the config", async () => {
    delete process.env.SERVER_A_SECRET;
    const stackPath = await writeStackAndLock(stackWithSecret, lockA);
    const adapter = upAdapter();
    const setSecret = vi.fn().mockResolvedValue(undefined);
    await handleUp({ stackFile: stackPath, secrets: "keychain" }, upDeps(adapter, { setSecret }));

    const id = deriveKeychainId("io.github.test/server-a");
    expect(setSecret).toHaveBeenCalledWith(id, "SERVER_A_SECRET", "prompted-secret");
    const entry = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0][2] as McpServerEntry;
    expect(entry.env?.SERVER_A_SECRET).toBe(`mcpm:keychain:${id}/SERVER_A_SECRET`);
  });
});
