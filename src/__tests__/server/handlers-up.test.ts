/**
 * Tests for handleMcpUp — the MCP (untrusted-caller) surface over `mcpm up`.
 *
 * These exercise the PR #64 hardening fixes:
 *  - A: a thrown handleUp failure is surfaced (result.error + result.failed),
 *       never swallowed into a clean empty result.
 *  - C: allowProcessEnv:false — a required env var only present in process.env is
 *       NOT auto-read, so the server fails (and the failure is surfaced).
 *  - D: allowUrlServers:false — URL servers are recorded as blocked, never installed.
 *
 * handleMcpUp constructs its own RegistryClient and reads the stack file relative
 * to process.cwd(), so we mock the registry module and chdir into a temp dir that
 * holds a real mcpm.yaml + mcpm-lock.yaml.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";
import type { ServerEntry } from "../../registry/types.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import type { ServerDeps } from "../../server/handlers.js";

// ---------------------------------------------------------------------------
// Mock the registry client that handleMcpUp constructs internally.
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

// vi.hoisted: the factory below is hoisted above normal module init, so the mock
// fn must be created in a hoisted block to be referenceable inside it.
const { getServerMock } = vi.hoisted(() => ({
  getServerMock: vi.fn((name: string, version?: string) =>
    Promise.resolve(makeServerEntry(name, version ?? "1.0.0"))
  ),
}));

vi.mock("../../registry/client.js", () => ({
  RegistryClient: class {
    getServer = getServerMock;
    getServerVersions = vi.fn().mockResolvedValue([]);
    searchServers = vi.fn().mockResolvedValue({ servers: [] });
  },
}));

// Imported after vi.mock so the mocked RegistryClient is in effect.
const { handleMcpUp } = await import("../../server/handlers.js");

// ---------------------------------------------------------------------------
// Deps + adapter helpers
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

function makeDeps(adapter = makeAdapter()): ServerDeps {
  return {
    registrySearch: vi.fn().mockResolvedValue([]),
    registryGetServer: vi.fn((name: string) =>
      Promise.resolve(makeServerEntry(name, "1.0.0"))
    ),
    detectClients: vi
      .fn<() => Promise<ClientId[]>>()
      .mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn().mockReturnValue(adapter),
    getConfigPath: vi.fn().mockReturnValue("/mock/config.json"),
    scanTier1: vi.fn().mockReturnValue([]),
    computeTrustScore: vi.fn().mockReturnValue({
      score: 75,
      maxPossible: 80,
      level: "safe",
      breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
    }),
    addToStore: vi.fn().mockResolvedValue(undefined),
    removeFromStore: vi.fn().mockResolvedValue(undefined),
  };
}

const lockFor = (name: string, identifier: string) => `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  ${name}:
    version: "1.0.0"
    registryType: npm
    identifier: "${identifier}"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;

// ---------------------------------------------------------------------------
// cwd management — handleMcpUp resolves the stack file relative to cwd.
// ---------------------------------------------------------------------------

let originalCwd: string;
let tmpDir: string;

async function writeStack(stackYaml: string, lockYaml?: string): Promise<void> {
  await writeFile(path.join(tmpDir, "mcpm.yaml"), stackYaml, "utf-8");
  if (lockYaml !== undefined) {
    await writeFile(path.join(tmpDir, "mcpm-lock.yaml"), lockYaml, "utf-8");
  }
}

beforeEach(async () => {
  originalCwd = process.cwd();
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "mcpm-mcpup-test-"));
  process.chdir(tmpDir);
  getServerMock.mockClear();
});

afterEach(() => {
  process.chdir(originalCwd);
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleMcpUp", () => {
  const REGISTRY_STACK = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
  const REGISTRY_LOCK = lockFor("io.github.test/server-a", "@test/server-a");

  // Fix F.2
  it("dryRun: true does not install and returns no installed servers", async () => {
    await writeStack(REGISTRY_STACK, REGISTRY_LOCK);
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);

    const result = await handleMcpUp({ dryRun: true }, deps);

    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(result.installed).toEqual([]);
    expect(result.error).toBeUndefined();
  });

  // Fix F.3
  it("blocked-by-policy: low-trust server with high minTrustScore appears in blocked", async () => {
    const stackWithPolicy = `
version: "1"
policy:
  minTrustScore: 90
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;
    await writeStack(stackWithPolicy, REGISTRY_LOCK);
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);
    // Trust 75/80 = 94%... so force a low score to be below the 90% floor.
    (deps.computeTrustScore as ReturnType<typeof vi.fn>).mockReturnValue({
      score: 30,
      maxPossible: 80,
      level: "risky",
      breakdown: { healthCheck: 0, staticScan: 20, externalScan: 0, registryMeta: 10 },
    });

    const result = await handleMcpUp({}, deps);

    expect(result.blocked).toContain("io.github.test/server-a");
    expect(adapter.addServer).not.toHaveBeenCalled();
  });

  // Fix F.4 (and fix A + fix C)
  it("missing-env (allowProcessEnv:false): required env not provided -> failed + surfaced error", async () => {
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
    await writeStack(stackWithEnv, REGISTRY_LOCK);
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);

    // Even if the secret leaks into process.env, allowProcessEnv:false must NOT
    // read it — so the required var stays unresolved and the server fails.
    const original = process.env.API_TOKEN;
    process.env.API_TOKEN = "ambient-secret-should-not-be-used";
    try {
      const result = await handleMcpUp({}, deps);

      // Fix A: a thrown failure is surfaced, not swallowed into a clean result.
      expect(result.error).toBeDefined();
      expect(result.failed.length).toBeGreaterThan(0);
      expect(result.installed).toEqual([]);
      // Fix C: the ambient secret was never written into a client config.
      expect(adapter.addServer).not.toHaveBeenCalled();
    } finally {
      if (original === undefined) delete process.env.API_TOKEN;
      else process.env.API_TOKEN = original;
    }
  });

  // Fix F.5 (and fix D)
  it("URL server (allowUrlServers:false): appears in blocked, addServer not called", async () => {
    const urlStack = `
version: "1"
servers:
  io.github.test/remote:
    url: "https://example.com/mcp"
`;
    // URL servers do not require a lock entry; omit the lock file so runLock is
    // a no-op-ish path is avoided — provide an (unused) lock to keep it simple.
    const urlLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/remote:
    url: "https://example.com/mcp"
`;
    await writeStack(urlStack, urlLock);
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);

    const result = await handleMcpUp({}, deps);

    expect(result.blocked).toContain("io.github.test/remote");
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(result.installed).toEqual([]);
  });

  // Fix A: no clients detected -> handleUp throws -> surfaced, not clean empty.
  it("surfaces a thrown failure when no clients are detected", async () => {
    await writeStack(REGISTRY_STACK, REGISTRY_LOCK);
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);
    (deps.detectClients as ReturnType<typeof vi.fn>).mockResolvedValue([]);

    const result = await handleMcpUp({}, deps);

    expect(result.error).toBeDefined();
    expect(result.failed.length).toBeGreaterThan(0);
    expect(result.installed).toEqual([]);
  });

  // Fix B: a traversing stackFile is rejected unconditionally (resolved-path
  // containment), independent of the Zod default.
  it("rejects a stackFile outside the working directory (path traversal)", async () => {
    await writeStack(REGISTRY_STACK, REGISTRY_LOCK);
    const deps = makeDeps();

    await expect(
      handleMcpUp({ stackFile: "../escape.yaml" }, deps)
    ).rejects.toThrow("within the working directory");
  });

  // Happy path: a registry server installs and is categorized as installed.
  it("installs a registry server and reports it under installed", async () => {
    await writeStack(REGISTRY_STACK, REGISTRY_LOCK);
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);

    const result = await handleMcpUp({}, deps);

    expect(result.installed).toContain("io.github.test/server-a");
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    expect(result.error).toBeUndefined();
  });
});
