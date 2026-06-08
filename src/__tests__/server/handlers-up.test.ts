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

// Integration-style tests: each uses a real temp dir, and the first handleMcpUp
// call pays a one-time dynamic import("../commands/up.js"). Under CI coverage
// instrumentation on the slower Node 22 runner that first test can exceed the
// 5s default timeout, so raise it for this file (it runs ~1s locally).
vi.setConfig({ testTimeout: 30000 });

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

  // Fix F.3, corrected per review finding H2: handleMcpUp constructs its own
  // handleUp deps with the REAL computeTrustScore (cts), so overriding
  // deps.computeTrustScore (as the original test did) has no effect on this path.
  // We instead drive the genuine pipeline: the clean mock server scores 55/80 = 69%
  // (health-null 15 + static 40 + externalScan 0 + registryMeta 0; no scanner ->
  // maxPossible 80), which is below the 90% policy floor (and the 94% lock snapshot
  // also blocks it via score-drop), so the real checkTrustPolicy blocks it.
  it("blocked-by-policy: a server below the trust floor is blocked via the real pipeline", async () => {
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
      // M1: the failed server lands in `failed` by NAME (not the error message).
      expect(result.error).toBeDefined();
      expect(result.failed).toContain("io.github.test/server-a");
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

    // M1: a whole-batch throw (no server ever processed) is signaled via the
    // authoritative `error` field — NOT by poisoning `failed`, which holds server
    // names only. So `failed` is empty here while `error` carries the message.
    expect(result.error).toBeDefined();
    expect(result.failed).toEqual([]);
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

  // H1: a `.env` in the working directory is an ambient secret source. On the MCP
  // surface (allowEnvFile:false) it must NOT be harvested into an installed config.
  // This fails on the pre-fix code (which read .env ungated) and passes after.
  it("does not harvest the working-directory .env into installed configs (H1)", async () => {
    const stackWithEnv = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
    env:
      LEAKME:
        required: false
        secret: false
`;
    await writeStack(stackWithEnv, REGISTRY_LOCK);
    await writeFile(
      path.join(tmpDir, ".env"),
      "LEAKME=host-secret-from-dotenv\n",
      "utf-8"
    );
    const adapter = makeAdapter();
    const deps = makeDeps(adapter);

    const result = await handleMcpUp({}, deps);

    expect(result.installed).toContain("io.github.test/server-a");
    // Installed, but the .env value must never reach the written config env.
    const entry = adapter.addServer.mock.calls[0]?.[2] as
      | { env?: Record<string, string> }
      | undefined;
    expect(entry?.env?.LEAKME).toBeUndefined();
  });

  // M3: lexical containment passes an in-cwd symlink (its own path is inside cwd),
  // but the reader would follow it out of tree. The realpath re-check must reject it.
  it("rejects a stackFile that is an in-cwd symlink pointing outside (symlink traversal)", async () => {
    const { symlink, writeFile: wf, mkdtemp: mkd } = await import("fs/promises");
    const outsideDir = await mkd(path.join(os.tmpdir(), "mcpm-outside-"));
    const outsideTarget = path.join(outsideDir, "secret.yaml");
    await wf(outsideTarget, REGISTRY_STACK, "utf-8");
    // Plant an in-cwd symlink whose real target is outside cwd.
    await symlink(outsideTarget, path.join(tmpDir, "link.yaml"));
    const deps = makeDeps();

    await expect(
      handleMcpUp({ stackFile: "link.yaml" }, deps)
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
