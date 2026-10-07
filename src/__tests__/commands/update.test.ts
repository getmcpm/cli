/**
 * Tests for src/commands/update.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - All external deps (store, registry, config adapters) are injected as mocks.
 * - Test handler directly — not Commander parsing.
 * - Cover: no servers, all up-to-date, one update available, --yes flag, --json,
 *   registry unavailable, trust score change display, config update.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { GeminiCliAdapter } from "../../config/adapters/gemini-cli.js";
import { VSCodeAdapter } from "../../config/adapters/vscode.js";
import { wrapEntry, unwrapEntry, isWrapped, WRAP_CONFINE_HASH_FLAG, WRAP_CONFINE_REQUIRED_FLAG } from "../../guard/wrap.js";
import type { InstalledServer } from "../../store/servers.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { Finding } from "../../scanner/tier1.js";
import type { ClientId } from "../../config/paths.js";
import { CLEAN_PENDING_LABEL } from "../../utils/format-trust.js";
import {
  NetworkError,
  NotFoundError,
  ValidationError,
} from "../../registry/errors.js";
import type { ConfigAdapter } from "../../config/adapters/index.js";

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

function makeTrustScore(
  level: "safe" | "caution" | "risky",
  score = 75,
  // 15 = health check NOT run, which is what `update` always produces (it scores with
  // `healthCheckPassed: null`). Pass 30 for the ran-and-passed case.
  healthCheck = 15,
  // 10 = the credited external scanner found things, so the server is not clean.
  externalScan = 10
): TrustScore {
  return {
    score,
    maxPossible: 100,
    level,
    breakdown: { healthCheck, staticScan: 40, externalScan, registryMeta: 10 },
  };
}

function makeAdapter(clientId: ClientId): ConfigAdapter {
  return {
    clientId,
    read: vi.fn().mockResolvedValue({
      "io.github.test/server-a": { command: "npx", args: ["-y", "@test/server"] },
      "io.github.test/server-b": { command: "npx", args: ["-y", "@test/server"] },
    }),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
  };
}

// ---------------------------------------------------------------------------
// Deps interface
// ---------------------------------------------------------------------------

interface UpdateDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string) => Promise<ServerEntry>;
  addInstalledServer: (server: InstalledServer) => Promise<void>;
  removeInstalledServer: (name: string) => Promise<void>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: {
    findings: Finding[];
    healthCheckPassed: boolean | null;
    hasExternalScanner: boolean;
    registryMeta: Record<string, unknown>;
  }) => TrustScore;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

function makeDeps(overrides: Partial<UpdateDeps> = {}): UpdateDeps {
  return {
    getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer()]),
    getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.0.0")),
    addInstalledServer: vi.fn().mockResolvedValue(undefined),
    removeInstalledServer: vi.fn().mockResolvedValue(undefined),
    getAdapter: vi.fn().mockImplementation((id: ClientId) => makeAdapter(id)),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    scanTier1: vi.fn().mockReturnValue([]),
    computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe")),
    confirm: vi.fn().mockResolvedValue(true),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

import { handleUpdate } from "../../commands/update.js";
import type { UpdateOptions } from "../../commands/update.js";

describe("handleUpdate — preserves launch protections and client settings (#115)", () => {
  it("repairs malformed env without dropping disabled state, native settings or valid custom args", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-update-recovery-"));
    const configPath = path.join(dir, "config.json");
    const name = "io.github.test/server-a";
    const adapter = new GeminiCliAdapter();
    const original = {
      command: "npx", args: ["-y", "@test/server", "/user/data"],
      env: { TOKEN: "keep", PORT: 1234 }, disabled: true,
      cwd: "/user/data", timeout: 1234, includeTools: ["read_file"],
    };
    try {
      await adapter.addServer(configPath, name, original as never);
      await handleUpdate({ yes: true }, makeDeps({
        getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer({ clients: [adapter.clientId] })]),
        getServer: vi.fn(async (_name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
        getAdapter: () => adapter, getConfigPath: () => configPath,
      }));
      expect((await adapter.read(configPath))[name]).toEqual({ ...original, args: ["-y", "@test/server@2.0.0", "/user/data"], env: { TOKEN: "keep" } });
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each([false, true])("preserves an external envFile and refuses only guarded updates (guarded=%s)", async (guarded) => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-update-envfile-"));
    const configPath = path.join(dir, "config.json");
    const name = "io.github.test/server-a";
    const adapter = new VSCodeAdapter();
    const original = { command: "npx", args: ["-y", "@test/server"], disabled: true };
    const configured = { ...(guarded ? wrapEntry(name, original, { mcpmBinary: "mcpm" }) : original), envFile: "/user/.env", type: "stdio" };
    try {
      await adapter.addServer(configPath, name, configured);
      const before = await readFile(configPath, "utf8");
      const deps = makeDeps({
        getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer({ clients: [adapter.clientId] })]),
        getServer: vi.fn(async (n: string, v?: string) => makeServerEntry(n, v ?? "2.0.0")),
        getAdapter: () => adapter, getConfigPath: () => configPath,
      });
      await handleUpdate({ yes: true, json: true }, deps);
      expect((await adapter.read(configPath))[name]).toEqual(guarded ? configured : { ...configured, args: ["-y", "@test/server@2.0.0"] });
      if (guarded) {
        expect(await readFile(configPath, "utf8")).toBe(before);
        expect(deps.addInstalledServer).not.toHaveBeenCalled();
        expect(deps.removeInstalledServer).not.toHaveBeenCalled();
        expect(JSON.parse((deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0])[0]).toMatchObject({ updated: false, clientErrors: [expect.stringMatching(/envFile/)] });
        expect(unwrapEntry(configured)).toEqual({ ...original, envFile: "/user/.env", type: "stdio" });
      } else expect(deps.addInstalledServer).toHaveBeenCalled();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it("keeps a custom arg on an unguarded server while replacing the old registry defaults", async () => {
    const name = "io.github.test/server-a";
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockResolvedValue({ [name]: {
      command: "npx", args: ["-y", "@test/server", "--old", "user-arg"], env: { TOKEN: "keep" }, disabled: true, cwd: "/data",
    } });
    const getServer = vi.fn(async (_name: string, version?: string) => {
      const entry = makeServerEntry(name, version ?? "2.0.0");
      entry.server.packages[0].runtimeArguments = [version ? "--old" : "--new"];
      return entry;
    });
    await handleUpdate({ yes: true }, makeDeps({ getServer, getAdapter: () => adapter }));
    expect(adapter.addServer).toHaveBeenCalledWith(expect.any(String), name, {
      command: "npx", args: ["-y", "@test/server@2.0.0", "--new", "user-arg"], env: { TOKEN: "keep" }, disabled: true, cwd: "/data",
    }, { force: true });
  });

  it.each(["unavailable", "wrong version", "wrong identity", "changed launcher", "changed transport"])("leaves custom args untouched when the historical baseline is %s", async (kind) => {
    const name = "io.github.test/server-a";
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockResolvedValue({ [name]: { command: "npx", args: ["-y", "@test/server", "user-arg"] } });
    const getServer = vi.fn(async (_name: string, version?: string) => {
      if (version && kind === "unavailable") throw new NotFoundError(name);
      const entry = makeServerEntry(version && kind === "wrong identity" ? "another-server" : name,
        version && kind !== "wrong version" ? version : "2.0.0");
      if (!version && kind === "changed launcher") {
        entry.server.packages[0].registryType = "pypi";
        entry.server.packages[0].identifier = "new-server";
      }
      if (!version && kind === "changed transport") {
        entry.server.remotes = [{ type: "streamable-http", url: "https://example.com/mcp", headers: [] }];
      }
      return entry;
    });
    const deps = makeDeps({ getServer, getAdapter: () => adapter,
      getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer({ clients: ["cursor"] })]),
    });
    await handleUpdate({ yes: true }, deps);
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(deps.removeInstalledServer).not.toHaveBeenCalled();
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });

  it("keeps remote credentials and native settings while replacing the registry URL", async () => {
    const name = "io.github.test/server-a";
    const adapter = makeAdapter("cursor");
    (adapter.read as ReturnType<typeof vi.fn>).mockResolvedValue({ [name]: {
      url: "https://old.example/mcp", headers: { Authorization: "Bearer user-token" }, disabled: true, timeout: 1234, type: "http",
    } });
    const getServer = vi.fn(async (_name: string, version?: string) => {
      const entry = makeServerEntry(name, version ?? "2.0.0");
      entry.server.remotes = [{ type: "streamable-http", url: version ? "https://old.example/mcp" : "https://new.example/mcp", headers: [{ name: "Authorization" }] }];
      return entry;
    });
    await handleUpdate({ yes: true }, makeDeps({ getServer, getAdapter: () => adapter,
      getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer({ clients: ["cursor"] })]),
    }));
    expect(adapter.addServer).toHaveBeenCalledWith(expect.any(String), name, {
      url: "https://new.example/mcp", headers: { Authorization: "Bearer user-token" }, disabled: true, timeout: 1234, type: "http",
    }, { force: true });
  });

  it.each([new GeminiCliAdapter(), new VSCodeAdapter()])("updates a confined disabled server through $clientId without losing user settings", async (adapter) => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-update-"));
    const configPath = path.join(dir, "config.json");
    const name = "io.github.test/oci";
    const original = {
      command: "docker", args: ["run", "--rm", "-i", "ghcr.io/test/server:1.0.0", "--old-default", "/user/data"],
      env: { NODE_OPTIONS: "--require /user/bootstrap.cjs", API_KEY: "${mcpm:secret:test}" },
      disabled: true, cwd: "/user/data", timeout: 1234, includeTools: ["read_file"], type: "stdio",
    };
    const profileHash = "a".repeat(64);
    const wrapper = { mcpmBinary: "/user/node", scriptPath: "/user/mcpm/dist/index.js" };
    const getServer = vi.fn(async (_name: string, version?: string) => {
      const entry = makeOciEntry(name, version ?? "2.0.0");
      entry.server.packages[0].runtimeArguments = [version ? "--old-default" : "--new-default"];
      return entry;
    });
    try {
      await adapter.addServer(configPath, name, wrapEntry(name, original, wrapper, { profileHash, required: true }));
      const deps = makeDeps({
        getInstalledServers: vi.fn().mockResolvedValue([makeInstalledServer({ name, clients: [adapter.clientId] })]),
        getServer, getAdapter: () => adapter, getConfigPath: () => configPath,
      });
      await handleUpdate({ yes: true, json: true }, deps);
      const updated = (await adapter.read(configPath))[name];
      expect(isWrapped(updated)).toBe(true);
      expect(updated.command).toBe(wrapper.mcpmBinary);
      expect(updated.args?.[0]).toBe(wrapper.scriptPath);
      expect(updated.args).toContain(WRAP_CONFINE_REQUIRED_FLAG);
      expect(updated.args?.[updated.args.indexOf(WRAP_CONFINE_HASH_FLAG) + 1]).toBe(profileHash);
      expect(updated.env?.NODE_OPTIONS).toBeUndefined();
      expect(unwrapEntry(updated)).toEqual({ ...original, args: ["run", "--rm", "-i", "ghcr.io/test/server:2.0.0", "--new-default", "/user/data"] });
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each([false, true])("refuses a deleted listing before confirmation or writes (json=%s)", async (json) => {
    const entry = makeServerEntry("io.github.test/server-a", "2.0.0");
    entry._meta!["io.modelcontextprotocol.registry/official"]!.status = "deleted";
    entry._meta!["io.modelcontextprotocol.registry/official"]!.statusMessage = "malware reported";
    const adapter = makeAdapter("claude-desktop");
    const lines: string[] = [];
    const deps = makeDeps({ getServer: vi.fn(async (name: string, version?: string) => version ? makeServerEntry(name, version) : entry), getAdapter: () => adapter, output: (t) => lines.push(t) });
    await handleUpdate({ json }, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
    expect(deps.removeInstalledServer).not.toHaveBeenCalled();
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(lines.join("\n")).toMatch(/deleted.*malware reported/i);
    if (json) expect(JSON.parse(lines.join("\n"))[0]).toMatchObject({ updated: false, error: expect.stringMatching(/deleted/i) });
  });

  it.each(["missing", "custom launcher", "tampered guard", "unreadable"])("does not overwrite %s config or advance the store", async (kind) => {
    const adapter = makeAdapter("claude-desktop");
    let existing = { command: "npx", args: ["-y", "@test/server"], env: { TOKEN: "keep" } };
    if (kind === "custom launcher") existing.command = "custom-launcher";
    if (kind === "tampered guard") {
      existing = wrapEntry("io.github.test/server-a", existing, { mcpmBinary: "mcpm" }) as typeof existing;
      existing.args[existing.args.length - 1] = "@attacker/server";
    }
    (adapter.read as ReturnType<typeof vi.fn>).mockResolvedValue(kind === "missing" ? {} : { "io.github.test/server-a": existing });
    if (kind === "unreadable") (adapter.read as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("permission denied"));
    const lines: string[] = [];
    const deps = makeDeps({ getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")), getAdapter: () => adapter, output: (t) => lines.push(t) });
    await handleUpdate({ yes: true, json: true }, deps);
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(deps.removeInstalledServer).not.toHaveBeenCalled();
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
    expect(JSON.parse(lines.join("\n"))[0]).toMatchObject({ updated: false, clientErrors: expect.any(Array) });
  });
});

// ---------------------------------------------------------------------------
// No servers installed
// ---------------------------------------------------------------------------

describe("handleUpdate — no servers installed", () => {
  it("outputs a message when no servers are installed", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([]),
      output: (t) => lines.push(t),
    });
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(/no servers installed/i);
  });

  it("does not call getServer when no servers are installed", async () => {
    const deps = makeDeps({ getInstalledServers: vi.fn().mockResolvedValue([]) });
    await handleUpdate({}, deps);
    expect(deps.getServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// All up to date
// ---------------------------------------------------------------------------

describe("handleUpdate — all up to date", () => {
  it("outputs 'all servers are up to date' when no version changes", async () => {
    // Installed version matches registry version
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ version: "1.0.0" }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.0.0")),
    });
    const lines: string[] = [];
    await handleUpdate({}, { ...deps, output: (t) => lines.push(t) });
    expect(lines.join("\n")).toMatch(/all servers are up to date/i);
  });

  it("does not prompt for confirmation when nothing to update", async () => {
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.0.0")),
    });
    await handleUpdate({}, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
  });

  it("does not call addInstalledServer when all are current", async () => {
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.0.0")),
    });
    await handleUpdate({}, deps);
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Update available
// ---------------------------------------------------------------------------

describe("handleUpdate — one update available", () => {
  function makeUpdateDeps() {
    return makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
    });
  }

  it("shows the old and new version in the output", async () => {
    const lines: string[] = [];
    const deps = { ...makeUpdateDeps(), output: (t: string) => lines.push(t) };
    await handleUpdate({}, deps);
    const out = lines.join("\n");
    expect(out).toContain("1.0.0");
    expect(out).toContain("1.1.0");
  });

  it("shows the server name in the output", async () => {
    const lines: string[] = [];
    const deps = { ...makeUpdateDeps(), output: (t: string) => lines.push(t) };
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toContain("io.github.test/server-a");
  });

  it("prompts for confirmation before updating", async () => {
    const deps = makeUpdateDeps();
    await handleUpdate({}, deps);
    expect(deps.confirm).toHaveBeenCalledOnce();
  });

  it("updates the store record with new version when confirmed", async () => {
    const deps = makeUpdateDeps();
    await handleUpdate({}, deps);
    expect(deps.removeInstalledServer).toHaveBeenCalledWith("io.github.test/server-a");
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-a", version: "1.1.0" })
    );
  });

  it("does NOT update when user declines confirmation", async () => {
    const deps = makeUpdateDeps();
    deps.confirm = vi.fn().mockResolvedValue(false);
    await handleUpdate({}, deps);
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });

  it("outputs cancellation note when user declines", async () => {
    const lines: string[] = [];
    const deps = { ...makeUpdateDeps(), confirm: vi.fn().mockResolvedValue(false), output: (t: string) => lines.push(t) };
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(/cancel|skipp/i);
  });

  it("runs trust scan on the new version", async () => {
    const deps = makeUpdateDeps();
    await handleUpdate({}, deps);
    expect(deps.scanTier1).toHaveBeenCalled();
    expect(deps.computeTrustScore).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Fix #5: client config is re-written on update (not just the store record)
// ---------------------------------------------------------------------------

function makeOciEntry(name: string, version: string): ServerEntry {
  return {
    server: {
      name,
      description: "An OCI test server",
      version,
      repository: { url: "https://github.com/test/server" },
      packages: [
        {
          registryType: "oci",
          identifier: `ghcr.io/test/server:${version}`,
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

describe("handleUpdate — writes new version to client config", () => {
  it("calls adapter.addServer with the new-version entry for each client", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockResolvedValue({
      "io.github.test/oci": { command: "docker", args: ["run", "--rm", "-i", "ghcr.io/test/server:1.0.0"] },
    });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/oci", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeOciEntry(name, version ?? "2.0.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);

    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toBe("/fake/claude-desktop/config.json");
    expect(call[1]).toBe("io.github.test/oci");
    // The re-resolved entry must carry the NEW version (2.0.0), not the old one.
    expect(call[2].command).toBe("docker");
    expect(call[2].args).toContain("ghcr.io/test/server:2.0.0");
    expect(call[3]).toEqual({ force: true });
  });

  it("does not write to client config when nothing is updated", async () => {
    const adapter = makeAdapter("claude-desktop");
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.0.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await handleUpdate({ yes: true }, deps);
    expect(adapter.addServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Fix #1: a pre-existing client-config env block (e.g. API keys) must be
// preserved into the re-written entry — a regression would silently wipe them.
// ---------------------------------------------------------------------------

describe("handleUpdate — preserves existing client-config env on update", () => {
  it("carries the user's existing env values into the new entry", async () => {
    const adapter = makeAdapter("claude-desktop");
    // The config already has this server with a user-set API key.
    (adapter.read as ReturnType<typeof vi.fn>).mockResolvedValue({
      "io.github.test/server-a": {
        command: "npx",
        args: ["-y", "@test/server"],
        env: { MY_KEY: "user-value" },
      },
    });
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);

    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[2].env.MY_KEY).toBe("user-value");
  });
});

// ---------------------------------------------------------------------------
// Fix #2: a per-client config-write failure must not be swallowed — surface a
// warning so a client silently left on the old version is visible.
// ---------------------------------------------------------------------------

describe("handleUpdate — partial config-write failure warning", () => {
  it("warns when a client config write fails (instead of silently swallowing)", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.addServer as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("config is read-only")
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);

    const out = lines.join("\n");
    expect(out).toMatch(/warning/i);
    expect(out).toContain("claude-desktop");
    expect(out).toContain("config is read-only");
  });

  it("advances the store on partial success while naming the client left behind", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.addServer as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("config is read-only")
    );
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop", "cursor"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: (id) => id === "claude-desktop" ? adapter : makeAdapter(id),
    });

    await handleUpdate({ yes: true }, deps);

    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-a", version: "1.1.0" })
    );
  });
});

// ---------------------------------------------------------------------------
// --yes flag skips confirmation
// ---------------------------------------------------------------------------

describe("handleUpdate — --yes flag", () => {
  it("does not call confirm when --yes is set", async () => {
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
    });
    await handleUpdate({ yes: true }, deps);
    expect(deps.confirm).not.toHaveBeenCalled();
  });

  it("still updates the store when --yes is set", async () => {
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
    });
    await handleUpdate({ yes: true }, deps);
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ version: "2.0.0" })
    );
  });
});

// ---------------------------------------------------------------------------
// --json flag
// ---------------------------------------------------------------------------

describe("handleUpdate — --json flag", () => {
  it("outputs valid JSON when --json is set and updates available", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ json: true, yes: true }, deps);
    const parsed = JSON.parse(lines.join("\n"));
    expect(Array.isArray(parsed)).toBe(true);
  });

  it("JSON output includes name, oldVersion, newVersion, updated", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ json: true, yes: true }, deps);
    const parsed = JSON.parse(lines.join("\n")) as Array<{
      name: string;
      oldVersion: string;
      newVersion: string;
      updated: boolean;
    }>;
    expect(parsed[0]).toMatchObject({
      name: "io.github.test/server-a",
      oldVersion: "1.0.0",
      newVersion: "2.0.0",
      updated: true,
    });
  });

  it("JSON output marks updated: false for up-to-date servers", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ json: true }, deps);
    const parsed = JSON.parse(lines.join("\n")) as Array<{ updated: boolean }>;
    expect(parsed[0].updated).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Registry unavailable (graceful)
// ---------------------------------------------------------------------------

describe("handleUpdate — registry unavailable", () => {
  it("shows error note for server when registry fails", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(new Error("Network failure")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(/error|unavailable|failed|could not/i);
  });

  // #92: same collapse as audit — each class must report itself.
  it.each([
    ["a 404", () => new NotFoundError("io.github.test/server"), /delisted/i],
    ["an unparseable body", () => new ValidationError("bad shape"), /could not parse/i],
    [
      "a network failure",
      () => new NetworkError("boom", new Error("ECONNREFUSED")),
      /unavailable/i,
    ],
  ])("reports %s as itself, not as a generic outage", async (_label, makeErr, expected) => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(makeErr()),
      output: (t: string) => lines.push(t),
    });
    await handleUpdate({}, deps);
    expect(lines.join("\n")).toMatch(expected);
  });

  it("does not call addInstalledServer when registry fails", async () => {
    const deps = makeDeps({
      getServer: vi.fn().mockRejectedValue(new Error("Network failure")),
    });
    await handleUpdate({}, deps);
    expect(deps.addInstalledServer).not.toHaveBeenCalled();
  });

  it("continues with other servers when one fails", async () => {
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
        makeInstalledServer({ name: "io.github.test/server-b", version: "1.0.0" }),
      ]),
      getServer: vi.fn()
        .mockImplementation(async (name: string, version?: string) => {
          if (name.endsWith("server-a")) throw new Error("Network failure");
          return makeServerEntry(name, version ?? "2.0.0");
        }),
    });
    await handleUpdate({ yes: true }, deps);
    // Second server should be updated
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-b", version: "2.0.0" })
    );
  });
});

// ---------------------------------------------------------------------------
// Trust score display on update
// ---------------------------------------------------------------------------

describe("handleUpdate — trust score on update", () => {
  it("shows trust level in the output after update", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe", 80, 15, 20)),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ yes: true }, deps);
    // NOT /safe/i. `update` scores with `healthCheckPassed: null`, so nothing it prints was
    // ever verified by a health check — it now says so rather than borrowing `safe`.
    expect(lines.join("\n")).toContain(CLEAN_PENDING_LABEL);
  });

  it("still says safe when the health check actually ran", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "2.0.0")),
      computeTrustScore: vi.fn().mockReturnValue(makeTrustScore("safe", 80, 30, 20)),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ yes: true }, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/safe/i);
    expect(out).not.toContain(CLEAN_PENDING_LABEL);
  });
});

// ---------------------------------------------------------------------------
// Multiple servers — some up to date, some not
// ---------------------------------------------------------------------------

describe("handleUpdate — multiple servers mixed state", () => {
  it("only updates servers with newer versions", async () => {
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
        makeInstalledServer({ name: "io.github.test/server-b", version: "2.0.0" }),
      ]),
      getServer: vi.fn()
        .mockImplementation(async (name: string, version?: string) => makeServerEntry(name, version ?? (name.endsWith("server-a") ? "1.1.0" : "2.0.0"))),
    });
    await handleUpdate({ yes: true }, deps);
    expect(deps.addInstalledServer).toHaveBeenCalledOnce();
    expect(deps.addInstalledServer).toHaveBeenCalledWith(
      expect.objectContaining({ name: "io.github.test/server-a", version: "1.1.0" })
    );
  });

  it("outputs a summary of what was updated", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0" }),
        makeInstalledServer({ name: "io.github.test/server-b", version: "2.0.0" }),
      ]),
      getServer: vi.fn()
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-a", "1.1.0"))
        .mockResolvedValueOnce(makeServerEntry("io.github.test/server-b", "2.0.0")),
      output: (t) => lines.push(t),
    });
    await handleUpdate({ yes: true }, deps);
    const out = lines.join("\n");
    expect(out).toContain("server-a");
  });
});

// ---------------------------------------------------------------------------
// #59 / #23 regression: `readExistingEnv` reads through `BaseAdapter.read()`,
// which since #23 (v0.34.0) DROPS an entry failing shape validation. A user
// whose entry was malformed in one field (e.g. `args: "bad"` from a hand-edit)
// but whose `env` held real API keys therefore got `undefined` back, and the
// `force: true` re-write wiped those keys while printing "✓ Updated".
// The existing "preserves existing client-config env" test above cannot see
// this: it mocks read() to RETURN the entry, the one thing the real read()
// stopped doing.
// ---------------------------------------------------------------------------

/** Mimic the real read(): a malformed entry goes to onSkip, never to the map. */
function readDropping(malformed: Record<string, unknown>, valid: Record<string, unknown> = {}) {
  return vi
    .fn()
    .mockImplementation(async (_p: string, onSkip?: (n: string, raw: unknown) => void) => {
      for (const [name, raw] of Object.entries(malformed)) onSkip?.(name, raw);
      return { ...valid };
    });
}

describe("handleUpdate — malformed client entry must not silently wipe env", () => {
  it("recovers the env block from the raw entry and REPAIRS the entry", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "io.github.test/server-a": {
          command: "npx",
          args: "-y @test/server", // the malformation
          env: { MY_KEY: "user-value" },
        },
      })
    );
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);

    // The write MUST happen — overwriting a mis-shaped entry with a freshly
    // resolved one is the user's self-repair path. Refusing it would convert a
    // self-healing case into a permanently stuck one.
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    // ...and it must carry the secrets forward.
    expect(call[2].env.MY_KEY).toBe("user-value");
    // ...and the repaired entry must have a well-formed args array.
    expect(Array.isArray(call[2].args)).toBe(true);
  });

  it("still repairs a malformed entry that has NO env to recover", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({ "io.github.test/server-a": { command: "npx", args: "-y @test/server" } })
    );
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
  });

  it("ignores an env recovered from a DIFFERENT malformed entry", async () => {
    // The onSkip callback fires for every malformed entry in the config, not
    // just the one being updated. Without the name filter, an unrelated broken
    // neighbour's env would be grafted onto this server.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping(
        { "some-other-server": { command: "npx", args: "bad", env: { LEAKED: "from-neighbour" } } },
        { "io.github.test/server-a": { command: "npx", args: ["-y", "@test/server"] } }
      )
    );
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);

    expect(adapter.addServer).toHaveBeenCalledTimes(1);
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[2].env?.LEAKED).toBeUndefined();
  });

  it("keeps the string keys when env ITSELF is the malformed field", async () => {
    // A numeric port is the archetypal hand-edit, and it is what makes the
    // entry invalid. Parsing the whole env record then rejected EVERY key and
    // destroyed the API key beside the bad one — the exact loss this fix
    // exists to prevent, in the population it targets.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "io.github.test/server-a": {
          command: "npx",
          args: ["-y", "@test/server"],
          env: { API_KEY: "s3cret", PORT: 8080 },
        },
      })
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);

    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[2].env.API_KEY).toBe("s3cret");
    expect(call[2].env.PORT).toBeUndefined();
    // and the key that could not be carried is NAMED, not dropped in silence
    expect(lines.join("\n")).toContain("PORT");
    // ...as a NOTE. "could not update claude-desktop" would be false: it did.
    expect(lines.join("\n")).toContain("(note:");
    expect(lines.join("\n")).not.toContain("could not update");
  });

  it("does not disparage a neighbour this run is ALSO updating", async () => {
    // Reporting from inside the per-server read said `srv-b ... (not updated)`
    // one line before `✓ Updated srv-b`, and repeated it once per server.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping(
        { "srv-b": { command: "npx", args: "BAD" } },
        { "srv-a": { command: "npx", args: ["-y", "a"] } }
      )
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "srv-a", version: "1.0.0", clients: ["claude-desktop"] }),
        makeInstalledServer({ name: "srv-b", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn().mockImplementation((n: string) => Promise.resolve(makeServerEntry(n, "1.1.0"))),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);
    const text = lines.join("\n");
    // Assert on the EXACT rendering of an entry in the skipped report — the
    // earlier /srv-b.*not updated/ could never match, because the report puts
    // "not updated" BEFORE the names, so it passed with the bug live.
    expect(text).not.toContain("srv-b (claude-desktop)");
    expect(text).not.toMatch(/malformed entr(y was|ies were) skipped/);
    // positive control: srv-b really was processed by this run
    expect(text).toMatch(/Updated srv-b/);
  });

  it("reports an unrelated malformed neighbour ONCE, not once per server", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping(
        { "never-installed": { command: "npx", args: "BAD" } },
        { "srv-a": { command: "npx", args: ["-y", "a"] } }
      )
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "srv-a", version: "1.0.0", clients: ["claude-desktop"] }),
        makeInstalledServer({ name: "srv-c", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn().mockImplementation((n: string) => Promise.resolve(makeServerEntry(n, "1.1.0"))),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);
    const hits = lines.join("\n").split("never-installed").length - 1;
    expect(hits).toBe(1);
  });

  it("keeps a string env key named __proto__ instead of dropping it silently", async () => {
    // A plain object literal routes an own `__proto__` key to Object.prototype's
    // setter, dropping it — which would break this code's own promise to NAME
    // anything it cannot carry. Same class v0.36.0 closed in the pin hash.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "io.github.test/server-a": {
          command: "npx",
          args: "bad",
          env: JSON.parse('{"__proto__":"secret-value","OK":"keep"}'),
        },
      })
    );
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(Object.prototype.hasOwnProperty.call(call[2].env, "__proto__")).toBe(true);
    expect(call[2].env.OK).toBe("keep");
    // The real hazard is the prototype being REPLACED by the recovered value.
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
    expect(typeof ({} as Record<string, unknown>).toString).toBe("function");
  });

  it("names a non-object env instead of returning in silence", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({ "io.github.test/server-a": { command: "npx", args: "bad", env: ["A=1"] } })
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);
    expect(lines.join("\n")).toMatch(/env is not an object/);
    // and an array env is never written out as {"0": ...}
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[2].env?.["0"]).toBeUndefined();
  });

  it("still reports an unrelated malformed entry under --json (via stderr)", async () => {
    // --json has no field for it and stdout must stay parseable, so replacing
    // read()'s stderr default emitted it NOWHERE — LESS visible than before
    // this change, which is the class this whole PR exists to close.
    const errs: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
    try {
      const adapter = makeAdapter("claude-desktop");
      (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
        readDropping(
          { "never-installed": { command: "npx", args: "BAD" } },
          { "srv-a": { command: "npx", args: ["-y", "a"] } }
        )
      );
      const lines: string[] = [];
      const deps = makeDeps({
        getInstalledServers: vi.fn().mockResolvedValue([
          makeInstalledServer({ name: "srv-a", version: "1.0.0", clients: ["claude-desktop"] }),
        ]),
        getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
        getAdapter: vi.fn().mockReturnValue(adapter),
        output: (t: string) => lines.push(t),
      });

      await handleUpdate({ yes: true, json: true }, deps);

      expect(errs.join("")).toContain("never-installed");
      // stdout must remain parseable JSON
      expect(() => JSON.parse(lines.join(""))).not.toThrow();
    } finally {
      spy.mockRestore();
    }
  });

  it("names EVERY client holding the same malformed entry, not just one", async () => {
    // A name-only key dropped one of two facts, and which client got named
    // depended on iteration order.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping(
        { "never-installed": { command: "npx", args: "BAD" } },
        { "srv-a": { command: "npx", args: ["-y", "a"] } }
      )
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({
          name: "srv-a",
          version: "1.0.0",
          clients: ["claude-desktop", "cursor"],
        }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);
    const text = lines.join("\n");
    expect(text).toContain("never-installed (claude-desktop)");
    expect(text).toContain("never-installed (cursor)");
    expect(text).toMatch(/2 other malformed entries/);
  });

  it("reports a malformed copy in a client the server is NOT installed in", async () => {
    // `update` writes only to a server's own `originalClients`. A malformed
    // copy of that name in a DIFFERENT client is therefore never updated —
    // but a name-scoped suppression filter hid it anyway, silently, because
    // the name succeeded elsewhere. Suppression must be keyed by (client,
    // name), the same way the fact is.
    const cd = makeAdapter("claude-desktop");
    const cur = makeAdapter("cursor");
    (cd.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping(
        { "srv-b": { command: "npx", args: "BAD" } }, // malformed HERE
        { "srv-a": { command: "npx", args: ["-y", "a"] } }
      )
    );
    (cur.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({}, { "srv-b": { command: "npx", args: ["-y", "b"] } }) // valid THERE
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "srv-a", version: "1.0.0", clients: ["claude-desktop"] }),
        makeInstalledServer({ name: "srv-b", version: "1.0.0", clients: ["cursor"] }),
      ]),
      getServer: vi.fn().mockImplementation((n: string, v?: string) => {
        const entry = makeServerEntry(n, v ?? "1.1.0");
        entry.server.packages[0].identifier = n === "srv-a" ? "a" : "b";
        return Promise.resolve(entry);
      }),
      getAdapter: vi.fn((id: ClientId) => (id === "cursor" ? cur : cd)),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);

    const text = lines.join("\n");
    // srv-b WAS updated — in cursor. The claude-desktop copy was not, and is
    // the one that must still be named.
    expect(text).toMatch(/Updated srv-b/);
    expect(text).toContain("srv-b (claude-desktop)");
  });

  it("sanitizes config-supplied names and env keys before the terminal", async () => {
    // Both the neighbour notice and the dropped-env-key note render values a
    // config file controls. Every other new render site in this change has an
    // escape test; these two did not.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "ev\u001b]0;PWNED\u0007il": { command: "npx", args: "BAD" },
        "srv-a": { command: "npx", args: "BAD", env: { "K\u001b[31mEY": 7 } },
      })
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "srv-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);

    const text = lines.join("\n");
    expect(text).toContain("PWNED"); // the neighbour name is still shown...
    expect(text).toContain("KEY"); // ...and so is the dropped env key...
    expect(text).not.toContain("\u001b"); // ...but no escape survives
  });

  it("records a written pair only AFTER the write succeeds", async () => {
    // Recording before `await addServer` would let a FAILED write suppress the
    // report for an entry that is therefore STILL malformed on disk. Needs two
    // servers: each is the other's malformed "neighbour" in the same config,
    // and both writes fail.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "srv-a": { command: "npx", args: "BAD" },
        "srv-b": { command: "npx", args: "BAD" },
      })
    );
    (adapter.addServer as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("read-only"));
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "srv-a", version: "1.0.0", clients: ["claude-desktop"] }),
        makeInstalledServer({ name: "srv-b", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn().mockImplementation((n: string) => Promise.resolve(makeServerEntry(n, "1.1.0"))),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);

    // Neither write landed, so both entries are still malformed and both must
    // still be named. Recording the pair before the await would hide them.
    const text = lines.join("\n");
    expect(text).toContain("srv-a (claude-desktop)");
    expect(text).toContain("srv-b (claude-desktop)");
  });

  it("carries clientNotes into --json", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "io.github.test/server-a": { command: "npx", args: "bad", env: { A: "1", N: 2 } },
      })
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true, json: true }, deps);
    const parsed = JSON.parse(lines.join(""));
    expect(parsed[0].clientNotes.join(" ")).toContain("N");
  });

  it("re-states the warning for an unrelated malformed neighbour", async () => {
    // Replacing the default onSkip suppressed its stderr line, so `update`
    // went silent about every OTHER broken entry in the same config.
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping(
        { "unrelated-bad": { command: "npx", args: "bad" } },
        { "io.github.test/server-a": { command: "npx", args: ["-y", "@test/server"] } }
      )
    );
    const lines: string[] = [];
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
      output: (t: string) => lines.push(t),
    });

    await handleUpdate({ yes: true }, deps);
    expect(lines.join("\n")).toContain("unrelated-bad");
  });

  it("ignores a non-string-valued env on the raw entry (narrow parse)", async () => {
    const adapter = makeAdapter("claude-desktop");
    (adapter.read as ReturnType<typeof vi.fn>).mockImplementation(
      readDropping({
        "io.github.test/server-a": { command: "npx", args: "bad", env: { NESTED: { deep: 1 } } },
      })
    );
    const deps = makeDeps({
      getInstalledServers: vi.fn().mockResolvedValue([
        makeInstalledServer({ name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-desktop"] }),
      ]),
      getServer: vi.fn(async (name: string, version?: string) => makeServerEntry(name, version ?? "1.1.0")),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });

    await handleUpdate({ yes: true }, deps);
    const call = (adapter.addServer as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[2].env?.NESTED).toBeUndefined();
  });
});
