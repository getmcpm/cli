/**
 * H9 Part A — `mcpm up` deny-by-default for URL/HTTP-transport servers.
 *
 * A stack-file `url:` server runs UNGUARDED (the guard relay only wraps stdio).
 * H9 refuses it unless the user opts in via `--allow-unguarded` or
 * `policy.allowUrlServers: true`, records consent, warns once, and re-warns
 * only when the consented set GAINS a server. The MCP-surface kill-switch
 * (`allowUrlServers === false`) always wins.
 */

import { describe, it, expect, vi } from "vitest";
import { handleUp } from "../../commands/up.js";
import type { UpDeps, UpServerStatus } from "../../commands/up.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

function makeAdapter(servers: Record<string, McpServerEntry> = {}) {
  return {
    clientId: "cursor" as ClientId,
    read: vi.fn().mockResolvedValue({ ...servers }),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
    setServerDisabled: vi.fn().mockResolvedValue(undefined),
  };
}

function makeDeps(overrides: Partial<UpDeps> = {}): UpDeps {
  const adapter = makeAdapter();
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["cursor"]),
    getAdapter: vi.fn().mockReturnValue(adapter),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    getServer: vi.fn(),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn(),
    runLock: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    promptEnvVar: vi.fn().mockResolvedValue("v"),
    output: vi.fn(),
    ...overrides,
  };
}

const urlStack = (url: string, policy = "") => `
version: "1"
${policy}servers:
  url-mcp:
    url: "${url}"
`;

const urlLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  url-mcp:
    url: "https://api.example.com/mcp"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;

const stdioStack = `
version: "1"
servers:
  url-mcp:
    url: "https://api.example.com/mcp"
  fs-mcp:
    version: "^1.0.0"
`;

async function writeStackAndLock(stackYaml: string, lockYaml: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-unguarded-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stackYaml, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lockYaml, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

function records(deps: UpDeps): Array<{ name: string; status: UpServerStatus }> {
  return (deps.recordResult as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]);
}

describe("handleUp — H9 url-server deny-by-default", () => {
  it("1. DENIES a url server by default (status blocked, message names UNGUARDED, no addServer)", async () => {
    const stackPath = await writeStackAndLock(urlStack("https://api.example.com/mcp"), urlLock);
    const deps = makeDeps({ recordResult: vi.fn() });

    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(/could not be installed/);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).not.toHaveBeenCalled();
    const rec = records(deps).find((r) => r.name === "url-mcp");
    expect(rec?.status).toBe("blocked");
    const out = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(out).toMatch(/UNGUARDED/);
  });

  it("2. --allow-unguarded installs + records + warns once", async () => {
    const stackPath = await writeStackAndLock(urlStack("https://api.example.com/mcp"), urlLock);
    const recordConsent = vi.fn(async () => {});
    const deps = makeDeps({
      recordResult: vi.fn(),
      readUnguardedConsent: async () => [],
      recordUnguardedConsent: recordConsent,
    });

    await handleUp({ stackFile: stackPath, allowUnguarded: true }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledWith(
      "/mock/config.json",
      "url-mcp",
      { url: "https://api.example.com/mcp" },
      { force: true },
    );
    expect(records(deps).find((r) => r.name === "url-mcp")?.status).toBe("installed");
    expect(recordConsent).toHaveBeenCalledWith(["url-mcp"]);
    const out = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect((out.match(/run WITHOUT runtime inspection/gi) ?? []).length).toBeGreaterThanOrEqual(1);
    expect(out).toMatch(/does NOT add protection/);
  });

  it("3. warn suppressed on a second up when the consented set is unchanged", async () => {
    const stackPath = await writeStackAndLock(urlStack("https://api.example.com/mcp"), urlLock);
    const deps = makeDeps({
      recordResult: vi.fn(),
      // store already lists the server → consented, no new warning.
      readUnguardedConsent: async () => ["url-mcp"],
      recordUnguardedConsent: vi.fn(async () => {}),
    });

    await handleUp({ stackFile: stackPath, allowUnguarded: true }, deps);

    const out = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    // Full multi-line warning must NOT fire; a quiet one-liner is allowed.
    expect(out).not.toMatch(/does NOT add protection/);
    expect(records(deps).find((r) => r.name === "url-mcp")?.status).toBe("installed");
  });

  it("4. dry-run + --allow-unguarded: no write, no consent persisted, no warning", async () => {
    const stackPath = await writeStackAndLock(urlStack("https://api.example.com/mcp"), urlLock);
    const recordConsent = vi.fn(async () => {});
    // Inject an explicit adapter so we can assert addServer was never called even
    // though dry-run never invokes getAdapter (no backup, no write).
    const adapter = makeAdapter();
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(adapter),
      recordResult: vi.fn(),
      readUnguardedConsent: async () => [],
      recordUnguardedConsent: recordConsent,
    });

    // Dry-run is a read-only preview: the deny-gate is skipped (would-install),
    // but nothing is written, no consent is persisted, and the warn-once UNGUARDED
    // warning never fires (up.ts gates both behind `!options.dryRun`).
    await handleUp({ stackFile: stackPath, allowUnguarded: true, dryRun: true }, deps);

    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(recordConsent).not.toHaveBeenCalled();
    const out = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(out).not.toMatch(/does NOT add protection/);
    expect(records(deps).find((r) => r.name === "url-mcp")?.status).toBe("skipped");
  });

  it("5. policy.allowUrlServers grants consent without the flag", async () => {
    const stackPath = await writeStackAndLock(
      urlStack("https://api.example.com/mcp", "policy:\n  allowUrlServers: true\n"),
      urlLock,
    );
    const deps = makeDeps({
      recordResult: vi.fn(),
      readUnguardedConsent: async () => [],
      recordUnguardedConsent: vi.fn(async () => {}),
    });

    await handleUp({ stackFile: stackPath }, deps);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalled();
    expect(records(deps).find((r) => r.name === "url-mcp")?.status).toBe("installed");
  });

  it("6. MCP-surface allowUrlServers:false overrides allowUnguarded:true (untrusted caller can't opt in)", async () => {
    const stackPath = await writeStackAndLock(urlStack("https://api.example.com/mcp"), urlLock);
    const deps = makeDeps({ recordResult: vi.fn() });

    await expect(
      handleUp({ stackFile: stackPath, allowUnguarded: true, allowUrlServers: false }, deps),
    ).rejects.toThrow(/could not be installed/);

    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).not.toHaveBeenCalled();
    expect(records(deps).find((r) => r.name === "url-mcp")?.status).toBe("blocked");
  });

  it("7. a normal registry (stdio) server in the same stack still installs unaffected", async () => {
    const fsLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  fs-mcp:
    version: "1.2.0"
    registryType: npm
    identifier: "@test/fs-mcp"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
  url-mcp:
    url: "https://api.example.com/mcp"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(stdioStack, fsLock);
    const deps = makeDeps({
      recordResult: vi.fn(),
      getServer: vi.fn().mockResolvedValue({
        server: {
          name: "fs-mcp",
          version: "1.2.0",
          packages: [{ registryType: "npm", identifier: "@test/fs-mcp", environmentVariables: [] }],
        },
      }),
      computeTrustScore: vi.fn().mockReturnValue({
        score: 75,
        maxPossible: 80,
        level: "safe",
        breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
      }),
    });

    // url-mcp denied → throws, but fs-mcp must still have installed.
    await expect(handleUp({ stackFile: stackPath }, deps)).rejects.toThrow(/could not be installed/);
    expect(records(deps).find((r) => r.name === "fs-mcp")?.status).toBe("installed");
    expect(records(deps).find((r) => r.name === "url-mcp")?.status).toBe("blocked");
  });
});
