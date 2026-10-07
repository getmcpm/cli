import { describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { stringify } from "yaml";
import { packageCoordinate, bindLockedPackage, validateIdentifier } from "../../registry/package-coordinate.js";
import { resolveInstallEntry } from "../../commands/install.js";
import { handleUp, type UpDeps } from "../../commands/up.js";
import { verifyHandler } from "../../commands/verify.js";
import { handleUpdate, type UpdateDeps } from "../../commands/update.js";
import { wrapEntry, unwrapEntry, isWrapped, WRAP_CONFINE_HASH_FLAG } from "../../guard/wrap.js";
import { GeminiCliAdapter } from "../../config/adapters/gemini-cli.js";
import { CursorAdapter } from "../../config/adapters/cursor.js";
import type { ServerEntry } from "../../registry/types.js";

const trust = { score: 75, maxPossible: 80, level: "safe" as const, assessedAt: "2026-01-01T00:00:00Z" };
const score = { ...trust, breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 } };
const entry = (name = "alpha", identifier = "@test/alpha", version: string | undefined = "2.3.0"): ServerEntry => ({
  server: { name, version: "9.0.0", packages: [{ registryType: "npm", identifier, version, environmentVariables: [] }] },
});
const locked = (identifier = "@test/alpha") => ({ version: "9.0.0", registryType: "npm", identifier, packageVersion: "2.3.0", trust });

describe("version-bound package launches (#120)", () => {
  it("repeated up can downgrade and upgrade a generated guarded pinned launch while preserving the user tail", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-launch-relock-"));
    const adapter = new GeminiCliAdapter();
    const config = path.join(dir, "client.json");
    const stack = path.join(dir, "mcpm.yaml");
    const original = { command: "npx", args: ["-y", "@test/alpha@2.4.0", "/user/data"],
      disabled: true, cwd: "/user/data", env: { NODE_OPTIONS: "--require /user/loader.cjs", TOKEN: "keep" }, includeTools: ["read_file"],
    };
    try {
      await adapter.addServer(config, "alpha", wrapEntry("alpha", original, { mcpmBinary: "mcpm" }, { profileHash: "a".repeat(64), required: true }));
      await writeFile(stack, stringify({ version: "1", servers: { alpha: { version: "9.0.0", env: {
        NODE_OPTIONS: { default: "--require /user/new-loader.cjs" }, MCPM_DISABLE_CONFINE: { default: "1" },
      } } } }));
      const server = entry();
      const deps = { detectClients: async () => ["gemini-cli"], getAdapter: () => adapter, getPath: () => config, getServer: vi.fn(async () => server),
        scanTier1: () => [], checkScannerAvailable: async () => false, scanTier2: async () => [], computeTrustScore: () => score,
        runLock: vi.fn(), confirm: async () => true, promptEnvVar: vi.fn(), output: vi.fn(),
      } as unknown as UpDeps;
      for (const version of ["2.3.0", "2.5.0"]) {
        server.server.packages[0].version = version;
        await writeFile(path.join(dir, "mcpm-lock.yaml"), stringify({ lockfileVersion: 1, lockedAt: trust.assessedAt, servers: { alpha: { ...locked(), packageVersion: version } } }));
        await handleUp({ stackFile: stack, allowProcessEnv: false }, deps);
        const updated = (await adapter.read(config)).alpha;
        expect(updated.env?.NODE_OPTIONS).toBeUndefined();
        expect(updated.env?.MCPM_DISABLE_CONFINE).toBeUndefined();
        expect(unwrapEntry(updated)).toEqual({ ...original, args: ["-y", `@test/alpha@${version}`, "/user/data"],
          env: { ...original.env, NODE_OPTIONS: "--require /user/new-loader.cjs", MCPM_DISABLE_CONFINE: "1" },
        });
      }
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each(["2.3.0", undefined, "latest"])("migrates a legacy guarded entry with old package version %s while retaining protections", async (oldPackageVersion) => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-launch-legacy-"));
    const adapter = new GeminiCliAdapter();
    const config = path.join(dir, "client.json");
    const original = { command: "npx", args: ["-y", "@test/alpha", "/user/data"],
      env: { NODE_OPTIONS: "--require /user/loader.cjs", TOKEN: "mcpm:keychain:alpha:TOKEN" },
      disabled: true, cwd: "/user/data", includeTools: ["read_file"], timeout: 1234,
    };
    try {
      await adapter.addServer(config, "alpha", wrapEntry("alpha", original, { mcpmBinary: "/user/node", scriptPath: "/user/mcpm/dist/index.js" }, { profileHash: "a".repeat(64), required: true }));
      const deps = { getInstalledServers: async () => [{ name: "alpha", version: "9.0.0", clients: ["gemini-cli"], installedAt: trust.assessedAt }],
        getServer: async (_name, version) => {
          const publication = entry();
          publication.server.packages[0].version = oldPackageVersion;
          if (!version) { publication.server.version = "10.0.0"; publication.server.packages[0].version = "2.4.0"; }
          return publication;
        }, getAdapter: () => adapter, getConfigPath: () => config, addInstalledServer: vi.fn(), removeInstalledServer: vi.fn(),
        scanTier1: () => [], computeTrustScore: () => score, confirm: async () => true, output: vi.fn(),
      } as UpdateDeps;
      await handleUpdate({ yes: true }, deps);
      const updated = (await adapter.read(config)).alpha;
      expect(isWrapped(updated)).toBe(true);
      expect(updated.args).toContain(WRAP_CONFINE_HASH_FLAG);
      expect(updated.env?.NODE_OPTIONS).toBeUndefined();
      expect(unwrapEntry(updated)).toEqual({ ...original, args: ["-y", "@test/alpha@2.4.0", "/user/data"] });
      expect(deps.addInstalledServer).toHaveBeenCalledOnce();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.skipIf(spawnSync("uvx", ["--version"]).status !== 0 || spawnSync("python3", ["--version"]).status !== 0)("the rendered uvx coordinate executes the exact synthetic wheel; trailing launcher flags stay server args", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-launch-uvx-"));
    try {
      const build = spawnSync("python3", ["-c", `
import csv, io, pathlib, sys, zipfile
root=pathlib.Path(sys.argv[1])
for version in ['1.2.3','1.2.3+unlocked','1.0.post1','1.0.post1+unlocked','1.0+abc.def']:
 dist=f'mcpm_version_fixture-{version}.dist-info'
 files={'mcpm_version_fixture.py':'import importlib.metadata,json,sys\\ndef main():\\n print(json.dumps({"version":importlib.metadata.version("mcpm-version-fixture"),"args":sys.argv[1:]}))\\n',
 f'{dist}/METADATA':f'Metadata-Version: 2.1\\nName: mcpm-version-fixture\\nVersion: {version}\\n',
 f'{dist}/WHEEL':'Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n',
 f'{dist}/entry_points.txt':'[console_scripts]\\nmcpm-version-fixture = mcpm_version_fixture:main\\n'}
 rows=io.StringIO();csv.writer(rows).writerows((name,'','') for name in [*files,f'{dist}/RECORD']);files[f'{dist}/RECORD']=rows.getvalue()
 with zipfile.ZipFile(root/f'mcpm_version_fixture-{version}-py3-none-any.whl','w') as wheel:
  for name,data in files.items():wheel.writestr(name,data)
`, dir], { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      for (const [declared, actual] of [["1.2.3", "1.2.3"], ["v1.2.3", "1.2.3"], ["1.0-1", "1.0.post1"], ["1.0+abc_def", "1.0+abc.def"]]) {
        const publication = entry();
        publication.server.packages = [{ registryType: "pypi", identifier: "mcpm-version-fixture", version: declared, runtimeArguments: ["--from", "evil", "--with", "evil"], environmentVariables: [] }];
        const launch = resolveInstallEntry(publication, "gemini-cli");
        const result = spawnSync(launch.command!, ["--no-config", "--offline", "--no-index", "--no-python-downloads", "--python", "python3", "--find-links", dir, ...launch.args!],
          { encoding: "utf8", env: { ...process.env, UV_CACHE_DIR: path.join(dir, "cache"), UV_TOOL_DIR: path.join(dir, "tools") } });
        expect(result.status, result.stderr).toBe(0);
        expect(JSON.parse(result.stdout)).toEqual({ version: actual, args: ["--from", "evil", "--with", "evil"] });
      }
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each(["registry.example:5000/team/server:1.2.3", `registry.example:5000/team/server@sha256:${"a".repeat(64)}`])("accepts an explicit OCI coordinate at a registry port: %s", (identifier) => {
    const server = entry();
    server.server.packages[0] = { registryType: "oci", identifier, version: identifier.includes("@") ? "descriptive-release" : "1.2.3", environmentVariables: [] };
    expect(resolveInstallEntry(server, "gemini-cli").args).toEqual(["run", "--rm", "-i", identifier]);
  });

  it.each(["npm", "pypi", "oci"])("rejects control characters in %s identifiers and versions", (registryType) => {
    const identifier = registryType === "oci" ? "example/server:1.2.3" : "test-server";
    expect(() => packageCoordinate({ registryType, identifier: identifier + "\n", version: "1.2.3" })).toThrow();
    expect(() => packageCoordinate({ registryType, identifier, version: "1.2.3\n" })).toThrow();
  });

  it.each(["custom", "__proto__", "constructor", "toString"])("refuses unsupported registry type %s without calling inherited object methods", (registryType) => {
    expect(() => validateIdentifier("anything", registryType)).toThrow(/Unsupported registry type/);
  });

  it("selects the complete locked package tuple among same-package version alternatives", () => {
    const server = entry();
    const exact = { ...server.server.packages[0], runtimeArguments: ["--locked"] };
    server.server.packages = [{ ...exact, version: "2.2.0", runtimeArguments: ["--old"] }, exact];
    const coordinate = bindLockedPackage(server, locked(), "alpha");
    expect(resolveInstallEntry(server, "cursor", coordinate).args).toEqual(["-y", "@test/alpha@2.3.0", "--locked"]);
    server.server.packages.push({ ...exact, runtimeArguments: ["--ambiguous"] });
    expect(() => bindLockedPackage(server, locked(), "alpha")).toThrow(/coordinate/);
  });

  it("pins the actual npm package version, which can differ from the MCP publication", () => {
    expect(resolveInstallEntry(entry(), "gemini-cli").args).toEqual(["-y", "@test/alpha@2.3.0"]);
  });

  it.each([undefined, "latest", "^2.0.0", "2.3.0 --package=evil", "npm:evil@2.3.0"])("refuses non-exact package version %s", (version) => {
    const server = entry();
    server.server.packages[0].version = version;
    expect(() => resolveInstallEntry(server, "gemini-cli")).toThrow(/version/i);
  });

  it("pins PyPI requirements and rejects OCI latest or contradictory tags", () => {
    const server = entry();
    server.server.packages[0] = { registryType: "pypi", identifier: "test-server", version: "1.2.3rc1", environmentVariables: [] };
    expect(resolveInstallEntry(server, "gemini-cli").args).toEqual(["test-server===1.2.3rc1"]);
    server.server.packages[0] = { registryType: "oci", identifier: "ghcr.io/test/server:latest", version: "2.3.0", environmentVariables: [] };
    expect(() => resolveInstallEntry(server, "gemini-cli")).toThrow();
    server.server.packages[0].identifier = "ghcr.io/test/server:1.0.0";
    expect(() => resolveInstallEntry(server, "gemini-cli")).toThrow();
  });

  it.each([false, true])("rejects live package drift before any batch backup, config or secret write (dry=%s)", async (dryRun) => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-launch-binding-"));
    const adapter = new GeminiCliAdapter();
    const config = path.join(dir, "client.json");
    const stack = path.join(dir, "mcpm.yaml");
    try {
      await writeFile(config, '{"mcpServers":{"existing":{"command":"keep"}}}');
      await writeFile(config + ".bak", "keep backup");
      const original = await readFile(config, "utf8");
      await writeFile(stack, stringify({ version: "1", servers: { alpha: { version: "9.0.0" }, beta: { version: "9.0.0", env: { TOKEN: { required: true, secret: true } } } } }));
      await writeFile(path.join(dir, "mcpm-lock.yaml"), stringify({ lockfileVersion: 1, lockedAt: trust.assessedAt, servers: { alpha: locked(), beta: locked("@test/beta") } }));
      const prompt = vi.fn().mockResolvedValue("synthetic-secret");
      const store = vi.fn();
      const deps = {
        detectClients: async () => ["gemini-cli"], getAdapter: () => adapter, getPath: () => config,
        getServer: vi.fn(async (name) => entry(name, name === "alpha" ? "@test/alpha" : "@attacker/beta")),
        scanTier1: () => [], checkScannerAvailable: async () => false, scanTier2: async () => [], computeTrustScore: () => score,
        runLock: vi.fn(), confirm: async () => true, promptEnvVar: prompt, setSecrets: store, output: vi.fn(),
      } as unknown as UpDeps;
      await expect(handleUp({ stackFile: stack, dryRun, secrets: "keychain" }, deps)).rejects.toThrow(/package|coordinate|identifier/i);
      expect(await readFile(config, "utf8")).toBe(original);
      expect(await readFile(config + ".bak", "utf8")).toBe("keep backup");
      expect(prompt).not.toHaveBeenCalled();
      expect(store).not.toHaveBeenCalled();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it.each([false, true])("rejects reserved stack env before any client/backup/secret write (dry=%s)", async (dryRun) => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-launch-reserved-env-"));
    const stack = path.join(dir, "mcpm.yaml");
    const adapters = { "gemini-cli": new GeminiCliAdapter(), cursor: new CursorAdapter() };
    const configs = { "gemini-cli": path.join(dir, "gemini.json"), cursor: path.join(dir, "cursor.json") };
    const original = { command: "npx", args: ["-y", "@test/alpha"] };
    try {
      for (const client of ["gemini-cli", "cursor"] as const) {
        await adapters[client].addServer(configs[client], "alpha", client === "cursor" ? wrapEntry("alpha", original, { mcpmBinary: "mcpm" }) : original);
        await writeFile(configs[client] + ".bak", "keep backup");
      }
      const before = await Promise.all(Object.values(configs).map((file) => readFile(file, "utf8")));
      await writeFile(stack, stringify({ version: "1", servers: { alpha: { version: "9.0.0", env: { MCPM_GUARD_CHILD_ENV: { default: "{}", secret: true } } } } }));
      await writeFile(path.join(dir, "mcpm-lock.yaml"), stringify({ lockfileVersion: 1, lockedAt: trust.assessedAt, servers: { alpha: locked() } }));
      const setSecrets = vi.fn();
      const deps = { detectClients: async () => ["gemini-cli", "cursor"], getAdapter: (id) => adapters[id], getPath: (id) => configs[id], getServer: async () => entry(),
        scanTier1: () => [], checkScannerAvailable: async () => false, scanTier2: async () => [], computeTrustScore: () => score,
        runLock: vi.fn(), confirm: async () => true, promptEnvVar: vi.fn(), setSecrets, output: vi.fn(),
      } as unknown as UpDeps;
      await expect(handleUp({ stackFile: stack, dryRun, secrets: "keychain", allowProcessEnv: false, allowEnvFile: false }, deps)).rejects.toThrow(/reserved/);
      expect(await Promise.all(Object.values(configs).map((file) => readFile(file, "utf8")))).toEqual(before);
      for (const file of Object.values(configs)) expect(await readFile(file + ".bak", "utf8")).toBe("keep backup");
      expect(setSecrets).not.toHaveBeenCalled();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it("binds Cursor to the locked package rather than the registry HTTP shortcut", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-launch-cursor-"));
    const adapter = new CursorAdapter();
    const config = path.join(dir, "client.json");
    const stack = path.join(dir, "mcpm.yaml");
    try {
      await writeFile(stack, stringify({ version: "1", servers: { alpha: { version: "9.0.0" } } }));
      await writeFile(path.join(dir, "mcpm-lock.yaml"), stringify({ lockfileVersion: 1, lockedAt: trust.assessedAt, servers: { alpha: locked() } }));
      const server = entry();
      server.server.remotes = [{ type: "streamable-http", url: "https://example.com/mcp", headers: [] }];
      const deps = {
        detectClients: async () => ["cursor"], getAdapter: () => adapter, getPath: () => config, getServer: vi.fn().mockResolvedValue(server),
        scanTier1: () => [], checkScannerAvailable: async () => false, scanTier2: async () => [], computeTrustScore: () => score,
        runLock: vi.fn(), confirm: async () => true, promptEnvVar: vi.fn(), output: vi.fn(),
      } as unknown as UpDeps;
      await handleUp({ stackFile: stack }, deps);
      expect((await adapter.read(config)).alpha).toEqual({ command: "npx", args: ["-y", "@test/alpha@2.3.0"] });
      expect(deps.getServer).toHaveBeenCalledOnce();
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it("verify refuses conflicting package/integrity/provenance coordinates before checking either record", async () => {
    const fetch = vi.fn(async () => ({ npmVersion: "2.3.0", integrity: "sha512-synthetic" }));
    const lock = { lockfileVersion: 1 as const, lockedAt: trust.assessedAt, servers: { alpha: {
      ...locked(), npmIntegrity: { npmVersion: "2.3.0", integrity: "sha512-synthetic" },
      provenance: { npmVersion: "4.0.0", status: "unsigned" as const, mode: "registry-record" as const },
    } } };
    expect(await verifyHandler({ parseLock: async () => lock, parseStack: async () => null,
      fetchNpmIntegrity: fetch, fetchNpmProvenance: vi.fn(), output: vi.fn(),
    })).toBe(1);
    expect(fetch).not.toHaveBeenCalled();
  });
});
