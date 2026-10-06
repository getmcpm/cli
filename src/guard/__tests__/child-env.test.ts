import { afterEach, beforeAll, describe, expect, test } from "vitest";
import { execSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { stringify } from "yaml";
import { CHILD_ENV_FIELD, isChildOnlyEnvKey, readChildEnv, restoreChildEnv } from "../child-env.js";
import { wrapEntry, unwrapEntry, rewrapEntry } from "../wrap.js";
import { hashConfineProfile, type ConfineProfile } from "../confine/profile.js";
import { fileSha } from "../store-integrity.js";
import { setSecret, toPlaceholder } from "../../store/keychain.js";
import { _resetCachedStorePath } from "../../store/index.js";
import type { McpServerEntry } from "../../config/adapters/index.js";

const bin = path.resolve("dist/index.js");
const ctx = { mcpmBinary: process.execPath, scriptPath: bin };
const homes: string[] = [];
const home = () => {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "mcpm-child-env-")));
  homes.push(dir);
  return dir;
};
const env = (dir: string) => ({ PATH: process.env.PATH, HOME: dir, USERPROFILE: dir, MCPM_DISABLE_OS_KEYCHAIN: "1" });
const launch = (entry: McpServerEntry, dir: string) => spawnSync(entry.command!, entry.args!, {
  env: { ...env(dir), ...entry.env }, input: "", encoding: "utf8", timeout: 15_000,
});
beforeAll(() => {
  if (!existsSync(bin)) execSync("npm run build", { timeout: 180_000, stdio: "ignore" });
}, 200_000);
afterEach(() => { for (const dir of homes.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function fixture(dir: string) {
  const secret = path.join(dir, "synthetic-secret");
  const hook = path.join(dir, "hook.mjs");
  const log = path.join(dir, "startup.jsonl");
  const server = path.join(dir, "server.cjs");
  writeFileSync(secret, "synthetic-only");
  writeFileSync(hook, `import{readFileSync,appendFileSync}from'node:fs';let value;try{value=readFileSync(${JSON.stringify(secret)},'utf8')}catch(e){value=e.code}appendFileSync(${JSON.stringify(log)},JSON.stringify({script:process.argv[1],value})+'\\n');`);
  writeFileSync(server, "process.exit(0)");
  return { secret, hook, log, server };
}
function enroll(dir: string, denied: string, required = true): { profileHash: string; required: boolean } {
  const profile: ConfineProfile = { tier: "standard", require_confine: required,
    read_deny: [denied], write_allow: [dir], net: "all", scratch_dir: path.join(dir, "scratch"),
    captured_at: "2026-10-04T00:00:00.000Z" };
  const body = stringify({ format_version: 1, servers: { synthetic: profile } });
  mkdirSync(path.join(dir, ".mcpm"), { recursive: true });
  writeFileSync(path.join(dir, ".mcpm/guard-confine.yaml"), body);
  writeFileSync(path.join(dir, ".mcpm/guard-confine.yaml.integrity"), fileSha(body));
  return { profileHash: hashConfineProfile(profile), required };
}

describe("declared child-only environment", () => {
  test.each(["NODE_OPTIONS", "node_options", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "OPENSSL_CONF", "MCPM_DISABLE_CONFINE"])("recognizes %s", (key) => {
    expect(isChildOnlyEnvKey(key)).toBe(true);
  });
  test("preserves original settings, placeholders, hash and legacy unwrap", () => {
    const original = { command: "node", args: ["server.js"], env: {
      NODE_OPTIONS: toPlaceholder("synthetic", "OPTIONS"), LD_PRELOAD: "lib.so", FOO: "bar",
    } };
    const wrapped = wrapEntry("synthetic", original, ctx);
    expect(wrapped.env).not.toHaveProperty("NODE_OPTIONS");
    expect(wrapped.env).not.toHaveProperty("LD_PRELOAD");
    expect(wrapped.env?.[CHILD_ENV_FIELD]).toContain(toPlaceholder("synthetic", "OPTIONS"));
    expect(unwrapEntry(wrapped)).toEqual(original);
    expect(unwrapEntry({ ...wrapped, env: original.env })).toEqual(original);
    expect(wrapped.args).toContain("FOO,LD_PRELOAD,NODE_OPTIONS");
    expect(unwrapEntry({ ...wrapped, env: { FOO: "bar" } })).toBeNull();
    expect(unwrapEntry({ ...wrapped, env: undefined })).toBeNull();
  });
  test.each(["MCPM_GUARD_CHILD_ENV", "mcpm_guard_child_env"])("refuses reserved field collision %s", (key) => {
    expect(() => wrapEntry("synthetic", { command: "node", env: { [key]: "x" } }, ctx)).toThrow("reserved");
  });
  test.each(["{", "null", "[]", '{"NODE_OPTIONS":3}', '{"NODE_OPTIONS":"x","HOME":"other"}', '{}'])("malformed transport %s refuses to unwrap and spawn", (payload) => {
    const dir = home();
    const f = fixture(dir);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { NODE_OPTIONS: `--import=${f.hook}` } }, ctx);
    wrapped.env![CHILD_ENV_FIELD] = payload;
    expect(unwrapEntry(wrapped)).toBeNull();
    const result = launch(wrapped, dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("CHILD-ENV-ERROR");
    expect(existsSync(f.log)).toBe(false);
  });
  test("ambient home/path stays in the guard while declared overrides are child-only", () => {
    const dir = home(); const f = fixture(dir); const output = path.join(dir, "env.json");
    writeFileSync(f.server, `require('node:fs').writeFileSync(${JSON.stringify(output)},JSON.stringify({home:process.env.HOME,path:process.env.PATH}));`);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { HOME: "/synthetic/child-home", PATH: "/synthetic/child-path" } }, ctx);
    expect(wrapped.env).not.toHaveProperty("HOME");
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(output, "utf8"))).toEqual({ home: "/synthetic/child-home", path: "/synthetic/child-path" });
  });
  test("Windows child overrides replace baseline aliases while POSIX keeps distinct names", () => {
    const baseline = { PATH: "ambient", HOME: "ambient-home" };
    const declared = { path: "child", home: "child-home" };
    expect(restoreChildEnv(baseline, declared, "win32")).toEqual(declared);
    expect(restoreChildEnv(baseline, declared, "linux")).toEqual({ ...baseline, ...declared });
    expect(baseline).toEqual({ PATH: "ambient", HOME: "ambient-home" });
  });
  test("rejects direct and transported copies of a setting", () => {
    expect(() => readChildEnv({ NODE_OPTIONS: "x", [CHILD_ENV_FIELD]: '{"NODE_OPTIONS":"y"}' }, ["NODE_OPTIONS"])).toThrow();
  });
  test("actual IDE launch executes NODE_OPTIONS only in server startup and preserves ordinary child env", () => {
    const dir = home();
    const f = fixture(dir);
    const childLog = path.join(dir, "child.json");
    writeFileSync(f.server, `require('node:fs').writeFileSync(${JSON.stringify(childLog)},JSON.stringify({plain:process.env.PLAIN,control:process.env.MCPM_DISABLE_CONFINE,carrier:process.env.${CHILD_ENV_FIELD}}));`);
    const original = { command: process.execPath, args: [f.server], env: { NODE_OPTIONS: `--import=${f.hook}`, PLAIN: "kept", MCPM_DISABLE_CONFINE: "1" } };
    const wrapped = wrapEntry("synthetic", original, ctx);
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.log, "utf8").trim().split("\n").map((line) => JSON.parse(line))).toEqual([{ script: f.server, value: "synthetic-only" }]);
    expect(JSON.parse(readFileSync(childLog, "utf8"))).toEqual({ plain: "kept", control: "1" });
  });
  test("Node coverage output belongs only to the server process", () => {
    const dir = home(); const f = fixture(dir); const coverage = path.join(dir, "coverage");
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { NODE_V8_COVERAGE: coverage } }, ctx);
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    const files = readdirSync(coverage).filter((name) => name.endsWith(".json"));
    expect(files).toHaveLength(1);
    const urls = JSON.parse(readFileSync(path.join(coverage, files[0]), "utf8")).result.map((script: { url: string }) => script.url);
    expect(urls).toContain(pathToFileURL(f.server).href);
    expect(urls).not.toContain(pathToFileURL(bin).href);
  });
  test("NODE_OPTIONS --require executes only in the actual server", () => {
    const dir = home(); const f = fixture(dir); const hook = path.join(dir, "hook.cjs");
    writeFileSync(hook, `require('node:fs').appendFileSync(${JSON.stringify(f.log)},process.argv[1]+'\\n');`);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { NODE_OPTIONS: `--require=${hook}` } }, ctx);
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.log, "utf8").trim()).toBe(f.server);
  });
  test("unconfined child retains declared DYLD setting", () => {
    const dir = home(); const f = fixture(dir); const output = path.join(dir, "dyld.json");
    writeFileSync(f.server, `require('node:fs').writeFileSync(${JSON.stringify(output)},JSON.stringify(process.env.DYLD_LIBRARY_PATH));`);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { DYLD_LIBRARY_PATH: "/tmp/synthetic" } }, ctx);
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(output, "utf8"))).toBe("/tmp/synthetic");
  });
  test("ambient loader collision refuses the child after ambient loader can run in guard", () => {
    const dir = home(); const f = fixture(dir);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { NODE_OPTIONS: `--import=${f.hook}` } }, ctx);
    const result = launch({ ...wrapped, env: { ...wrapped.env, NODE_OPTIONS: `--import=${f.hook}` } }, dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("CHILD-ENV-ERROR");
    expect(JSON.parse(readFileSync(f.log, "utf8").trim()).script).toBe(bin);
  });
  test("keychain loader placeholder resolves only into the actual child", async () => {
    const dir = home(); const f = fixture(dir);
    const oldHome = process.env.HOME;
    process.env.HOME = dir; _resetCachedStorePath();
    try { await setSecret("synthetic", "OPTIONS", `--import=${f.hook}`); }
    finally { process.env.HOME = oldHome; _resetCachedStorePath(); }
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { NODE_OPTIONS: toPlaceholder("synthetic", "OPTIONS") } }, ctx);
    expect(wrapped.env![CHILD_ENV_FIELD]).not.toContain(f.hook);
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(f.log, "utf8").trim())).toEqual({ script: f.server, value: "synthetic-only" });
  });
  test.runIf(process.platform === "darwin")("confined import cannot read the synthetic secret; declared mcpm control cannot disable confine", ({ skip }) => {
    const probe = spawnSync("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)", "/usr/bin/true"], { encoding: "utf8" });
    if (probe.status !== 0) skip(); // tool sandboxes may forbid sandbox_apply
    const dir = home(); const f = fixture(dir);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { NODE_OPTIONS: `--import=${f.hook}`, MCPM_DISABLE_CONFINE: "1", HOME: path.join(dir, "server-home"), PATH: "/synthetic/server/path" } }, ctx, enroll(dir, f.secret, false));
    const result = launch(wrapped, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(f.log, "utf8").trim())).toEqual({ script: f.server, value: "EPERM" });
    expect(readFileSync(path.join(dir, ".mcpm/guard-events.jsonl"), "utf8")).toContain("confine-applied");
  });
  test.runIf(process.platform === "darwin")("updated launcher keeps operational confinement and child-only startup controls", ({ skip }) => {
    const probe = spawnSync("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)", "/usr/bin/true"], { encoding: "utf8" });
    if (probe.status !== 0) skip();
    const dir = home(); const f = fixture(dir);
    const original = { command: process.execPath, args: ["-e", "process.exit(0)"], env: {
      NODE_OPTIONS: `--import=${f.hook}`, MCPM_DISABLE_CONFINE: "1",
    } };
    const wrapped = wrapEntry("synthetic", original, ctx, enroll(dir, f.secret, true));
    const updated = rewrapEntry(wrapped, { ...original, args: [f.server] });
    const result = launch(updated, dir);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(f.log, "utf8").trim())).toEqual({ script: f.server, value: "EPERM" });
    expect(readFileSync(path.join(dir, ".mcpm/guard-events.jsonl"), "utf8")).toContain("confine-applied");
  });
  test.runIf(process.platform === "darwin")("confine refuses DYLD settings that native sandbox-exec strips", ({ skip }) => {
    const probe = spawnSync("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)", process.execPath, "-e", "console.log(process.env.DYLD_LIBRARY_PATH)"], { env: { PATH: process.env.PATH, DYLD_LIBRARY_PATH: "/tmp/synthetic" }, encoding: "utf8" });
    if (probe.status !== 0) skip();
    expect(probe.stdout.trim()).toBe("undefined");
    const dir = home(); const f = fixture(dir);
    const wrapped = wrapEntry("synthetic", { command: process.execPath, args: [f.server], env: { DYLD_LIBRARY_PATH: "/tmp/synthetic" } }, ctx, enroll(dir, f.secret));
    const result = launch(wrapped, dir);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cannot preserve declared DYLD_*");
  });
});
