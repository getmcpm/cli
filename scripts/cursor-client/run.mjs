#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const serverName = "io.github.getmcpm/native-fixture";
const packageName = "@mcpm/native-fixture";
const positional = process.argv.slice(2);
const cursorInput = process.env.CURSOR_AGENT ?? positional.shift();
const cursor = cursorInput?.includes(path.sep) ? path.resolve(cursorInput) : cursorInput;
assert.notEqual(process.platform, "win32", "This fixture harness requires a POSIX host or Linux container");
if (!cursor) throw new Error("Usage: CURSOR_AGENT=/path/to/cursor-agent node scripts/cursor-client/run.mjs [EVIDENCE_DIR]");

const evidence = path.resolve(process.env.CURSOR_EVIDENCE ?? positional[0] ?? await mkdtemp(path.join(os.tmpdir(), "mcpm-cursor-")));
const home = path.join(evidence, "home");
const bin = path.join(evidence, "bin");
const work = path.join(evidence, "work");
const configPath = path.join(home, ".cursor", "mcp.json");
const cli = path.join(root, "dist", "index.js");
const fixtureRegistry = path.join(root, "scripts", "native-client", "fixture-registry.mjs");
const peer = path.join(root, "scripts", "native-client", "peer.mjs");
assert.ok(await readFile(cli, "utf8"), `missing built CLI: ${cli}`);
await mkdir(evidence, { recursive: true, mode: 0o700 });
assert.deepEqual(await readdir(evidence), [], "evidence directory must be empty");
await mkdir(home, { mode: 0o700 });
await mkdir(path.dirname(configPath));
await mkdir(bin, { recursive: true });
await mkdir(work, { recursive: true });

const npx = path.join(bin, "npx");
await writeFile(npx, `#!/usr/bin/env node
import { spawn } from "node:child_process";
const [flag, spec, ...args] = process.argv.slice(2);
if (flag !== "-y" || !/^@mcpm\\/native-fixture@(1|2)\\.0\\.0$/.test(spec)) {
  console.error("cursor-fixture npx shim: unexpected launch", process.argv.slice(2));
  process.exit(64);
}
const version = spec.split("@").at(-1);
process.env.MCPM_NATIVE_WORK ??= ${JSON.stringify(work)};
const child = spawn(process.execPath, [${JSON.stringify(peer)}, version, ...args], { stdio: "inherit", env: process.env });
child.on("error", error => { console.error(error); process.exit(1); });
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
`);
await chmod(npx, 0o755);

const baseEnv = {
  HOME: home,
  AGENT_CLI_CREDENTIAL_STORE: "file",
  PATH: `${bin}:${process.env.PATH ?? ""}`,
  MCPM_NATIVE_WORK: work,
  MCPM_DISABLE_OS_KEYCHAIN: "1",
  NO_OPEN_BROWSER: "1",
  DISABLE_AUTOUPDATER: "1",
};

function run(file, args, extraEnv = {}) {
  const result = spawnSync(file, args, {
    cwd: work,
    env: { ...baseEnv, ...extraEnv },
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  return { ...result, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function mcpm(args, version = "1.0.0") {
  const result = run(process.execPath, ["--import", fixtureRegistry, cli, ...args], {
    MCPM_NATIVE_REGISTRY_DOUBLE: "1",
    MCPM_NATIVE_VERSION: version,
  });
  assert.equal(result.status, 0, `mcpm ${args.join(" ")} failed:\n${result.stderr}\n${result.stdout}`);
  return result;
}

function readConfig() {
  return JSON.parse(requireText(configPath));
}

function requireText(file) {
  return readFileSync(file, "utf8");
}

function wireLines() {
  if (!existsSync(path.join(work, "wire.jsonl"))) return [];
  const text = requireText(path.join(work, "wire.jsonl"));
  return text.trim() ? text.trim().split("\n").map(JSON.parse) : [];
}

function assertDiscovery(result, label) {
  assert.equal(result.status, 0, `${label} Cursor discovery failed:\n${result.stderr}\n${result.stdout}`);
  assert.ok(result.stdout.includes(`Tools for ${serverName} (4):`), `${label}: unexpected discovery header`);
  for (const tool of ["attack", "echo", "slow", "warn"]) assert.match(result.stdout, new RegExp(`- ${tool} \\(text\\)`));
}

function assertWire(wire, previousWire, version, label) {
  const pids = new Set(wire.map(row => row.pid));
  assert.ok(pids.size >= 1, `${label}: missing peer PID`);
  assert.ok(previousWire.every(row => !pids.has(row.pid)), `${label}: peer process was reused`);
  for (const pid of pids) {
    const rows = wire.filter(row => row.pid === pid);
    const requests = rows.filter(row => row.direction === "to-server").map(row => row.message);
    for (const method of ["initialize", "notifications/initialized", "tools/list"]) {
      assert.ok(requests.some(message => message.method === method), `${label}: missing ${method}`);
    }
    assert.equal(requests.some(message => message.method === "tools/call"), false, `${label}: unexpected tool execution`);
    const initialize = requests.find(message => message.method === "initialize");
    const response = rows.find(row => row.direction === "from-server" && row.message.id === initialize.id);
    assert.equal(response?.message.result?.serverInfo?.version, version, `${label}: wrong running fixture version`);
  }
}

const seed = {
  mcpServers: {
    retained: { command: process.execPath, args: ["-e", "process.exit(0)"] },
  },
};
await writeFile(configPath, `${JSON.stringify(seed, null, 2)}\n`);

const cursorVersion = run(cursor, ["--version"]);
assert.equal(cursorVersion.status, 0, `Cursor CLI is not runnable:\n${cursorVersion.stderr}`);

const report = {
  schemaVersion: 1,
  suite: "cursor-cli-lifecycle",
  client: "cursor",
  configPath,
  cursorAgent: cursor,
  cursorVersion: cursorVersion.stdout.trim(),
  mcpmVersion: JSON.parse(requireText(path.join(root, "package.json"))).version,
  fixture: { serverName, packageName, syntheticRegistry: true },
  cases: [],
  notTested: [
    "Cursor desktop/editor UI and workspace trust prompts",
    "Cursor account-authenticated model or MCP tool execution",
    "Cursor MCP approval prompts and persistent mcp enable/disable state",
    "Non-stdio URL/HTTP transport",
    "Protocol methods beyond initialize, initialized, and tools/list",
  ],
};

async function observe(id, expected) {
  const beforeWire = wireLines();
  const result = run(cursor, ["mcp", "list-tools", serverName]);
  assertDiscovery(result, id);
  const config = readConfig();
  assert.deepEqual(config.mcpServers.retained, seed.mcpServers.retained, `${id}: unrelated config changed`);
  assert.equal(expected.present, Object.hasOwn(config.mcpServers, serverName), `${id}: server presence mismatch`);
  assert.notEqual(config.mcpServers[serverName].disabled, true, `${id}: server remains disabled`);
  if (expected.wrapped !== undefined) {
    const entry = config.mcpServers[serverName];
    assert.equal(entry.args?.includes("--inner") ?? false, expected.wrapped, `${id}: guard wrap mismatch`);
  }
  const wire = wireLines().slice(beforeWire.length);
  assertWire(wire, beforeWire, expected.version, id);
  report.cases.push({ id, status: "pass", cursor: { status: result.status, stdout: result.stdout.trim() }, config, wire });
}

mcpm(["install", serverName, "--client", "cursor", "--yes", "--skip-health-check", "--json"]);
await observe("install-and-discover", { present: true, wrapped: false, version: "1.0.0" });

mcpm(["guard", "enable", "--client", "cursor", "--server", serverName]);
await observe("guard-enable-and-discover", { present: true, wrapped: true, version: "1.0.0" });

mcpm(["update", "--yes", "--json"], "2.0.0");
await observe("update-and-discover", { present: true, wrapped: true, version: "2.0.0" });
assert.equal(readConfig().mcpServers[serverName].args.at(-1), `${packageName}@2.0.0`, "update did not select fixture v2");

mcpm(["guard", "disable", "--client", "cursor", "--server", serverName]);
await observe("guard-disable-and-discover", { present: true, wrapped: false, version: "2.0.0" });

mcpm(["disable", serverName, "--client", "cursor"]);
const beforeDisabledWire = wireLines();
const disabled = run(cursor, ["mcp", "list-tools", serverName]);
assert.equal(disabled.error, undefined, "disabled discovery did not complete");
assert.equal(readConfig().mcpServers[serverName].disabled, true, "disable did not set config flag");
assert.deepEqual(readConfig().mcpServers.retained, seed.mcpServers.retained, "disable changed unrelated config");
const disabledWire = wireLines().slice(beforeDisabledWire.length);
if (disabled.status === 0) {
  assertDiscovery(disabled, "client-disable");
  assertWire(disabledWire, beforeDisabledWire, "2.0.0", "client-disable");
} else {
  assert.equal(disabled.signal, null, "disabled discovery was interrupted");
  assert.match(`${disabled.stdout}\n${disabled.stderr}`, /disabled|not found|unknown/i);
  assert.equal(disabledWire.length, 0, "disabled server unexpectedly started");
}
report.cases.push({
  id: "client-disable-blocks-discovery",
  status: disabled.status === 0 ? "limitation" : "pass",
  ...(disabled.status === 0 ? { limitation: "Cursor CLI list-tools ignores mcpm's generic disabled:true config flag" } : {}),
  cursor: { status: disabled.status, stdout: disabled.stdout.trim(), stderr: disabled.stderr.trim() },
  config: readConfig(), wire: disabledWire,
});

mcpm(["enable", serverName, "--client", "cursor"]);
await observe("client-enable-clears-flag-and-discovers", { present: true, wrapped: false, version: "2.0.0" });

mcpm(["remove", serverName, "--client", "cursor", "--yes"]);
const beforeRemovedWire = wireLines();
const removed = run(cursor, ["mcp", "list-tools", serverName]);
assert.equal(removed.error, undefined, "removed discovery did not complete");
assert.equal(removed.signal, null, "removed discovery was interrupted");
assert.equal(wireLines().length, beforeRemovedWire.length, "removed server unexpectedly started");
assert.notEqual(removed.status, 0, "removed server unexpectedly remained discoverable");
assert.match(`${removed.stdout}\n${removed.stderr}`, /not found|unknown|not configured/i);
assert.equal(Object.hasOwn(readConfig().mcpServers, serverName), false, "remove left fixture in Cursor config");
assert.deepEqual(readConfig().mcpServers.retained, seed.mcpServers.retained, "remove changed unrelated config");
report.cases.push({ id: "remove-preserves-unrelated-config", status: "pass", cursor: { status: removed.status, stdout: removed.stdout.trim(), stderr: removed.stderr.trim() }, config: readConfig() });

report.counts = { pass: report.cases.filter(row => row.status === "pass").length, limitation: report.cases.filter(row => row.status === "limitation").length, fail: 0 };
report.status = report.counts.limitation ? "partial" : "pass";
await writeFile(path.join(evidence, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
process.exitCode = report.counts.limitation ? 1 : 0;
console.log(JSON.stringify({ status: report.status, evidence, counts: report.counts, cursorVersion: report.cursorVersion, mcpmVersion: report.mcpmVersion }, null, 2));
