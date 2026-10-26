#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
const gemini = path.resolve(process.env.GEMINI_CLI ?? args.shift() ?? '');
assert.ok(existsSync(gemini) && gemini.endsWith('.js'), 'Pass the extracted Gemini CLI bundle/gemini.js explicitly');
const evidence = path.resolve(args.shift() ?? await mkdtemp(path.join(os.tmpdir(), 'mcpm-gemini-')));
await mkdir(evidence, { recursive: true, mode: 0o700 });
assert.deepEqual(await readdir(evidence), [], 'evidence directory must be empty');
const home = path.join(evidence, 'home'), work = path.join(evidence, 'work'), bin = path.join(evidence, 'bin');
const controlWork = path.join(evidence, 'control');
for (const dir of [home, work, bin, controlWork, path.join(home, '.gemini')]) await mkdir(dir, { recursive: true, mode: 0o700 });
const configPath = path.join(home, '.gemini', 'settings.json');
const trustPath = path.join(home, '.gemini', 'trustedFolders.json');
const peer = path.join(root, 'scripts/native-client/peer.mjs');
const registry = path.join(root, 'scripts/native-client/fixture-registry.mjs');
const cli = path.join(root, 'dist/index.js');
const server = 'io.github.getmcpm/native-fixture';
const env = { HOME: home, PATH: `${bin}:${process.env.PATH ?? ''}`, CI: '1', NO_COLOR: '1', NO_BROWSER: '1',
  GEMINI_TELEMETRY_ENABLED: 'false', MCPM_DISABLE_OS_KEYCHAIN: '1', MCPM_NATIVE_WORK: work };
const text = file => readFileSync(file, 'utf8');
const config = () => JSON.parse(text(configPath));
const wireAt = dir => {
  const file = path.join(dir, 'wire.jsonl');
  return existsSync(file) && text(file).trim() ? text(file).trim().split('\n').map(JSON.parse) : [];
};
const wire = () => wireAt(work);
function run(file, args, extra = {}) {
  const r = spawnSync(file, args, { cwd: work, env: { ...env, ...extra }, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(r.error, undefined, `${file}: ${r.error}`);
  assert.equal(r.signal, null, `${file}: interrupted`);
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
const native = args => run(process.execPath, [gemini, ...args]);
function mcpm(args, version = '1.0.0') {
  const r = run(process.execPath, ['--import', registry, cli, ...args], { MCPM_NATIVE_REGISTRY_DOUBLE: '1', MCPM_NATIVE_VERSION: version });
  assert.equal(r.status, 0, `mcpm ${args.join(' ')}: ${r.stderr}\n${r.stdout}`);
}
await writeFile(path.join(bin, 'npx'), `#!/usr/bin/env node
import {spawn} from 'node:child_process';
const [flag,spec,...args]=process.argv.slice(2);
if(flag!=='-y'||!/^@mcpm\\/native-fixture@(1|2)\\.0\\.0$/.test(spec))process.exit(64);
process.env.MCPM_NATIVE_WORK ??= ${JSON.stringify(work)};
const child=spawn(process.execPath,[${JSON.stringify(peer)},spec.split('@').at(-1),...args],{stdio:'inherit',env:process.env});
child.on('error',()=>process.exit(1));child.on('exit',(code,signal)=>process.exit(code??(signal?1:0)));
`);
await chmod(path.join(bin, 'npx'), 0o755);
const seed = { telemetry: { enabled: false }, ui: { theme: 'Default' }, mcpServers: {
  retained: { command: process.execPath, args: [peer, '1.0.0'], env: { MCPM_NATIVE_WORK: controlWork } },
} };
await writeFile(configPath, JSON.stringify(seed));
const version = native(['--version']);
assert.equal(version.status, 0, version.stderr);
const report = { schemaVersion: 1, suite: 'gemini-cli-lifecycle', client: 'gemini-cli', clientVersion: version.stdout.trim(),
  configPath, trustPath, syntheticRegistry: true, cases: [],
  notTested: ['Interactive trust or tool consent UI', 'Tools/list or tools/call (native mcp list probes initialize and ping only)',
    'Provider/model requests and credentials', 'HTTP/SSE/OAuth', 'Other client versions, platforms or universal conformance'] };
async function identity(dir) {
  const rows = {};
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.js')) continue;
    rows[entry.name] = createHash('sha256').update(readFileSync(path.join(dir, entry.name))).digest('hex');
  }
  return rows;
}
report.artifacts = { candidateDist: await identity(path.join(root, 'dist')), geminiBundle: await identity(path.dirname(gemini)) };
function preserve() {
  const raw = config();
  for (const key of ['telemetry', 'ui']) assert.deepEqual(raw[key], seed[key], `unrelated ${key} changed`);
  assert.deepEqual(raw.mcpServers.retained, seed.mcpServers.retained, 'unrelated server changed');
}
function connected(r) {
  assert.equal(r.status, 0, r.stderr);
  const line = `${r.stdout}\n${r.stderr}`.split('\n').find(line => line.includes(`${server}:`));
  assert.ok(line?.endsWith(' - Connected'), `fixture not connected: ${line}\n${r.stderr}`);
}
function traffic(rows, before, expected) {
  const pids = new Set(rows.map(row => row.pid));
  assert.ok(pids.size, 'no fixture peer');
  assert.ok(before.every(row => !pids.has(row.pid)), 'peer reused');
  for (const pid of pids) {
    const session = rows.filter(row => row.pid === pid);
    const messages = session.filter(row => row.direction === 'to-server').map(row => row.message);
    for (const method of ['initialize', 'notifications/initialized', 'ping']) assert.ok(messages.some(m => m.method === method), `missing ${method}`);
    assert.equal(messages.some(m => m.method === 'tools/call'), false, 'unexpected tool call');
    const initialize = messages.find(m => m.method === 'initialize');
    const result = session.find(row => row.direction === 'from-server' && row.message.id === initialize.id)?.message.result;
    assert.equal(result?.serverInfo.version, expected, 'wrong running version');
    assert.equal(result?.protocolVersion, initialize.params.protocolVersion, 'fixture negotiation mismatch');
  }
}
function observe(id, expectedVersion, wrapped) {
  const before = wire(), r = native(['mcp', 'list']);
  connected(r); preserve();
  assert.equal(config().mcpServers[server].args?.includes('--inner') ?? false, wrapped);
  const rows = wire().slice(before.length); traffic(rows, before, expectedVersion);
  report.cases.push({ id, status: 'pass', native: r, config: config(), wire: rows });
}
mcpm(['install', server, '--client', 'gemini-cli', '--yes', '--skip-health-check', '--json']);
const beforeTrust = wire(), untrusted = native(['mcp', 'list']);
assert.equal(untrusted.status, 0); assert.match(untrusted.stderr + untrusted.stdout, /folder is untrusted/);
assert.equal(wire().length, beforeTrust.length, 'untrusted folder launched peer');
report.cases.push({ id: 'untrusted-folder-blocks-launch', status: 'pass', native: untrusted, wire: [] });
await writeFile(trustPath, JSON.stringify({ [work]: 'TRUST_FOLDER' }));
observe('install-and-connect', '1.0.0', false);
mcpm(['guard', 'enable', '--client', 'gemini-cli', '--server', server]);
observe('guard-enable-and-connect', '1.0.0', true);
mcpm(['update', '--yes', '--json'], '2.0.0');
observe('update-and-connect', '2.0.0', true);
mcpm(['guard', 'disable', '--client', 'gemini-cli', '--server', server]);
observe('guard-disable-and-connect', '2.0.0', false);
mcpm(['disable', server, '--client', 'gemini-cli']);
const beforeDisabled = wire(), beforeDisabledControl = wireAt(controlWork), disabled = native(['mcp', 'list']);
assert.equal(disabled.status, 0); preserve();
assert.equal(config().mcpServers[server].disabled, true);
const rows = wire().slice(beforeDisabled.length);
if (rows.length) { connected(disabled); traffic(rows, beforeDisabled, '2.0.0'); }
else {
  const line = (disabled.stdout + disabled.stderr).split('\n').find(line => line.includes(`${server}:`));
  assert.match(line ?? '', / - (Disabled|Blocked)$/);
  assert.match(disabled.stdout + disabled.stderr, /retained:.* - Connected/);
  traffic(wireAt(controlWork).slice(beforeDisabledControl.length), beforeDisabledControl, '1.0.0');
}
report.cases.push({ id: 'mcpm-disable-blocks-launch', status: rows.length ? 'limitation' : 'pass', native: disabled, wire: rows,
  ...(rows.length ? { limitation: 'Gemini CLI mcp list ignores the generic disabled:true entry flag' } : {}) });
mcpm(['enable', server, '--client', 'gemini-cli']);
observe('mcpm-enable-and-connect', '2.0.0', false);
for (const action of ['disable', 'enable']) {
  const toggle = native(['mcp', action, server]);
  assert.equal(toggle.status, 0);
  const output = (toggle.stdout + toggle.stderr).replace(/\x1b\[[0-9;]*m/g, '');
  const refused = output.trim() === `Error: Server '${server}' not found. Use 'gemini mcp' to see available servers.`;
  if (!refused) assert.ok(output.includes(`✓ MCP server '${server}' ${action}d.`), `unexpected native toggle output: ${output}`);
  const before = wire(), beforeControl = wireAt(controlWork), listed = native(['mcp', 'list']);
  assert.equal(listed.status, 0); preserve();
  assert.match(listed.stdout + listed.stderr, /retained:.* - Connected/);
  const controlRows = wireAt(controlWork).slice(beforeControl.length);
  traffic(controlRows, beforeControl, '1.0.0');
  const rows = wire().slice(before.length);
  if (refused || action === 'enable') { connected(listed); traffic(rows, before, '2.0.0'); }
  else {
    const line = (listed.stdout + listed.stderr).split('\n').find(line => line.includes(`${server}:`));
    assert.ok(line?.endsWith(' - Disabled'), line);
    assert.equal(rows.length, 0, 'native disable launched target');
  }
  report.cases.push({ id: `native-${action}-command`, status: refused ? 'limitation' : 'pass', native: toggle, listing: listed, wire: rows, controlWire: controlRows,
    ...(refused ? { limitation: `Native Gemini ${action} reports the listed server as not found while exiting zero` } : {}) });
}
mcpm(['remove', server, '--client', 'gemini-cli', '--yes']);
const beforeRemoved = wire(), removed = native(['mcp', 'list']);
assert.equal(removed.status, 0); preserve();
assert.equal(Object.hasOwn(config().mcpServers, server), false);
assert.equal(wire().length, beforeRemoved.length);
assert.equal((removed.stdout + removed.stderr).includes(server), false);
report.cases.push({ id: 'remove-preserves-unrelated-config', status: 'pass', native: removed, wire: [] });
report.counts = { pass: report.cases.filter(row => row.status === 'pass').length, limitation: report.cases.filter(row => row.status === 'limitation').length, fail: 0 };
report.status = report.counts.limitation ? 'partial' : 'pass';
await writeFile(path.join(evidence, 'report.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ status: report.status, clientVersion: report.clientVersion, counts: report.counts, evidence }));
process.exitCode = report.counts.limitation ? 1 : 0;
