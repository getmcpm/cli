import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, rm, chmod, symlink, readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { applyEdits, getNodeValue, modify, parseTree } from 'jsonc-parser';
import { serverName } from './fixture-registry.mjs';
import { assertEcho as checkEcho, assertNativeWire, assertGuestBoundary, cliArtifact } from './checks.mjs';
import { gateway } from './gateway.mjs';
import { approveFixtureDialogs, fixtureInputPrompt, fixtureInputValue } from './approval.mjs';
import { consentDialogs } from './consent-vscode.mjs';
import { interactiveClaude } from './consent-claude.mjs';
import { vscodeTrustDialogs } from './trust-vscode.mjs';
import { interactiveClaudeTrust } from './trust-claude.mjs';
import { approvalCases, assertConsentObservation } from './checks.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const client = process.argv[2];
const flags = process.argv.slice(3);
assert.ok(flags.every(f => ['candidate', 'realistic', 'approvals', 'trust'].includes(f)) && new Set(flags).size === flags.length);
const candidate = flags.includes('candidate'), realistic = flags.includes('realistic'), approvals = flags.includes('approvals'), trust = flags.includes('trust');
assert.ok([realistic, approvals, trust].filter(Boolean).length <= 1);
assert.ok((!realistic && !trust) || candidate);
assert.ok(['vscode', 'claude-code'].includes(client));
assert.equal(process.platform, 'darwin', 'native test requires macOS guest');
assert.equal(root, '/opt/mcpm-native', 'native test must run inside the prepared guest');
assert.equal(homedir(), '/Users/admin', 'unexpected guest account');
function probe(file, args) {
  const result = spawnSync(file, args, { encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr); return result.stdout;
}
const boundary = { model: probe('/usr/sbin/sysctl', ['-n', 'hw.model']), mounts: probe('/sbin/mount', []),
  pfRules: probe('/usr/bin/sudo', ['/sbin/pfctl', '-sr']), pfStatus: probe('/usr/bin/sudo', ['/sbin/pfctl', '-s', 'info']) };
assertGuestBoundary(boundary);
const work = `${root}/work`; const evidence = `${root}/evidence`;
await mkdir(work, { recursive: true }); await mkdir(evidence, { recursive: true }); await mkdir(`${root}/bin`, { recursive: true });
const cli = `${root}/node_modules/@getmcpm/cli/dist/index.js`;
const node = `${root}/node/bin/node`;
const env = { PATH: `${root}/bin:${root}/node/bin:${root}/node_modules/.bin:/usr/bin:/bin:/usr/sbin:/sbin`, HOME: homedir(), TMPDIR: '/tmp',
  MCPM_NATIVE_WORK: work, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1', ENABLE_TOOL_SEARCH: 'false' };
const bindings = { env: 'synthetic env "quoted" \\ path', input: fixtureInputValue };
if (realistic) env.NATIVE_FIXTURE_SOURCE = bindings.env;
const configPath = client === 'vscode' ? `${homedir()}/Library/Application Support/Code/User/mcp.json` : `${homedir()}/.claude.json`;
const key = client === 'vscode' ? 'servers' : 'mcpServers';
const seed = client === 'vscode' ? { servers: {}, inputs: [{ id: 'retained', type: 'promptString', description: 'Synthetic fixture' }] }
  : { mcpServers: {}, hasCompletedOnboarding: true, projects: { '/opt/unrelated': { allowedTools: ['Read'] } } };
if (realistic && client === 'vscode') seed.inputs.push({ id: 'native-fixture-input', type: 'promptString', description: fixtureInputPrompt, default: fixtureInputValue });
const seedText = realistic && client === 'vscode'
  ? '// native-fixture user-owned comment\n' + JSON.stringify(seed, null, 2).replace(/\n}$/, ',\n}\n') : JSON.stringify(seed, null, 2);
function assertEcho(content, expected) {
  const result = checkEcho(content, expected);
  if (realistic) assert.deepEqual(result.bindings, bindings, 'client must resolve and preserve declared variables');
  return result;
}
let currentCase;
let observationNumber = 0;
const report = { schemaVersion: 1, boundary, client, suite: trust ? 'trust' : approvals ? 'approvals' : realistic ? 'realistic-config' : 'baseline', cliArtifact: await cliArtifact(root, candidate), platform: process.platform, arch: process.arch, node: process.version,
  configPath, syntheticRegistryAndLauncher: true, syntheticModelGateway: client === 'claude-code', cases: [],
  notTested: ['Live registry/npm service behavior', 'Real provider/model or usage-skill behavior', ...(trust ? ['Inline chat, Agent Host, portable VS Code profiles and non-project server scopes'] : approvals ? ['VS Code native macOS dialog rendering, inline chat and Agent Host approvals'] : ['Interactive chat/approval UI']), 'All protocol features or other platforms/clients'] };
async function json(file, fallback) {
  try {
    const raw = await readFile(file, 'utf8');
    if (file === configPath && client === 'vscode') {
      const errors = [], tree = parseTree(raw, errors, { allowTrailingComma: true });
      assert.equal(errors.length, 0); assert.ok(tree); return getNodeValue(tree);
    }
    return JSON.parse(raw);
  } catch (e) { if (e.code === 'ENOENT') return fallback; throw e; }
}
async function lines(file) { try { const s = await readFile(file, 'utf8'); assert.ok(s.length < 4 * 1024 * 1024); return s.trim() ? s.trim().split('\n').map(s => JSON.parse(s)) : []; } catch (e) { if (e.code === 'ENOENT') return []; throw e; } }
function product(args, version = '1.0.0') {
  const r = spawnSync(node, ['--import', `${root}/fixture-registry.mjs`, cli, ...args], { env: { ...env, MCPM_NATIVE_REGISTRY_DOUBLE: '1', MCPM_NATIVE_VERSION: version }, cwd: root, encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024 });
  assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr}\n${r.stdout}`); return { args, stdout: r.stdout, stderr: r.stderr };
}
async function execute(command, args, extraEnv = {}, interrupt) {
  const child = spawn(command, args, { env: { ...env, ...extraEnv }, cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', b => { stdout = (stdout + b).slice(-1024 * 1024); });
  child.stderr.on('data', b => { stderr = (stderr + b).slice(-1024 * 1024); });
  let timedOut = false, interrupted = false;
  const timeout = setTimeout(() => { timedOut = true; try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 60000);
  const poll = interrupt ? setInterval(async () => {
    if ((await lines(`${work}/wire.jsonl`)).some(w => w.message.method === 'tools/call' && w.message.params.name === 'slow')) {
      clearInterval(poll); interrupted = child.kill('SIGINT');
    }
  }, 100) : null;
  try {
    const result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (status, signal) => resolve({ status, signal, stdout, stderr })); });
    return { ...result, timedOut, interrupted };
  } finally { clearTimeout(timeout); clearInterval(poll); }
}
async function native(caseName, version, consent, trustIntent) {
  const eventOffset = (await lines(`${homedir()}/.mcpm/guard-events.jsonl`)).length;
  const request = { case: caseName, text: `native-${caseName}${approvals || trust ? '-' + (observationNumber + 1) : ''}`, version, ...(consent ? { consent } : {}), ...(trustIntent ? { trust: trustIntent } : {}) };
  for (const name of ['wire.jsonl', 'gateway.jsonl', 'receipt.json', 'reload.json', 'consent-intent.json', 'consent-ack.json', 'trust-intent.json', 'trust-ack.jsonl', 'trust-ui.jsonl']) await rm(`${work}/${name}`, { force: true });
  await writeFile(`${work}/request.json`, JSON.stringify(request));
  if (trustIntent) await writeFile(`${work}/trust-intent.json`, JSON.stringify(trustIntent));
  let execution, receipt;
  if (client === 'vscode') {
    const approvalLog = [], approvalUI = {}, controller = new AbortController();
    let approvalError;
    const approval = (trust ? vscodeTrustDialogs(9222, work, approvalLog, controller.signal)
      : approvals ? consentDialogs(work, approvalLog, controller.signal, approvalUI)
      : approveFixtureDialogs(9222, approvalLog, controller.signal)).catch(e => { approvalError = String(e?.stack ?? e?.message ?? e); });
    try {
      execution = await execute('/Applications/Visual Studio Code.app/Contents/MacOS/Code', [trustIntent?.workspacePath ?? root, '--user-data-dir', `${homedir()}/Library/Application Support/Code`,
        '--extensions-dir', `${root}/extensions`, '--extensionDevelopmentPath', `${root}/vscode-extension`, '--remote-debugging-port=9222',
        ...(trust ? ['--enable-proposed-api', 'mcpm-test.mcpm-native-smoke'] : []),
        '--skip-welcome', '--skip-release-notes', ...(!trust ? ['--disable-workspace-trust'] : []), '--disable-updates', '--disable-telemetry']);
    } finally { controller.abort(); await approval; }
    receipt = await json(`${work}/receipt.json`, approvals || trust ? { status: 'fail', error: 'missing native extension receipt' } : null);
    if (approvals) receipt.fixtureApprovalUI = approvalUI;
    if (receipt) { receipt[trust ? 'fixtureTrust' : 'fixtureApprovals'] = approvalLog; if (approvalError) receipt.approvalError = approvalError; }
  } else {
    const model = await gateway(work, request);
    try {
      const extraEnv = { ANTHROPIC_BASE_URL: model.url, ANTHROPIC_API_KEY: 'synthetic-native-fixture-key' };
      execution = trust
        ? await interactiveClaudeTrust(`${root}/node_modules/.bin/claude`, { ...env, ...extraEnv }, root, trustIntent.workspacePath, work, request, model)
        : approvals ? await interactiveClaude(`${root}/node_modules/.bin/claude`, ['--permission-mode', 'default'], { ...env, ...extraEnv }, root, work, request, model)
        : await execute(`${root}/node_modules/.bin/claude`, ['-p', `Run the native fixture ${caseName} check.`, '--output-format', 'stream-json', '--verbose', '--max-turns', '4', '--dangerously-skip-permissions'], extraEnv, caseName === 'cancel');
      const expectedExit = trust && trustIntent.workspace === 'deny' ? execution.status === 1 : execution.status === 0;
      receipt = { client, case: caseName, status: expectedExit && !execution.failure && !model.observations.some(o => o.error) ? 'pass' : 'fail', responses: model.results, gateway: model.observations,
        ...(trust ? { permissionMode: 'default', fixtureTrust: execution.trustDecisions, fixtureApprovals: execution.toolDecisions }
          : approvals ? { permissionMode: 'default', fixtureApprovals: execution.decisions } : {}) };
    } finally { await model.close(); }
  }
  const wire = await lines(`${work}/wire.jsonl`);
  const events = (await lines(`${homedir()}/.mcpm/guard-events.jsonl`)).slice(eventOffset);
  const observedConfigPath = trustIntent?.configPath ?? configPath;
  const observation = { request, execution, receipt, wire, events, configPath: observedConfigPath, config: await json(observedConfigPath),
    configText: await readFile(observedConfigPath, 'utf8'),
    backupText: await readFile(observedConfigPath + '.bak', 'utf8').catch(e => { if (e.code !== 'ENOENT') throw e; return null; }),
    pins: await json(`${homedir()}/.mcpm/pins.json`, null),
    ...(trust && client === 'vscode' ? { trustUI: await lines(`${work}/trust-ui.jsonl`) } : {}),
    ...(approvals || trust ? { clientSettings: await json(client === 'vscode' ? `${homedir()}/Library/Application Support/Code/User/settings.json`
      : trust ? `${trustIntent.workspacePath}/.claude/settings.local.json` : `${root}/.claude/settings.local.json`, null) } : {}) };
  const filename = `${++observationNumber}-${caseName}-${version}.json`;
  await writeFile(`${evidence}/${filename}`, JSON.stringify(observation, null, 2), { flag: 'wx' });
  currentCase.evidence.push(filename);
  return observation;
}
function results(obs) {
  if (client === 'vscode') return obs.receipt.results;
  return obs.receipt.responses.map(r => ({ content: typeof r.content === 'string' ? [{ type: 'text', text: r.content }] : r.content }));
}
function success(obs, tool = 'echo') {
  assert.equal(obs.execution.timedOut, false, 'native execution deadline exceeded');
  assert.equal(obs.execution.status, 0, obs.execution.stderr + obs.execution.stdout);
  assert.equal(obs.receipt?.status, 'pass'); assertNativeWire(obs.wire, client, tool);
}
async function run(id, fn) {
  const row = { id, status: 'fail', evidence: [] };
  currentCase = row;
  try {
    assert.ok(!(approvals || trust) || report.cases.every(c => c.status === 'pass'), 'earlier dependent case failed; stop remaining cases');
    await fn(); row.status = 'pass';
  } catch (e) { row.reason = e.stack; }
  report.cases.push(row); console.log(`${row.status}: ${client}/${id}${row.reason ? ': ' + row.reason.split('\n')[0] : ''}`);
  await writeFile(`${evidence}/report.json`, JSON.stringify(report, null, 2));
}

report.clientVersion = client === 'vscode' ? JSON.parse(await readFile('/Applications/Visual Studio Code.app/Contents/Resources/app/package.json')).version
  : JSON.parse(await readFile(`${root}/node_modules/@anthropic-ai/claude-code/package.json`)).version;
report.cliVersion = JSON.parse(await readFile(`${root}/node_modules/@getmcpm/cli/package.json`)).version;
report.hashes = {};
for (const file of [...(await readdir(root)).filter(f => /\.(mjs|json|tgz|tcl)$/.test(f)), 'vscode-extension/package.json', 'vscode-extension/tests.cjs']) report.hashes[file] = createHash('sha256').update(await readFile(`${root}/${file}`)).digest('hex');
await mkdir(path.dirname(configPath), { recursive: true }); await writeFile(configPath, seedText);
if (client === 'vscode') await writeFile(`${homedir()}/Library/Application Support/Code/User/settings.json`, JSON.stringify({ 'chat.tools.global.autoApprove': !approvals, ...(approvals ? { 'chat.permissions.default': 'default', 'window.dialogStyle': 'custom' } : {}), ...(trust ? { 'chat.mcp.autostart': 'never' } : {}), 'telemetry.telemetryLevel': 'off', 'update.mode': 'none', 'extensions.autoUpdate': false, 'chat.mcp.discovery.enabled': trust ? { 'cursor-workspace': true } : {} }));
// Simulate npm's launcher only for the named, dependency-free fixture package.
await chmod(`${root}/launcher.mjs`, 0o755);
await symlink(`${root}/launcher.mjs`, `${root}/bin/npx`);

if (trust) {
  const workspace = async (name, marker = 'retained') => {
    const workspacePath = `${root}/trust-${client}-${name}`;
    const projectConfig = client === 'vscode' ? `${workspacePath}/${name === 'workspace-deny' ? '.vscode/mcp.json' : '.cursor/mcp.json'}` : `${workspacePath}/.mcp.json`;
    await mkdir(workspacePath, { recursive: true });
    await mkdir(path.dirname(projectConfig), { recursive: true });
    const entry = { command: `${root}/bin/npx`, args: ['-y', '@mcpm/native-fixture@1.0.0', '--native-marker', marker] };
    await writeFile(projectConfig, JSON.stringify(client === 'vscode' && name === 'workspace-deny' ? { servers: { [serverName]: { type: 'stdio', ...entry } } } : { mcpServers: { [serverName]: entry } }, null, 2));
    return { workspacePath, configPath: projectConfig };
  };
  const observe = async (caseName, location, workspaceDecision, serverDecision) => {
    const obs = await native(caseName, '1.0.0', undefined, { ...location, workspace: workspaceDecision, server: serverDecision });
    assert.equal(obs.execution.timedOut, false, 'native trust execution deadline exceeded');
    assert.equal(obs.execution.status, workspaceDecision === 'deny' && client === 'claude-code' ? 1 : 0, obs.execution.stderr + obs.execution.stdout);
    assert.equal(obs.receipt?.status, 'pass'); return obs;
  };
  await run('untrusted-workspace-blocks-project-server', async () => {
    const location = await workspace('workspace-deny');
    const obs = await observe('trust-workspace-deny', location, 'deny', 'deny');
    assert.equal(obs.wire.length, 0); assert.equal(obs.receipt.workspaceTrusted ?? false, false);
  });
  await run('trusted-workspace-server-denial-blocks-launch', async () => {
    const location = await workspace('server-deny');
    const obs = await observe('trust-server-deny', location, 'allow', 'deny');
    assert.equal(obs.wire.length, 0);
  });
  let approvedLocation;
  await run('exact-server-trust-persists-across-restart', async () => {
    approvedLocation = await workspace('approved');
    const first = await observe('trust-server-allow', approvedLocation, 'allow', 'allow');
    const restarted = await observe('trust-server-persisted', approvedLocation, 'persisted', 'persisted');
    const a = assertEcho(results(first).at(-1).content, { text: first.request.text, version: '1.0.0' });
    const b = assertEcho(results(restarted).at(-1).content, { text: restarted.request.text, version: '1.0.0' });
    assert.equal(a.marker, 'retained'); assert.equal(b.marker, 'retained'); assert.notEqual(a.pid, b.pid);
  });
  await run('changed-definition-trust-boundary', async () => {
    const changed = await workspace('approved', 'changed');
    if (client === 'vscode') {
      const denied = await observe('trust-definition-deny', changed, 'persisted', 'deny'); assert.equal(denied.wire.length, 0);
      const allowed = await observe('trust-definition-allow', changed, 'persisted', 'allow');
      assertEcho(results(allowed).at(-1).content, { text: allowed.request.text, version: '1.0.0', marker: 'changed' });
    } else {
      const observed = await observe('trust-definition-change', changed, 'persisted', 'persisted');
      assertEcho(results(observed).at(-1).content, { text: observed.request.text, version: '1.0.0', marker: 'changed' });
    }
  });
} else if (approvals) {
  product(['install', serverName, '--client', client, '--yes', '--skip-health-check', '--json']);
  const config = await json(configPath); config[key][serverName].args.push('--native-marker', 'retained');
  await writeFile(configPath, JSON.stringify(config, null, 2));
  const observe = async (action, tool = 'echo', caseName = 'echo') => {
    const obs = await native(caseName, '1.0.0', { action, tool }); assertConsentObservation(obs, client, action, tool); return obs;
  };
  await run(approvalCases[0], async () => { await observe('allow', 'echo', 'one-shot'); });
  await run(approvalCases[1], async () => { await observe('deny'); await observe('cancel'); });
  await run(approvalCases[2], async () => {
    const first = await observe('always'), restarted = await observe('persisted');
    const a = assertEcho(results(first).at(-1).content, { text: first.request.text, version: '1.0.0' });
    const b = assertEcho(results(restarted).at(-1).content, { text: restarted.request.text, version: '1.0.0' });
    assert.notEqual(a.pid, b.pid, 'fresh client must reconnect to a new peer');
    await observe('deny', 'warn', 'warn');
  });
  await run(approvalCases[3], async () => {
    product(['guard', 'enable', '--client', client, '--server', serverName]);
    const obs = await observe('allow', 'attack', 'block');
    assert.match(JSON.stringify(obs.receipt), /BLOCKED by mcpm-guard/);
    assert.ok(obs.events.some(e => e.action === 'block'));
    assertEcho(results(obs).at(-1).content, { text: obs.request.text, version: '1.0.0' });
  });
} else {
await run('install-and-native-echo', async () => {
  product(['install', serverName, '--client', client, '--yes', '--skip-health-check', '--json']);
  const config = await json(configPath); config[key][serverName].args.push('--native-marker', 'retained'); config[key][serverName].env = { NATIVE_RETAINED: 'synthetic', ...(realistic ? {
    NATIVE_ENV: client === 'vscode' ? '${env:NATIVE_FIXTURE_SOURCE}' : '${NATIVE_FIXTURE_SOURCE}',
    NATIVE_INPUT: client === 'vscode' ? '${input:native-fixture-input}' : '${NATIVE_FIXTURE_MISSING:-' + fixtureInputValue + '}',
  } : {}) };
  const raw = await readFile(configPath, 'utf8');
  await writeFile(configPath, realistic && client === 'vscode'
    ? applyEdits(raw, modify(raw, [key, serverName], config[key][serverName], {}))
    : JSON.stringify(config, null, 2));
  const obs = await native('echo', '1.0.0'); success(obs); assertEcho(results(obs).at(-1).content, { text: 'native-echo', version: '1.0.0' });
});
await run('enable-and-native-block-recovery', async () => {
  product(['guard', 'enable', '--client', client, '--server', serverName]);
  const obs = await native('block', '1.0.0'); success(obs, 'attack');
  assert.match(JSON.stringify(obs.receipt), /BLOCKED by mcpm-guard/);
  assertEcho(results(obs).at(-1).content, { text: 'native-block', version: '1.0.0' });
  assert.ok(obs.events.some(e => e.action === 'block'));
  assert.match(obs.pins?.handshakes?.[serverName]?.current_hash, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(obs.pins.servers[serverName]).sort(), ['attack', 'echo', 'slow', 'warn']);
});
await run('warn-and-forward', async () => {
  const obs = await native('warn', '1.0.0'); success(obs, 'warn');
  const expected = JSON.parse(await readFile(`${root}/warn.json`)).message.result.content[0].text;
  const actual = results(obs).at(-1).content.map(c => c.value ?? c.text).join('\n'); assert.equal(actual, expected);
  assert.ok(obs.events.some(e => e.action === 'warn' && e.findings.some(f => f.signature_id === 'unicode-tag-concealment')));
});
await run('cancel-and-recover', async () => {
  const obs = await native('cancel', '1.0.0'); assertNativeWire(obs.wire, client, 'slow');
  if (client === 'vscode') {
    success(obs, 'slow');
    const slow = obs.wire.find(w => w.message.method === 'tools/call' && w.message.params.name === 'slow').message;
    assert.ok(obs.wire.some(w => w.message.method === 'notifications/cancelled' && w.message.params.requestId === slow.id));
    assertEcho(results(obs).at(-1).content, { text: 'native-cancel', version: '1.0.0' });
  } else {
    assert.equal(obs.execution.interrupted, true, 'test must actually interrupt the slow call');
    assert.equal(obs.execution.timedOut, false, 'deadline is not cancellation');
    const recovery = await native('echo', '1.0.0'); success(recovery); assertEcho(results(recovery).at(-1).content, { text: 'native-echo', version: '1.0.0' });
  }
});
if (client === 'vscode') await run('restart-without-cached-result', async () => {
  const obs = await native('restart', '1.0.0'); success(obs);
  const values = results(obs).map(r => assertEcho(r.content, { text: 'native-restart', version: '1.0.0' }));
  assert.equal(values.length, 2); assert.notEqual(values[0].pid, values[1].pid);
});
await run('update-preserves-wrap-and-settings', async () => {
  const before = await json(configPath);
  product(['update', '--yes', '--json'], '2.0.0');
  const after = await json(configPath); assert.deepEqual(after[key][serverName].env, before[key][serverName].env);
  for (const field of Object.keys(seed).filter(k => k !== key)) assert.deepEqual(after[field], before[field]);
  const obs = await native('echo', '2.0.0'); success(obs); assertEcho(results(obs).at(-1).content, { text: 'native-echo', version: '2.0.0' });
  assert.ok(JSON.stringify(after[key][serverName]).includes('guard'));
});
await run('schema-drift-and-recovery', async () => {
  const before = await json(`${homedir()}/.mcpm/pins.json`);
  await writeFile(`${work}/drift`, 'synthetic');
  try {
    const obs = await native('drift', '2.0.0'); assertNativeWire(obs.wire, client);
    assert.equal(obs.execution.timedOut, false, 'a schema block must not strand the client');
    if (client === 'vscode') { assert.equal(obs.execution.status, 0); assert.equal(obs.receipt?.status, 'pass'); }
    assert.ok(obs.wire.some(w => w.message.method === 'tools/list'));
    assert.ok(!obs.wire.some(w => w.message.method === 'tools/call'));
    assert.ok(obs.events.some(e => e.action === 'block' && e.findings.some(f => f.signature_id === 'schema-drift')));
    assert.deepEqual(obs.pins.servers[serverName], before.servers[serverName], 'drift must not repin');
  } finally { await rm(`${work}/drift`, { force: true }); }
  const obs = await native('echo', '2.0.0'); success(obs); assertEcho(results(obs).at(-1).content, { text: 'native-echo', version: '2.0.0' });
});
await run('disable-restores-launch-and-remove-preserves-settings', async () => {
  product(['guard', 'disable', '--client', client, '--server', serverName]);
  const config = await json(configPath); assert.deepEqual(config[key][serverName].args, ['-y', '@mcpm/native-fixture@2.0.0', '--native-marker', 'retained']);
  const obs = await native('attack', '2.0.0'); success(obs, 'attack'); assert.match(JSON.stringify(results(obs)), /Ignore previous instructions/);
  product(['remove', serverName, '--client', client, '--yes']);
  const after = await json(configPath); assert.equal(after[key][serverName], undefined);
  for (const field of Object.keys(seed).filter(k => k !== key)) assert.deepEqual(after[field], config[field]);
  if (realistic) {
    assert.equal(await readFile(configPath + '.bak', 'utf8'), seedText, 'first raw backup must survive all operations');
    if (client === 'vscode') {
      const raw = await readFile(configPath, 'utf8');
      assert.ok(raw.startsWith('// native-fixture user-owned comment\n'));
      assert.ok(raw.endsWith(',\n}\n'), 'unrelated trailing comma must survive the lifecycle');
    }
  }
  if (client === 'vscode') { const removed = await native('absent', '2.0.0'); assert.equal(removed.execution.status, 0); assert.equal(removed.receipt.status, 'pass'); }
  else {
    const removed = await execute(`${root}/node_modules/.bin/claude`, ['mcp', 'get', serverName]);
    assert.equal(removed.timedOut, false); assert.notEqual(removed.status, 0); assert.match(removed.stdout + removed.stderr, /not found|no.*server/i);
    const filename = `${++observationNumber}-absent-2.0.0.json`;
    await writeFile(`${evidence}/${filename}`, JSON.stringify({ request: { case: 'absent', version: '2.0.0' }, execution: removed,
      config: after, configText: await readFile(configPath, 'utf8'), backupText: await readFile(configPath + '.bak', 'utf8') }, null, 2), { flag: 'wx' });
    currentCase.evidence.push(filename);
  }
});
}
report.counts = { pass: report.cases.filter(c => c.status === 'pass').length, fail: report.cases.filter(c => c.status === 'fail').length };
await writeFile(`${evidence}/report.json`, JSON.stringify(report, null, 2));
process.exitCode = report.counts.fail ? 1 : 0;
