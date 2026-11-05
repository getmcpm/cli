import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertDoctorObservation, doctorCases, validateReport } from './checks.mjs';
import { gateway } from './gateway.mjs';

function observation(client = 'vscode', scenario = 'healthy', mode = 'direct') {
  const model = { schemaVersion: 1, ok: scenario !== 'malformed',
    clients: ['claude-code', 'claude-desktop', 'cursor', 'gemini-cli', 'vscode', 'windsurf'].map(id => ({
      id, label: id, exists: id === 'cursor', malformed: id === 'cursor' && scenario === 'malformed', serverCount: 0, guardedCount: 0,
    })), runtimes: ['npx', 'uvx', 'docker'].map(name => ({ name, available: false })), crossClient: null, secrets: [],
    issues: scenario === 'malformed' ? [{ kind: 'malformed-config', message: 'Cursor config is malformed' }] : [],
  };
  const content = [{ type: 'text', text: JSON.stringify(model) }];
  const result = scenario === 'denied' ? { isError: true, content: [{ type: 'text', text: 'EACCES: permission denied' }] } : { content, structuredContent: model };
  const message = (direction, message) => ({ direction, message });
  return { request: { case: 'doctor-' + scenario, version: mode },
    config: { [client === 'vscode' ? 'servers' : 'mcpServers']: { 'native-doctor': {
      ...(client === 'vscode' ? { type: 'stdio' } : {}), command: '/opt/mcpm-native/node/bin/node',
      args: ['/opt/mcpm-native/doctor-peer.mjs', '/opt/mcpm-native/work', '/opt/mcpm-native/doctor-home', mode],
    } } }, pins: mode === 'guarded' ? { servers: { 'native-doctor': { mcpm_doctor: { current_hash: 'sha256:' + 'a'.repeat(64) } } } } : null, execution: { status: 0, timedOut: false },
    receipt: { status: 'pass', results: [{ content: result.content.map(part => ({ value: part.text })) }], responses: [{ content: result.content.map(part => part.text).join('\n'), ...(scenario === 'denied' ? { is_error: true } : {}) }] },
    wire: [message('to-server', { id: 1, method: 'initialize', params: { clientInfo: { name: client === 'vscode' ? 'Visual Studio Code' : 'claude-code' } } }),
      message('to-server', { id: 2, method: 'tools/list' }),
      message('from-server', { id: 2, result: { tools: [{ name: 'mcpm_doctor', annotations: { readOnlyHint: true }, outputSchema: { properties: { schemaVersion: { const: 1 } } } }] } }),
      message('to-server', { id: 3, method: 'tools/call', params: { name: 'mcpm_doctor', arguments: {} } }),
      message('from-server', { id: 3, result })] };
}
test('doctor observations distinguish wire evidence from native-visible text/errors', () => {
  for (const client of ['vscode', 'claude-code']) for (const scenario of ['healthy', 'malformed', 'denied', 'recovered']) for (const mode of ['direct', 'guarded']) assertDoctorObservation(observation(client, scenario, mode), client);
});
test('doctor launch config accepts JSONC null-prototype objects without weakening values', () => {
  const obs = observation();
  obs.config.servers = Object.assign(Object.create(null), obs.config.servers);
  obs.config.servers['native-doctor'] = Object.assign(Object.create(null), obs.config.servers['native-doctor']);
  assertDoctorObservation(obs, 'vscode');
  obs.config.servers['native-doctor'].args[3] = 'guarded';
  assert.throws(() => assertDoctorObservation(obs, 'vscode'));
});
test('doctor evidence fails closed on lost contracts, correlation, text or error state', () => {
  for (const mutate of [
    o => { o.wire.at(-1).message.result.structuredContent.ok = false; },
    o => { o.wire.at(-1).message.id = 99; },
    o => { o.wire[2].message.result.tools[0].outputSchema.properties.schemaVersion.const = 2; },
    o => { o.wire[3].message.params.arguments = { destructive: true }; },
    o => { o.receipt.results = []; },
    o => { o.wire.push(o.wire.at(-1)); },
    o => { delete o.wire.at(-1).message.result.structuredContent.issues; },
    o => { o.config.servers['native-doctor'].args[3] = 'guarded'; },
    o => { o.wire.push({ direction: 'to-server', message: { id: 4, method: 'tools/call', params: { name: 'mcpm_install', arguments: {} } } }); },
  ]) { const o = observation(); mutate(o); assert.throws(() => assertDoctorObservation(o, 'vscode')); }
  const guarded = observation('vscode', 'healthy', 'guarded'); guarded.pins = null;
  assert.throws(() => assertDoctorObservation(guarded, 'vscode'));
  const denied = observation('claude-code', 'denied'); delete denied.receipt.responses[0].is_error;
  assert.throws(() => assertDoctorObservation(denied, 'claude-code'));
  const error = observation('vscode', 'denied'); delete error.wire.at(-1).message.result.isError;
  assert.throws(() => assertDoctorObservation(error, 'vscode'));
});
test('synthetic gateway requests only doctor with empty arguments', async () => {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const work = await mkdtemp('/tmp/mcpm-doctor-gateway-');
  const model = await gateway(work, { case: 'doctor-healthy', text: 'nonce' });
  try {
    const response = await fetch(model.url + '/v1/messages', { method: 'POST', body: JSON.stringify({ tools: [{ name: 'mcp__native-doctor__mcpm_doctor' }], messages: [], model: 'synthetic' }) });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.content[0].name, 'mcp__native-doctor__mcpm_doctor');
    assert.deepEqual(result.content[0].input, {});
  } finally { await model.close(); await rm(work, { recursive: true }); }
});
test('doctor recorder forwards exact frames, isolates env and exits when child closes', async () => {
  const { mkdtemp, mkdir, copyFile, writeFile, readFile, realpath, rm } = await import('node:fs/promises');
  const { spawn } = await import('node:child_process');
  const root = await realpath(await mkdtemp('/tmp/mcpm-doctor-recorder-'));
  try {
    await copyFile(new URL('./doctor-peer.mjs', import.meta.url), `${root}/doctor-peer.mjs`);
    await mkdir(`${root}/node_modules/@getmcpm/cli/dist`, { recursive: true });
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/index.js`, `
      const readline = require('node:readline');
      readline.createInterface({ input: process.stdin }).once('line', line => {
        const request = JSON.parse(line);
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: {
          args: process.argv.slice(2), env: process.env, request,
        } }) + '\\n', () => process.exit(0));
      });
    `);
    for (const mode of ['direct', 'guarded']) {
      const work = `${root}/${mode}`; await mkdir(work);
      const child = spawn(process.execPath, [`${root}/doctor-peer.mjs`, work, `${root}/home`, mode], {
        env: { PATH: '/usr/bin:/bin', HOME: '/wrong', NATIVE_SECRET: 'must-not-forward' }, stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = '', stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
      const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
      try {
        const closed = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
        const request = { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'mcpm_doctor', arguments: {} } };
        // Keep stdin open: a finished server must not strand its recorder.
        child.stdin.write(JSON.stringify(request) + '\n');
        assert.deepEqual(await closed, { code: 0, signal: null }, stderr);
        const response = JSON.parse(stdout), cli = `${root}/node_modules/@getmcpm/cli/dist/index.js`;
        assert.deepEqual(response.result.args, mode === 'direct' ? ['serve']
          : ['guard', 'run', '--inner', '--server-name', 'native-doctor', '--', process.execPath, cli, 'serve']);
        assert.equal(response.result.env.HOME, `${root}/home`); assert.equal(response.result.env.PATH, '/usr/bin:/bin');
        assert.equal(response.result.env.NATIVE_SECRET, undefined); assert.deepEqual(response.result.request, request);
        const wire = (await readFile(`${work}/wire.jsonl`, 'utf8')).trim().split('\n').map(JSON.parse);
        assert.deepEqual(wire.map(row => [row.direction, row.message]), [['to-server', request], ['from-server', response]]);
      } finally { clearTimeout(timer); child.kill(); }
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('doctor report rejects unknown suites, partial failures and missing evidence', () => {
  const pins = { vscode: { version: '1' }, claudeCode: '2', mcpm: '0.49.0', node: { version: '26.11.1' } };
  for (const client of ['vscode', 'claude-code']) {
    const report = { schemaVersion: 1, suite: 'doctor', client, clientVersion: client === 'vscode' ? '1' : '2',
      cliVersion: pins.mcpm, node: 'v26.11.1', platform: 'darwin', arch: 'arm64', hashes: {},
      boundary: { model: 'VirtualMac2,1', mounts: '', pfStatus: 'Status: Enabled', pfRules: 'block drop all' },
      syntheticRegistryAndLauncher: false, syntheticModelGateway: client === 'claude-code',
      cases: doctorCases.map((id, i) => ({ id, status: 'pass', evidence: [`${i}.json`] })), counts: { pass: 8, fail: 0 },
    };
    const evidence = Object.fromEntries(doctorCases.map((id, i) => {
      const [mode, scenario] = id.split('-'); return [`${i}.json`, observation(client, scenario, mode)];
    }));
    validateReport(report, client, pins, {}, evidence);
    for (const mutate of [
      r => { r.suite = 'unknown'; }, r => { delete r.suite; },
      r => { r.cases.pop(); }, r => { r.cases[2].status = 'fail'; },
      r => { r.counts = { pass: 7, fail: 1 }; }, r => { r.cases[0].evidence = []; },
      r => { r.cases[1].evidence = r.cases[0].evidence; }, r => { r.syntheticRegistryAndLauncher = true; },
    ]) {
      const changed = structuredClone(report); mutate(changed);
      assert.throws(() => validateReport(changed, client, pins, {}, evidence));
    }
    const missing = { ...evidence }; delete missing['0.json'];
    assert.throws(() => validateReport(report, client, pins, {}, missing));
    const wrongMode = structuredClone(evidence); wrongMode['4.json'].request.version = 'direct';
    assert.throws(() => validateReport(report, client, pins, {}, wrongMode));
  }
});
