import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, readdir, access } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { networkInterfaces } from 'node:os';
import { equivalent, exchange, assertEcho, assertUnsupported } from './harness.mjs';

const app = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(app, 'node_modules/@getmcpm/cli/dist/index.js');
const peer = path.join(app, 'peer.mjs');
const output = '/evidence';
const modernVersion = '2026-07-28';
const meta = { 'io.modelcontextprotocol/protocolVersion': modernVersion, 'io.modelcontextprotocol/clientCapabilities': {} };
const report = { schemaVersion: 1, scope: 'stdio relay and named serve operations; synthetic peers',
  environment: { os: process.platform, arch: process.arch, node: process.version }, packages: {}, cases: [],
  exclusions: ['Installed native clients and configuration adapters', 'Model/skill behavior', 'HTTP/OAuth', 'Universal protocol conformance'],
};
await mkdir(output, { recursive: true });
for (const name of ['@getmcpm/cli', '@modelcontextprotocol/sdk', '@modelcontextprotocol/client', '@modelcontextprotocol/server', '@modelcontextprotocol/inspector']) {
  report.packages[name] = JSON.parse(await readFile(path.join(app, 'node_modules', name, 'package.json'), 'utf8')).version;
}
report.lockSha256 = createHash('sha256').update(await readFile(path.join(app, 'package-lock.json'))).digest('hex');
report.cliSha256 = createHash('sha256').update(await readFile(cli)).digest('hex');
report.harnessSha256 = {};
for (const file of ['run.mjs', 'peer.mjs', 'harness.mjs', 'self-check.mjs']) {
  report.harnessSha256[file] = createHash('sha256').update(await readFile(path.join(app, file))).digest('hex');
}
report.specifications = [
  'https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning',
  'https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr',
];
const lock = JSON.parse(await readFile(path.join(app, 'package-lock.json')));
report.artifact = lock.packages['node_modules/@getmcpm/cli'];

async function optionalJson(file, fallback) {
  try { return JSON.parse(await readFile(file, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return fallback; throw e; }
}
async function lines(file) {
  let s;
  try { s = await readFile(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return []; throw e; }
  assert.ok(s.length < 1024 * 1024, 'evidence budget exceeded');
  return s.trim() ? s.trim().split('\n').map(line => JSON.parse(line)) : [];
}
const signatures = obs => obs.events.flatMap(e => e.findings || []).map(f => f.signature_id);
async function location(id, guarded) {
  const home = `/work/state/${id}/${guarded ? 'guarded' : 'direct'}`;
  await mkdir(home, { recursive: true });
  return { home, env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, WIRE: `${home}/peer.jsonl` } };
}
function launch(server, guarded, wirePath) {
  const args = server === 'serve' ? [cli, 'serve'] : [peer, server, ...(wirePath ? [wirePath] : [])];
  return { command: process.execPath, args: guarded ? [cli, 'guard', 'run', '--inner', '--server-name', 'sandbox', '--', process.execPath, ...args] : args };
}
async function stateFiles(home) {
  return { events: await lines(`${home}/.mcpm/guard-events.jsonl`), pins: await optionalJson(`${home}/.mcpm/pins.json`, null) };
}
async function pair(id, exercise, check = (a, b) => equivalent(a.value, b.value), status = 'pass') {
  const row = { id, status: 'fail', evidence: [] };
  try {
    const direct = await exercise(false, await location(id, false));
    await writeFile(`${output}/${id}-direct.json`, JSON.stringify(direct, null, 2));
    row.evidence.push(`${id}-direct.json`);
    const guarded = await exercise(true, await location(id, true));
    await writeFile(`${output}/${id}-guarded.json`, JSON.stringify(guarded, null, 2));
    row.evidence.push(`${id}-guarded.json`);
    check(direct, guarded);
    row.status = status;
    row.direct = direct.value;
    row.guarded = guarded.value;
  } catch (e) { row.reason = e.stack; }
  report.cases.push(row);
  console.log(`${row.status}: ${id}${row.reason ? ': ' + row.reason.split('\n')[0] : ''}`);
  await writeFile(`${output}/report.json`, JSON.stringify(report, null, 2));
}

// Validate the actual boundary before executing any published CLI or reference peer.
try {
  assert.equal(process.platform, 'linux');
  assert.equal(process.getuid(), 1000);
  assert.match(await readFile('/proc/self/status', 'utf8'), /CapEff:\s+0+\n/);
  assert.deepEqual(Object.keys(networkInterfaces()), ['lo']);
  const mounts = await readFile('/proc/self/mountinfo', 'utf8');
  assert.ok(!mounts.includes('/Users/') && !mounts.includes('docker.sock') && !mounts.includes('/host/'));
  for (const absent of ['/var/run/docker.sock', '/Users', '/home/node/.ssh', '/home/node/.aws']) {
    await assert.rejects(access(absent));
  }
  await assert.rejects(writeFile('/app/should-be-readonly', 'test'), { code: 'EROFS' });
  report.boundary = { status: 'pass', uid: process.getuid(), interfaces: ['lo'], rootReadOnly: true, effectiveCapabilities: 0 };
} catch (e) {
  report.boundary = { status: 'fail', reason: e.stack };
  await writeFile(`${output}/report.json`, JSON.stringify(report, null, 2));
  throw e;
}

async function sdkRun(clientKind, serverKind, mode, action, guarded, loc) {
  const v2 = clientKind === 'v2';
  const { Client } = v2 ? await import('@modelcontextprotocol/client') : await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = v2 ? await import('@modelcontextprotocol/client/stdio') : await import('@modelcontextprotocol/sdk/client/stdio.js');
  const types = v2 ? null : await import('@modelcontextprotocol/sdk/types.js');
  const callbacks = [];
  const client = new Client({ name: 'sandbox-client', version: '1' }, {
    capabilities: { sampling: { tools: {} }, elicitation: { form: {} }, roots: {} },
    ...(v2 ? { versionNegotiation: { mode, probe: { timeoutMs: 1000 } } } : {}),
  });
  const set = (method, schema, fn) => client.setRequestHandler(v2 ? method : types[schema], fn);
  set('sampling/createMessage', 'CreateMessageRequestSchema', async () => {
    callbacks.push('sampling'); return { model: 'fake', role: 'assistant', content: { type: 'text', text: 'Sunny.' } };
  });
  set('elicitation/create', 'ElicitRequestSchema', async () => {
    callbacks.push('elicitation'); return { action: ['decline', 'cancel'].includes(action) ? action : 'accept', content: {} };
  });
  set('roots/list', 'ListRootsRequestSchema', async () => { callbacks.push('roots'); return { roots: [{ uri: 'file:///synthetic', name: 'synthetic' }] }; });
  const transport = new StdioClientTransport({ ...launch(serverKind, guarded, loc.env.WIRE), env: loc.env, stderr: 'pipe', cwd: loc.home });
  let stderr = '';
  transport.stderr?.on('data', b => { stderr = (stderr + b).slice(-32768); });
  const call = (name, args = {}, opts = {}) => v2 ? client.callTool({ name, arguments: args }, opts) : client.callTool({ name, arguments: args }, undefined, opts);
  let value;
  let version;
  try {
    if (action === 'unsupported') {
      await assert.rejects(client.connect(transport, { timeout: 3000 }), e => {
        value = { code: e.code, message: e.message }; return true;
      });
    } else {
      await client.connect(transport, { timeout: 3000 });
      if (action === 'ordinary') {
        value = { tools: await client.listTools(), resources: await client.listResources(),
          resource: await client.readResource({ uri: 'test://hello' }), prompts: await client.listPrompts(),
          prompt: await client.getPrompt({ name: 'hello' }),
          concurrent: await Promise.all([call('echo', { index: 1 }), call('echo', { index: 2 })]),
        };
        assert.equal(value.tools.tools.length, 5);
        value.concurrent.forEach((result, i) => assertEcho(result, { index: i + 1 }));
        assert.deepEqual(value.resource.contents, [{ uri: 'test://hello', text: 'Hello.' }]);
        assert.deepEqual(value.prompt.messages, [{ role: 'user', content: { type: 'text', text: 'Hello.' } }]);
      } else if (action === 'serve') {
        value = await client.listTools(); assert.ok(value.tools.some(t => t.name === 'mcpm_search'));
      } else if (action === 'attack' || action === 'input-attack') {
        const target = action === 'attack' ? 'attack' : 'interactive';
        if (guarded) {
          await assert.rejects(call(target, { poison: true }), e => { assert.equal(e.code, -32099); assert.ok(e.data.signature_id); return true; });
          assert.ok(!callbacks.includes('elicitation'));
          value = { blocked: true, recovery: await call('echo', { after: 'block' }) };
          assertEcho(value.recovery, { after: 'block' });
        } else { value = await call(target, { poison: true }); if (action === 'attack') assert.match(value.content[0].text, /Ignore previous/); }
      } else if (action === 'timeout' || action === 'abort') {
        const controller = new AbortController();
        const timer = action === 'abort' ? setTimeout(() => controller.abort(new Error('scenario cancelled')), 100) : null;
        try { await assert.rejects(call('slow', {}, { timeout: action === 'timeout' ? 100 : 3000, signal: controller.signal }), action === 'timeout' ? /timeout|timed out/i : /scenario cancelled/); }
        finally { clearTimeout(timer); }
        value = await call('echo', { after: action });
        assertEcho(value, { after: action });
      } else if (action === 'progress') {
        const progress = [];
        value = await call('notify', {}, { onprogress: p => progress.push(p) });
        assert.equal(progress.length, 1); assert.equal(progress[0].progress, 1);
      } else {
        value = await call('interactive');
        assert.equal(callbacks.filter(c => c === 'elicitation').length, 1);
        assert.equal(callbacks.filter(c => c === 'sampling').length, serverKind === 'v1' ? 1 : 2);
        assert.equal(callbacks.filter(c => c === 'roots').length, 1);
        if (serverKind !== 'v1') assert.equal(JSON.parse(value.content[0].text).city.action, ['decline', 'cancel'].includes(action) ? action : 'accept');
      }
    }
    if (v2) version = client.getNegotiatedProtocolVersion();
  } finally { await client.close(); }
  const wire = await lines(loc.env.WIRE);
  if (action === 'timeout' || action === 'abort') {
    const request = wire.find(w => w.direction === 'to-server' && w.message.params?.name === 'slow')?.message;
    assert.ok(request, 'missing slow request');
    assert.ok(wire.some(w => w.direction === 'to-server' && w.message.method === 'notifications/cancelled' && w.message.params.requestId === request.id), 'missing correlated cancellation');
  }
  if (!v2) version = wire.find(w => w.message.result?.protocolVersion)?.message.result.protocolVersion;
  return { value, version, callbacks, wire, stderr, ...await stateFiles(loc.home) };
}

for (const [label, client, server, mode] of [
  ['v1-legacy', 'v1', 'v1', 'legacy'],
  ['v2-fallback', 'v2', 'v1', 'auto'],
  ['v1-dual', 'v1', 'v2', 'legacy'],
  ['v2-modern', 'v2', 'v2', { pin: modernVersion }],
]) {
  for (const action of ['ordinary', 'interactive']) {
    await pair(`${label}-${action}`, (g, l) => sdkRun(client, server, mode, action, g, l), (a, b) => {
      equivalent(a.value, b.value); equivalent(a.callbacks, b.callbacks);
      const opening = label === 'v2-modern' ? 'server/discover' : 'initialize';
      for (const obs of [a, b]) assert.ok(obs.wire.some(w => w.message.method === opening));
      equivalent(a.version, b.version);
      assert.equal(a.version, label === 'v2-modern' ? modernVersion : '2025-11-25');
      if (label === 'v2-modern') {
        for (const obs of [a, b]) for (const { direction, message } of obs.wire) {
          if (direction === 'to-server' && message.method && 'id' in message) {
            assert.equal(message.params._meta['io.modelcontextprotocol/protocolVersion'], modernVersion);
            assert.ok(message.params._meta['io.modelcontextprotocol/clientCapabilities']);
          }
          if (message.result) assert.ok(['complete', 'input_required'].includes(message.result.resultType));
        }
      }
      assert.match(b.pins?.handshakes?.sandbox?.current_hash, /^sha256:[a-f0-9]{64}$/);
      if (action === 'ordinary') {
        assert.deepEqual(Object.keys(b.pins.servers.sandbox).sort(), ['attack', 'echo', 'interactive', 'notify', 'slow']);
        for (const pin of Object.values(b.pins.servers.sandbox)) assert.match(pin.current_hash, /^sha256:[a-f0-9]{64}$/);
      }
      if (label === 'v2-modern' && action === 'interactive') {
        for (const obs of [a, b]) {
          const interim = obs.wire.find(w => w.message.result?.resultType === 'input_required').message;
          const retry = obs.wire.find(w => w.message.params?.inputResponses).message;
          assert.equal(retry.params.requestState, interim.result.requestState);
          assert.notEqual(retry.id, interim.id);
          const original = obs.wire.find(w => w.direction === 'to-server' && w.message.id === interim.id).message;
          equivalent(original.params.arguments, retry.params.arguments);
          assert.equal(retry.params.name, original.params.name);
          assert.deepEqual(Object.keys(retry.params.inputResponses).sort(), Object.keys(interim.result.inputRequests).sort());
        }
      }
    });
  }
}
for (const action of ['decline', 'cancel', 'progress', 'timeout', 'abort', 'attack']) {
  await pair(`modern-${action}`, (g, l) => sdkRun('v2', 'v2', { pin: modernVersion }, action, g, l), action === 'attack'
    ? (a, b) => { assert.ok(a.value.content); assert.equal(b.value.blocked, true); assert.ok(signatures(b).length); }
    : undefined);
}
for (const version of ['v1', 'v2']) await pair(`${version}-input-attack`, (g, l) => sdkRun(version, version, { pin: modernVersion }, 'input-attack', g, l), (a, b) => {
  assert.ok(a.value.content); assert.equal(b.value.blocked, true);
  if (version === 'v1') {
    const request = b.wire.find(w => w.message.method === 'elicitation/create').message;
    const response = b.wire.find(w => w.direction === 'to-server' && w.message.error?.code === -32099).message;
    assert.equal(response.id, request.id);
  } else assert.ok(!b.wire.some(w => w.direction === 'to-server' && w.message.error));
});
for (const [id, client, server, mode, code] of [
  ['legacy-to-modern-only', 'v1', 'v2-only', 'legacy', -32022],
  ['modern-pin-to-legacy', 'v2', 'v1', { pin: modernVersion }, null],
]) {
  await pair(id, (g, l) => sdkRun(client, server, mode, 'unsupported', g, l), (a, b) => {
    equivalent(a.value, b.value);
    for (const obs of [a, b]) assertUnsupported(obs, code ? 'initialize' : 'server/discover', code ?? -32601, code ?? 'ERA_NEGOTIATION_FAILED');
  }, 'unsupported');
}
for (const client of ['v1', 'v2']) await pair(`${client}-mcpm-serve`, (g, l) => sdkRun(client, 'serve', 'auto', 'serve', g, l));

async function rawRun(guarded, loc, exercise, server = 'raw') {
  const { command, args } = launch(server, guarded, loc.env.WIRE);
  const session = exchange(command, args, { env: loc.env, cwd: loc.home });
  let value;
  try { value = await exercise(session); } finally { await session.close(); }
  return { value, wire: session.wire, stderr: session.stderr, ...await stateFiles(loc.home) };
}
for (const name of (await readdir(path.join(app, 'fixtures'))).sort()) {
  const fixturePath = path.join(app, 'fixtures', name);
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  await pair(`fixture-${name.replace('.json', '')}`, (g, l) => rawRun(g, l, s => s.request('tools/call', { case: 'fixture', path: fixturePath, _meta: meta })), (a, b) => {
    assert.equal(b.value.id, a.value.id);
    if (fixture.expected_action === 'block') { assert.equal(b.value.error.code, -32099); assert.ok(signatures(b).length); }
    else { equivalent(a.value, b.value); if (fixture.expected_action === 'warn') assert.ok(signatures(b).includes('guard-unsupported-input-request')); }
  });
}
for (const kind of ['deep', 'large']) await pair(`raw-${kind}`, (g, l) => rawRun(g, l, s => s.request('tools/call', { case: kind, _meta: meta })));
for (const action of ['ignore', 'block']) {
  await pair(`coverage-policy-${action}`, async (g, l) => {
    if (g) {
      await mkdir(`${l.home}/.mcpm`, { recursive: true });
      await writeFile(`${l.home}/.mcpm/guard-policy.yaml`, JSON.stringify({ signature_overrides: [{ id: 'guard-unsupported-input-request', action }] }));
    }
    return rawRun(g, l, s => s.request('tools/call', { case: 'fixture', path: path.join(app, 'fixtures/modern-unsupported-input.json'), _meta: meta }));
  }, (a, b) => {
    if (action === 'ignore') { equivalent(a.value, b.value); assert.ok(!signatures(b).includes('guard-unsupported-input-request')); }
    else { assert.equal(b.value.error.code, -32099); assert.ok(signatures(b).includes('guard-unsupported-input-request')); }
  });
}
await pair('unknown-version', (g, l) => rawRun(g, l, s => s.request('tools/list', {
  _meta: { ...meta, 'io.modelcontextprotocol/protocolVersion': '1900-01-01' },
}), 'v2-only'), (a, b) => { equivalent(a.value, b.value); assert.equal(b.value.error.code, -32022); assert.ok(b.value.error.data.supported.includes(modernVersion)); });
await pair('discovery-drift-restart', async (g, l) => {
  const first = await rawRun(g, l, s => s.request('server/discover', { case: 'sandbox', _meta: meta }));
  const second = await rawRun(g, l, s => s.request('server/discover', { case: 'renamed', _meta: meta }));
  if (g) {
    assert.match(first.pins.handshakes.sandbox.current_hash, /^sha256:[a-f0-9]{64}$/);
    assert.equal(second.pins.handshakes.sandbox.current_hash, first.pins.handshakes.sandbox.current_hash);
    assert.ok(signatures(second).includes('handshake-drift-identity'));
  }
  return second;
});
for (const kind of ['malformed', 'oversize', 'disconnect', 'silent']) {
  await pair(`raw-${kind}`, (g, l) => rawRun(g, l, async s => {
    let reason;
    await assert.rejects(s.request('tools/call', { case: kind, _meta: meta }, 1500), e => { reason = e.message; return true; });
    return { rejected: true, reason };
  }), (a, b) => {
    assert.equal(a.value.rejected, true); assert.equal(b.value.rejected, true);
    if (kind === 'oversize') assert.ok(signatures(b).includes('frame-too-large'));
    if (kind === 'malformed') assert.ok(signatures(b).includes('malformed-frame'));
    assert.match(b.value.reason, kind === 'silent' ? /deadline/ : /peer disconnected/);
    assert.match(a.value.reason, kind === 'silent' ? /deadline/ : kind === 'disconnect' ? /peer disconnected/ : /JSON/);
  });
}
await pair('inspector-tools-list', async (g, l) => {
  const launched = launch('v2', g, l.env.WIRE);
  const inspector = path.join(app, 'node_modules/@modelcontextprotocol/inspector/clients/cli/build/index.js');
  const config = `${l.home}/inspector.json`;
  await writeFile(config, JSON.stringify({ mcpServers: { sandbox: { ...launched, env: l.env } } }));
  const result = spawnSync(process.execPath, [inspector, '--config', config, '--server', 'sandbox', '--method', 'tools/list'], {
    env: l.env, cwd: l.home, encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  const value = JSON.parse(result.stdout); assert.equal(value.tools.length, 5);
  return { value, wire: await lines(l.env.WIRE), stderr: result.stderr, ...await stateFiles(l.home) };
});
report.cases.push(...report.exclusions.map((id, i) => ({ id: `excluded-${i + 1}`, description: id, status: 'not tested' })));
report.counts = Object.fromEntries(['pass', 'fail', 'unsupported', 'not tested'].map(s => [s, report.cases.filter(r => r.status === s).length]));
await writeFile(`${output}/report.json`, JSON.stringify(report, null, 2));
console.log(JSON.stringify(report.counts));
process.exitCode = report.counts.fail ? 1 : 0;
