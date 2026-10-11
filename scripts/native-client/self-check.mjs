import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtureMetadata, serverName } from './fixture-registry.mjs';
import { assertEcho, assertNativeWire, assertGuestBoundary, checkPayload, evidenceFiles, validateReport } from './checks.mjs';
import { mkdir, mkdtemp, readFile, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { exchange } from '../protocol-sandbox/harness.mjs';
import { gateway } from './gateway.mjs';
import { fixtureApproval } from './approval.mjs';
import { command } from './command.mjs';
import { runInNewContext } from 'node:vm';
import path from 'node:path';

test('fixture registry keeps exact and latest versions distinct and denies external requests', () => {
  const base = 'https://registry.modelcontextprotocol.io/v0.1/servers/' + encodeURIComponent(serverName) + '/versions/';
  assert.equal(fixtureMetadata(base + 'latest', '2.0.0').server.packages[0].version, '2.0.0');
  assert.equal(fixtureMetadata(base + '1.0.0', '2.0.0').server.version, '1.0.0');
  assert.throws(() => fixtureMetadata('https://example.com/'));
});
test('payload rejects escaping symlinks and excessive bytes before copying to a guest', async () => {
  const root = await mkdtemp(tmpdir() + '/mcpm-payload-');
  try {
    await mkdir(`${root}/node_modules`);
    for (const name of ['node.tar.gz', 'vscode.zip', 'package.json', 'package-lock.json', 'pins.json']) await writeFile(`${root}/${name}`, 'public');
    assert.equal((await checkPayload(root)).bytes, 30);
    await symlink(tmpdir(), `${root}/node_modules/outside`);
    await assert.rejects(checkPayload(root), /symlink escapes/);
    await rm(`${root}/node_modules/outside`);
    await truncate(`${root}/node.tar.gz`, 1024 * 1024 * 1024 + 1);
    await assert.rejects(checkPayload(root), /byte budget/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
test('UI consent automation is restricted to the synthetic fixture and excludes account dialogs', () => {
  assert.equal(fixtureApproval({ text: 'Enable global auto approve?', buttons: ['Cancel', 'Enable'] }), 'Enable');
  assert.equal(fixtureApproval({ text: 'native-fixture: call echo?', buttons: ['Allow', 'Cancel'] }), 'Allow');
  assert.equal(fixtureApproval({ text: 'Sign in to GitHub', buttons: ['Allow', 'Sign in'] }), undefined);
  assert.equal(fixtureApproval({ text: 'native-fixture: Allow access to your account?', buttons: ['Allow'] }), undefined);
  assert.equal(fixtureApproval({ text: 'Unrelated command', buttons: ['Allow'] }), undefined);
});
test('guest export refuses traversal, wrong shapes, and empty success reports', () => {
  assert.throws(() => evidenceFiles({ '../outside.json': {} }));
  assert.throws(() => evidenceFiles({ '/outside.json': {} }));
  assert.throws(() => evidenceFiles([]));
  assert.throws(() => validateReport({ client: 'vscode', clientVersion: '1.141.0', cases: [], counts: { pass: 0, fail: 0 } }, 'vscode', '1.141.0'));
  assert.deepEqual(evidenceFiles({ 'report.json': { cases: [] } }), [['report.json', { cases: [] }]]);
  assert.throws(() => evidenceFiles(Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`${i}.json`, { text: 'a'.repeat(3 * 1024 * 1024) }]))), /total evidence budget/);
});
test('complete reports require matching versions, all named cases and independent exported observations', () => {
  const pins = { vscode: { version: '1.141.0' }, claudeCode: '2.1.296', mcpm: '0.47.1', node: { version: '26.11.1' } };
  const hashes = { 'fixture.mjs': 'sha256-fixture' };
  const ids = ['install-and-native-echo', 'enable-and-native-block-recovery', 'warn-and-forward', 'cancel-and-recover',
    'restart-without-cached-result', 'update-preserves-wrap-and-settings', 'schema-drift-and-recovery', 'disable-restores-launch-and-remove-preserves-settings'];
  const report = { schemaVersion: 1, client: 'vscode', clientVersion: pins.vscode.version, cliVersion: pins.mcpm, node: 'v' + pins.node.version,
    platform: 'darwin', arch: 'arm64', hashes, boundary: { model: 'VirtualMac2,1', mounts: '', pfStatus: 'Status: Enabled', pfRules: 'block drop all' },
    cases: ids.map((id, i) => ({ id, status: 'pass', evidence: [`${i}.json`] })), counts: { pass: 8, fail: 0 } };
  const evidence = Object.fromEntries(report.cases.map(c => [c.evidence[0], {}]));
  validateReport(report, 'vscode', pins, hashes, evidence);
  for (const change of [{ cases: [] }, { cases: report.cases.slice(1) }, { hashes: {} }, { cliVersion: '0.0.0' },
    { cases: report.cases.map(c => ({ ...c, evidence: ['0.json'] })) }]) {
    assert.throws(() => validateReport({ ...report, ...change }, 'vscode', pins, hashes, evidence));
  }
  assert.throws(() => validateReport(report, 'vscode', pins, hashes, {}), /incomplete case evidence/);
});
test('guest boundary rejects physical Macs, disabled filtering and extra allow rules', () => {
  const boundary = { model: 'VirtualMac2,1\n', mounts: '/dev/disk3s1 on / (apfs)', pfStatus: 'Status: Enabled for 0 days', pfRules: 'block drop all\n' };
  assertGuestBoundary(boundary);
  for (const change of [{ model: 'Mac14,2' }, { mounts: 'share on /Volumes/share (virtiofs)' }, { pfStatus: 'Status: Disabled' }, { pfRules: 'pass all\nblock drop all' }]) {
    assert.throws(() => assertGuestBoundary({ ...boundary, ...change }));
  }
});
test('host commands abort promptly, enforce deadlines and bound output', async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 100);
  try {
    const result = await command(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { signal: controller.signal });
    assert.equal(result.error, 'ABORT_ERR'); assert.notEqual(result.status, 0);
  } finally { clearTimeout(timer); }
  const timeout = await command(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeout: 100 });
  assert.equal(timeout.signal, 'SIGKILL'); assert.notEqual(timeout.status, 0);
  const verbose = await command(process.execPath, ['-e', "process.stdout.write('x'.repeat(100000))"], { maxBuffer: 1024 });
  assert.equal(verbose.error, 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'); assert.notEqual(verbose.status, 0);
});
test('VS Code drift observation finishes even when native startup waits forever for live tools', async () => {
  let receipt;
  const vscode = { version: '1.141.0', lm: { tools: [] }, window: { activeTextEditor: { document: { uri: { fsPath: '/Users/admin/Library/Application Support/Code/User/mcp.json' } } } },
    commands: { executeCommand: name => name === 'workbench.mcp.startServer' ? new Promise(() => {}) : Promise.resolve() } };
  const fs = { existsSync: () => true, readFileSync: name => name.endsWith('request.json') ? '{"case":"drift"}' : name.endsWith('wire.jsonl') ? '{"method":"tools/list"}' : '{"signature_id":"schema-drift"}',
    writeFileSync: (name, content) => { receipt = JSON.parse(content); } };
  const exports = {};
  runInNewContext(await readFile(new URL('./vscode-extension/tests.cjs', import.meta.url), 'utf8'), {
    exports, __dirname: '/fixture/vscode-extension', console, setTimeout: (fn, delay) => delay === 45000 ? undefined : setTimeout(fn, delay), clearTimeout,
    require: name => ({ vscode, 'node:fs': fs, 'node:path': path, 'node:assert/strict': assert })[name],
  });
  let timeout;
  try {
    await Promise.race([exports.run(), new Promise((_, reject) => { timeout = setTimeout(() => reject(Error('drift case hung')), 1500); })]);
    assert.equal(receipt.status, 'pass');
  } finally { clearTimeout(timeout); }
});
test('synthetic gateway emits a real tool-use round and accepts only its correlated results', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-gateway-');
  const g = await gateway(work, { case: 'echo', text: 'nonce' });
  try {
    const request = { model: 'synthetic', stream: false, tools: [{ name: 'mcp__native__echo' }], messages: [] };
    const response = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify(request) });
    const body = await response.json(); assert.equal(body.stop_reason, 'tool_use'); assert.equal(body.content[0].name, 'mcp__native__echo');
    assert.deepEqual(body.content[0].input, { text: 'nonce' });
    const unrelated = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify({ ...request, messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'native-unissued', content: 'synthetic' }] }] }) });
    assert.equal(unrelated.status, 422, 'unissued result must not complete the run');
    const duplicate = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify({ ...request, messages: [{ role: 'user', content: Array(2).fill({ type: 'tool_result', tool_use_id: 'native-0', content: 'synthetic' }) }] }) });
    assert.equal(duplicate.status, 422, 'duplicate results must not advance the run');
    const done = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify({ ...request, messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 'native-0', content: 'synthetic' }] }] }) });
    assert.equal((await done.json()).stop_reason, 'end_turn');
    const missing = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify({ ...request, tools: [] }) });
    assert.equal(missing.status, 422);
  } finally { await g.close(); await rm(work, { recursive: true, force: true }); }
});
test('fixture launcher is executable in module context and forwards exact package/marker', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-launcher-');
  const session = exchange(process.execPath, [new URL('./launcher.mjs', import.meta.url).pathname, '-y', '@mcpm/native-fixture@2.0.0', '--native-marker', 'retained'], { env: { MCPM_NATIVE_WORK: work } });
  try {
    await session.request('initialize', {});
    const result = await session.request('tools/call', { name: 'echo', arguments: { text: 'nonce' } });
    assertEcho(result.result.content, { text: 'nonce', version: '2.0.0' });
  } finally { await session.close(); await rm(work, { recursive: true, force: true }); }
});
test('native results require actual identity/calls and exact echoed values', () => {
  const content = [{ type: 'text', text: JSON.stringify({ text: 'nonce', version: '1.0.0', marker: 'retained', pid: 1 }) }];
  assertEcho(content, { text: 'nonce', version: '1.0.0' });
  assert.throws(() => assertEcho(content, { text: 'wrong', version: '1.0.0' }));
  assert.throws(() => assertNativeWire([], 'vscode', 'echo'));
  const wire = [{ direction: 'to-server', message: { method: 'initialize', params: { clientInfo: { name: 'Visual Studio Code' } } } }];
  assert.throws(() => assertNativeWire(wire, 'vscode', 'echo'));
  assert.throws(() => assertNativeWire(wire, 'claude-code'));
});
