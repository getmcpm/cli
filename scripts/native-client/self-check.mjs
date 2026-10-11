import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtureMetadata, serverName } from './fixture-registry.mjs';
import { assertEcho, assertNativeWire, evidenceFiles, validateReport } from './checks.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { exchange } from '../protocol-sandbox/harness.mjs';
import { gateway } from './gateway.mjs';
import { fixtureApproval } from './approval.mjs';

test('fixture registry keeps exact and latest versions distinct and denies external requests', () => {
  const base = 'https://registry.modelcontextprotocol.io/v0.1/servers/' + encodeURIComponent(serverName) + '/versions/';
  assert.equal(fixtureMetadata(base + 'latest', '2.0.0').server.packages[0].version, '2.0.0');
  assert.equal(fixtureMetadata(base + '1.0.0', '2.0.0').server.version, '1.0.0');
  assert.throws(() => fixtureMetadata('https://example.com/'));
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
});
test('synthetic gateway emits a real tool-use round and accepts only its correlated results', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-gateway-');
  const g = await gateway(work, { case: 'echo', text: 'nonce' });
  try {
    const request = { model: 'synthetic', stream: false, tools: [{ name: 'mcp__native__echo' }], messages: [] };
    const response = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify(request) });
    const body = await response.json(); assert.equal(body.stop_reason, 'tool_use'); assert.equal(body.content[0].name, 'mcp__native__echo');
    assert.deepEqual(body.content[0].input, { text: 'nonce' });
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
