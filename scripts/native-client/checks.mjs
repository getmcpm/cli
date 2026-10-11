import assert from 'node:assert/strict';

export function assertEcho(content, expected) {
  const text = content.filter(c => typeof c.value === 'string' || c.type === 'text').map(c => c.value ?? c.text).join('\n');
  const result = JSON.parse(text);
  assert.equal(result.text, expected.text);
  assert.equal(result.version, expected.version);
  assert.equal(result.marker, 'retained');
  assert.ok(Number.isInteger(result.pid) && result.pid > 0);
  return result;
}

export function assertNativeWire(wire, client, tool) {
  assert.ok(wire.some(w => w.message.method === 'initialize' || w.message.method === 'server/discover'), 'missing native opening');
  const identity = JSON.stringify(wire.filter(w => w.direction === 'to-server').map(w => w.message.params?.clientInfo ?? w.message.params?._meta?.['io.modelcontextprotocol/clientInfo']));
  assert.match(identity, client === 'vscode' ? /Visual Studio Code|vscode/i : /claude/i, 'unexpected client identity');
  if (tool) assert.ok(wire.some(w => w.direction === 'to-server' && w.message.method === 'tools/call' && w.message.params.name === tool), 'missing actual native tool call');
}

export function validateReport(report, client, version) {
  const expected = ['install-and-native-echo', 'enable-and-native-block-recovery', 'warn-and-forward', 'cancel-and-recover',
    ...(client === 'vscode' ? ['restart-without-cached-result'] : []), 'update-preserves-wrap-and-settings', 'schema-drift-and-recovery', 'disable-restores-launch-and-remove-preserves-settings'];
  assert.equal(report.client, client); assert.equal(report.clientVersion, version);
  assert.deepEqual(report.cases.map(c => c.id), expected, 'incomplete native matrix');
  assert.ok(report.cases.every(c => c.status === 'pass'));
  assert.deepEqual(report.counts, { pass: expected.length, fail: 0 });
}

export function evidenceFiles(value) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  const entries = Object.entries(value); assert.ok(entries.length > 0 && entries.length <= 32);
  for (const [name, data] of entries) {
    assert.match(name, /^[a-z0-9][a-z0-9.-]*\.json$/); assert.ok(!name.includes('..'));
    assert.ok(data && typeof data === 'object' && JSON.stringify(data).length <= 4 * 1024 * 1024);
  }
  return entries;
}
