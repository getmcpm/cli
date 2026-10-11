import assert from 'node:assert/strict';
import { lstat, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';

export async function checkPayload(root) {
  root = await realpath(root);
  let bytes = 0, entries = 0;
  async function visit(file) {
    assert.ok(++entries <= 50000, 'payload entry budget exceeded');
    const stat = await lstat(file);
    if (stat.isSymbolicLink()) {
      assert.ok((await realpath(file)).startsWith(root + path.sep), 'payload symlink escapes public payload');
    } else if (stat.isDirectory()) {
      for (const child of await readdir(file)) await visit(path.join(file, child));
    } else {
      assert.ok(stat.isFile(), 'payload contains a non-file');
      bytes += stat.size; assert.ok(bytes <= 1024 * 1024 * 1024, 'payload byte budget exceeded');
    }
  }
  for (const file of ['node_modules', 'node.tar.gz', 'vscode.zip', 'package.json', 'package-lock.json', 'pins.json']) await visit(path.join(root, file));
  return { bytes, entries };
}

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

export function assertGuestBoundary(boundary) {
  assert.match(boundary.model.trim(), /^VirtualMac\d+,\d+$/, 'requires an Apple virtual machine');
  assert.ok(!/virtiofs|My Shared Files/i.test(boundary.mounts), 'host filesystem share mounted');
  assert.match(boundary.pfStatus, /^Status: Enabled\b/m, 'guest packet filter is disabled');
  assert.equal(boundary.pfRules.trim(), 'block drop all', 'unexpected guest packet-filter rules');
}

export function validateReport(report, client, pins, hashes, evidence) {
  const expected = ['install-and-native-echo', 'enable-and-native-block-recovery', 'warn-and-forward', 'cancel-and-recover',
    ...(client === 'vscode' ? ['restart-without-cached-result'] : []), 'update-preserves-wrap-and-settings', 'schema-drift-and-recovery', 'disable-restores-launch-and-remove-preserves-settings'];
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.client, client); assert.equal(report.clientVersion, client === 'vscode' ? pins.vscode.version : pins.claudeCode);
  assert.equal(report.cliVersion, pins.mcpm); assert.equal(report.node, 'v' + pins.node.version);
  assert.equal(report.platform, 'darwin'); assert.equal(report.arch, 'arm64');
  assertGuestBoundary(report.boundary); assert.deepEqual(report.hashes, hashes, 'guest payload differs from host');
  assert.deepEqual(report.cases.map(c => c.id), expected, 'incomplete native matrix');
  assert.ok(report.cases.every(c => c.status === 'pass'));
  assert.deepEqual(report.counts, { pass: expected.length, fail: 0 });
  const references = report.cases.flatMap(c => { assert.ok(Array.isArray(c.evidence) && c.evidence.length > 0, 'missing case evidence'); return c.evidence; });
  assert.equal(new Set(references).size, references.length, 'case evidence was overwritten');
  assert.deepEqual(references.sort(), Object.keys(evidence).filter(f => f !== 'report.json').sort(), 'incomplete case evidence export');
}

export function evidenceFiles(value) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  const entries = Object.entries(value); assert.ok(entries.length > 0 && entries.length <= 32);
  assert.ok(Buffer.byteLength(JSON.stringify(value)) <= 16 * 1024 * 1024, 'total evidence budget exceeded');
  for (const [name, data] of entries) {
    assert.match(name, /^[a-z0-9][a-z0-9.-]*\.json$/); assert.ok(!name.includes('..'));
    assert.ok(data && typeof data === 'object' && Buffer.byteLength(JSON.stringify(data)) <= 4 * 1024 * 1024);
  }
  return entries;
}
