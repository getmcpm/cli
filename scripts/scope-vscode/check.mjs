import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const sha = text => createHash('sha256').update(text).digest('hex');

export const caseIds = ['vscode-json', 'vscode-human', 'claude-default', 'claude-explicit', 'vscode-malformed', 'vscode-user-jsonc', 'vscode-symlink', 'vscode-denied', 'missing-root', 'empty-root', 'bad-client', 'vscode-bare'];
export const origins = ['vscode-project', 'copilot-project', 'vscode-user', 'copilot-user'];
export const fixtureFiles = ['project/.vscode/mcp.json', 'project/.mcp.json', 'home/.config/Code/User/mcp.json', 'home/.copilot/mcp-config.json', 'home/.claude.json', 'project/.github/copilot-instructions.md', 'AGENTS.md', 'home/.copilot/copilot-instructions.md', 'forbidden.json'];
export const nativeFiles = ['/home/node/.config/Code/User/mcp.json', '/work/native-project/.vscode/mcp.json', '/work/native-project/.mcp.json', '/home/node/.copilot/mcp-config.json', '/home/node/.config/Code/User/settings.json'];
export const cliEnvironment = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/work/scope-cli/home', TMPDIR: '/work/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
export const sourceIdentities = origins.map((origin, i) => ({ origin, path: '/work/scope-cli/' + fixtureFiles[i], format: i === 0 || i === 2 ? 'vscode' : 'copilot-portable', scope: i < 2 ? 'project' : 'user' }));
function checkSnapshots(snapshot, expected) {
  assert.deepEqual(Object.keys(snapshot).sort(), [...expected].sort(), 'complete fixture snapshot');
  for (const value of Object.values(snapshot)) {
    assert.ok(Number.isInteger(value.mode) && value.mode >= 0 && value.mode <= 0o777);
    if (value.state === 'symlink') { assert.equal(value.target, '/work/scope-cli/forbidden.json'); continue; }
    assert.equal(value.state, 'file'); const bytes = Buffer.from(value.base64, 'base64');
    assert.equal(bytes.toString('base64'), value.base64); assert.equal(value.bytes, bytes.length); assert.equal(value.sha256, sha(bytes));
  }
}
export function checkReport(report) {
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.boundary.uid, 1000); assert.equal(report.boundary.gid, 1000); assert.match(report.boundary.capEff, /^0+$/);
  assert.equal(report.boundary.noNewPrivs, '1'); assert.deepEqual(report.boundary.interfaces, ['lo']); assert.equal(report.boundary.rootWriteError, 'EROFS');
  assert.equal(report.sentinelControl.status, 0); assert.equal(report.sentinelControl.signal, null);
  assert.equal(report.sentinelControl.markerContents, 'SCOPE_SECRET_EXEC'); assert.equal(report.sentinelControl.removed, true);
  assert.deepEqual(report.cli.map(row => row.id), caseIds);
  for (const row of report.cli) {
    const root = row.id === 'missing-root' ? '/work/not-present' : row.id === 'empty-root' ? '' : '/work/scope-cli/project';
    const options = row.id === 'claude-default' ? ['--json'] : row.id === 'claude-explicit' ? ['--client', 'claude-code', '--json'] : ['--client', row.id === 'bad-client' ? 'unsupported' : 'vscode', ...(row.id === 'vscode-human' ? [] : ['--json'])];
    assert.equal(row.command, '/usr/local/bin/node'); assert.deepEqual(row.args, ['/app/node_modules/@getmcpm/cli/dist/index.js', 'scope', root, ...options]);
    assert.equal(row.cwd, '/work/scope-cli/project'); assert.deepEqual(row.env, cliEnvironment);
    assert.equal(row.signal, null); assert.ok(!row.error);
    assert.equal(row.status, ['vscode-json', 'vscode-human', 'claude-default', 'claude-explicit'].includes(row.id) ? 0 : 1);
    checkSnapshots(row.before, fixtureFiles); checkSnapshots(row.after, fixtureFiles);
    assert.deepEqual(row.after, row.before, 'scope did not mutate inputs'); assert.equal(row.markerExists, false, 'configured command did not execute');
    assert.deepEqual(row.marker, { path: '/work/scope-cli/EXECUTION_MARKER', state: 'missing', code: 'ENOENT' });
    for (const value of ['SCOPE_SECRET', 'EXECUTION_MARKER']) assert.ok(!row.stdout.includes(value) && !row.stderr.includes(value), 'sensitive value not output');
    if (row.id === 'vscode-human') { assert.match(row.stdout, /^VS Code scope inventory:/); continue; }
    if (row.id === 'bad-client') continue;
    const model = JSON.parse(row.stdout);
    assert.equal(model.schemaVersion, 1);
    assert.equal(model.root.path, root);
    assert.equal(model.client, row.id.startsWith('claude') ? 'claude-code' : 'vscode');
    for (const field of ['hostVersion', 'effective', 'loaded', 'enforced']) assert.equal(model[field], 'unknown');
    assert.equal(model.inventoryComplete, row.status === 0);
    if (row.id === 'vscode-json') {
      assert.deepEqual(model.sources.map(source => source.origin), origins);
      assert.deepEqual(model.servers.map(server => server.origin), origins);
      for (let i = 0; i < sourceIdentities.length; i++) {
        const source = model.sources[i], expected = sourceIdentities[i], server = model.servers[i];
        for (const key of ['origin', 'path', 'format', 'scope']) assert.equal(source[key], expected[key]);
        assert.equal(source.state, 'present');
        assert.equal(server.name, 'same'); assert.equal(server.source, expected.path); assert.equal(server.format, expected.format); assert.equal(server.scope, expected.scope); assert.equal(server.configured, true);
        assert.ok(!('possibleShadowedBy' in server));
        assert.deepEqual(server.sameNameIn, sourceIdentities.filter(peer => peer.origin !== expected.origin).map(peer => ({ origin: peer.origin, source: peer.path })));
      }
    }
    const sourceError = { 'vscode-malformed': [0, 'malformed'], 'vscode-user-jsonc': [3, 'malformed'], 'vscode-symlink': [0, 'symlink-skipped'], 'vscode-denied': [0, 'unreadable'] }[row.id];
    if (sourceError) assert.equal(model.sources[sourceError[0]].state, sourceError[1]);
    if (row.id === 'vscode-bare') {
      assert.equal(model.sources[1].container, 'bare'); assert.equal(model.sources[1].state, 'malformed');
      assert.ok(model.servers.some(server => server.name === 'visible-neighbor' && server.declaration === 'object'));
      assert.ok(model.servers.some(server => server.name === 'servers' && server.declaration === 'malformed'));
    }
    if (row.id === 'missing-root' || row.id === 'empty-root') assert.deepEqual(model.sources, []);
  }
  assert.deepEqual(JSON.parse(report.cli.find(row => row.id === 'claude-default').stdout), JSON.parse(report.cli.find(row => row.id === 'claude-explicit').stdout), 'default Claude selection unchanged');
  const native = report.native;
  assert.equal(report.nativeProcess.status, 0); assert.equal(report.nativeProcess.signal, null); assert.ok(!report.nativeProcess.error);
  assert.equal(report.nativeProcess.command, '/opt/vscode/bin/code');
  assert.ok(!report.nativeProcess.args.some(arg => /^(?:--user-data-dir|--profile)(?:=|$)/.test(arg)));
  assert.equal(report.nativeProcess.env.HOME, '/home/node'); assert.equal(report.nativeProcess.env.XDG_CONFIG_HOME, undefined);
  assert.equal(native.status, 'pass'); assert.equal(native.version, '1.141.0');
  assert.equal(report.productCommit, '2a59476c9bfcb90b3ddc372c36762471b7dfad1c');
  assert.deepEqual(native.commands, ['workbench.mcp.openUserMcpJson']);
  assert.equal(native.configPath, '/home/node/.config/Code/User/mcp.json');
  assert.equal(native.projectPath, '/work/native-project/.vscode/mcp.json');
  assert.equal(native.languageId, 'jsonc');
  assert.equal(native.initialDiagnosticsKind, 'snapshot');
  assert.equal(native.initialDiagnostics.filter(row => row.severity === 0).length, 0, 'valid syntax before negative control');
  assert.ok(Number.isSafeInteger(native.initialVersion) && native.initialVersion > 0);
  assert.equal(native.originalSha256, sha(native.originalText));
  assert.equal(native.originalSha256, report.nativeBefore[native.projectPath].sha256);
  assert.equal(native.transitions.length, 2, 'invalid and restored document states retained');
  let version = native.initialVersion;
  for (const transition of native.transitions) {
    assert.ok(Number.isSafeInteger(transition.version) && transition.version > version, 'causal document versions'); version = transition.version;
    assert.equal(transition.sha256, sha(transition.text), 'actual text/hash binding');
  }
  assert.equal(native.transitions[0].text, '{"servers":');
  assert.notEqual(native.transitions[0].sha256, native.originalSha256);
  assert.equal(native.transitions[1].text, native.originalText);
  for (const [i, name] of ['invalid', 'restored'].entries()) {
    const transition = native.transitions[i];
    assert.ok(native.diagnosticEvents.some(event => event.path === native.projectPath && event.version === transition.version && event.sha256 === transition.sha256 && JSON.stringify(event.diagnostics) === JSON.stringify(native[`${name}Diagnostics`])), 'actual owned URI/version diagnostic event');
  }
  assert.ok(native.invalidDiagnostics.some(row => row.severity === 0), 'actual syntax negative control');
  assert.equal(native.restoredDiagnostics.filter(row => row.severity === 0).length, 0);
  assert.equal(native.restoredSha256, native.originalSha256);
  assert.equal(native.restoredSha256, native.transitions[1].sha256);
  assert.match(native.originalSha256, /^[a-f0-9]{64}$/);
  checkSnapshots(report.nativeBefore, nativeFiles); checkSnapshots(report.nativeAfter, nativeFiles);
  assert.deepEqual(report.nativeAfter, report.nativeBefore, 'inert native fixture bytes restored');
  return { status: 'pass', cliCases: report.cli.length, nativeScope: 'default-profile URI and JSONC editor syntax only; MCP selection/activation unknown' };
}
