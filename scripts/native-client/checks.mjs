import assert from 'node:assert/strict';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { serverName } from './fixture-registry.mjs';

export async function checkPayload(root, candidate = false) {
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
  for (const file of ['node_modules', 'node.tar.gz', 'vscode.zip', 'package.json', 'package-lock.json', 'pins.json', ...(candidate ? ['candidate.tgz'] : [])]) await visit(path.join(root, file));
  return { bytes, entries };
}

export async function cliArtifact(root, candidate = false) {
  const pkg = JSON.parse(await readFile(`${root}/node_modules/@getmcpm/cli/package.json`));
  const lock = JSON.parse(await readFile(`${root}/package-lock.json`)).packages['node_modules/@getmcpm/cli'];
  assert.equal(pkg.name, '@getmcpm/cli'); assert.equal(pkg.version, lock.version);
  const result = { kind: candidate ? 'candidate' : 'published', version: pkg.version, integrity: lock.integrity,
    entrySha256: createHash('sha256').update(await readFile(`${root}/node_modules/@getmcpm/cli/dist/index.js`)).digest('hex') };
  if (candidate) {
    const stat = await lstat(`${root}/candidate.tgz`);
    assert.ok(stat.isFile() && stat.size <= 32 * 1024 * 1024, 'invalid candidate archive');
    const tar = await readFile(`${root}/candidate.tgz`);
    result.sha256 = createHash('sha256').update(tar).digest('hex');
    assert.equal(lock.integrity, 'sha512-' + createHash('sha512').update(tar).digest('base64'), 'candidate integrity mismatch');
    const packedFiles = execFileSync('/usr/bin/tar', ['-tf', `${root}/candidate.tgz`], { timeout: 10000, maxBuffer: 1024 * 1024 })
      .toString().trim().split('\n').filter(f => f === 'package/package.json' || (f.startsWith('package/dist/') && !f.endsWith('/')))
      .map(f => f.slice('package/'.length)).sort();
    assert.ok(packedFiles.length > 1 && packedFiles.length <= 1024 && new Set(packedFiles).size === packedFiles.length, 'invalid candidate file set');
    assert.ok(packedFiles.every(f => f.split('/').every(p => p && p !== '.' && p !== '..')), 'invalid candidate path');
    const installed = `${root}/node_modules/@getmcpm/cli`;
    const installedFiles = ['package.json'];
    for (const name of await readdir(`${installed}/dist`, { recursive: true })) {
      const stat = await lstat(`${installed}/dist/${name}`);
      assert.ok(stat.isFile() || stat.isDirectory(), 'invalid installed candidate file');
      if (stat.isFile()) installedFiles.push(`dist/${name}`);
    }
    assert.deepEqual(installedFiles.sort(), packedFiles, 'installed candidate file set differs from archive');
    result.filesSha256 = {};
    // index.js imports split chunks; bind every shipped dist file as well as the entry.
    for (const file of packedFiles) {
      const packed = execFileSync('/usr/bin/tar', ['-xOf', `${root}/candidate.tgz`, `package/${file}`], { timeout: 10000, maxBuffer: 8 * 1024 * 1024 });
      const hash = createHash('sha256').update(await readFile(`${installed}/${file}`)).digest('hex');
      assert.equal(hash, createHash('sha256').update(packed).digest('hex'), `installed candidate ${file} differs from archive`);
      result.filesSha256[file] = hash;
    }
    assert.match(lock.resolved, /^file:(?:\.\/)?candidate\.tgz$/);
    const manifest = JSON.parse(await readFile(`${root}/package.json`));
    assert.match(manifest.dependencies['@getmcpm/cli'], /^file:(?:\.\/)?candidate\.tgz$/);
  }
  return result;
}

export function assertEcho(content, expected) {
  const text = content.filter(c => typeof c.value === 'string' || c.type === 'text').map(c => c.value ?? c.text).join('\n');
  const result = JSON.parse(text);
  assert.equal(result.text, expected.text);
  assert.equal(result.version, expected.version);
  assert.equal(result.marker, expected.marker ?? 'retained');
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

export const approvalCases = ['one-shot-reprompts', 'deny-and-cancel-before-dispatch', 'persistent-exact-tool-permission', 'guard-block-after-approval'];
export const trustCases = ['untrusted-workspace-blocks-project-server', 'trusted-workspace-server-denial-blocks-launch', 'exact-server-trust-persists-across-restart', 'changed-definition-trust-boundary'];

export function assertTrustObservation(obs, client) {
  const plan = {
    'trust-workspace-deny': ['deny', 'deny', 'workspace-deny'],
    'trust-server-deny': ['allow', 'deny', 'server-deny'],
    'trust-server-allow': ['allow', 'allow', 'approved'],
    'trust-server-persisted': ['persisted', 'persisted', 'approved'],
    'trust-definition-deny': ['persisted', 'deny', 'approved'],
    'trust-definition-allow': ['persisted', 'allow', 'approved'],
    'trust-definition-change': ['persisted', 'persisted', 'approved'],
  }[obs.request.case];
  assert.ok(plan, 'unexpected trust case');
  assert.deepEqual([obs.request.trust.workspace, obs.request.trust.server], plan.slice(0, 2), 'wrong trust decisions for case');
  assert.equal(obs.execution.timedOut, false, 'trust deadline is not a result');
  assert.equal(obs.execution.status, obs.request.trust.workspace === 'deny' && client === 'claude-code' ? 1 : 0, obs.execution.stderr + obs.execution.stdout);
  assert.equal(obs.execution.failure, undefined); assert.equal(obs.receipt?.status, 'pass'); assert.equal(obs.receipt.approvalError, undefined);
  const intent = obs.request.trust, workspace = intent.workspacePath;
  assert.equal(workspace, `/opt/mcpm-native/trust-${client}-${plan[2]}`, 'wrong trust workspace');
  const expectedConfig = client === 'vscode'
    ? obs.request.case === 'trust-workspace-deny' ? `${workspace}/.vscode/mcp.json` : `${workspace}/.cursor/mcp.json`
    : `${workspace}/.mcp.json`;
  assert.equal(intent.configPath, expectedConfig);
  assert.equal(obs.configPath, intent.configPath);
  const nativeVscodeConfig = client === 'vscode' && obs.request.case === 'trust-workspace-deny';
  const marker = obs.request.case.includes('definition') ? 'changed' : 'retained';
  assert.equal(obs.request.version, '1.0.0');
  assert.deepEqual(obs.config, { [nativeVscodeConfig ? 'servers' : 'mcpServers']: { [serverName]: {
    ...(nativeVscodeConfig ? { type: 'stdio' } : {}), command: '/opt/mcpm-native/bin/npx',
    args: ['-y', '@mcpm/native-fixture@1.0.0', '--native-marker', marker],
  } } }, 'wrong project server definition');
  assert.deepEqual(JSON.parse(obs.configText), obs.config, 'project config readback differs');
  const decisions = obs.receipt.fixtureTrust;
  assert.ok(Array.isArray(decisions) && decisions.every(d => ['workspace', 'server', 'tool-policy'].includes(d.phase)));
  const workspaceDecisions = decisions.filter(d => d.phase === 'workspace'), serverDecisions = decisions.filter(d => d.phase === 'server'), toolPolicy = decisions.filter(d => d.phase === 'tool-policy');
  assert.ok(toolPolicy.length <= 1 && toolPolicy.every(d => d.button === 'Enable'), 'unexpected tool-policy setup decision');
  assert.equal(workspaceDecisions.length, intent.workspace === 'persisted' ? 0 : 1, 'missing, repeated or unexpected workspace decision');
  assert.equal(serverDecisions.length, intent.workspace === 'deny' || intent.server === 'persisted' ? 0 : 1, 'missing, repeated or unexpected server decision');
  for (const decision of workspaceDecisions) assert.match(decision.button ?? decision.label, intent.workspace === 'allow' ? /^(?:Trust (?:Folder|Workspace)(?: & Continue)?|Yes, I trust.*)$/i : /^(?:No, .*|Cancel|.*restricted mode.*)$/i);
  for (const decision of serverDecisions) assert.match(decision.button ?? decision.label, intent.server === 'deny' ? /Do not trust|Continue without using/ : /^Trust$|^Use this MCP server$/);
  const denied = intent.workspace === 'deny' || intent.server === 'deny';
  if (client === 'vscode') {
    assert.equal(obs.receipt.workspaceTrusted, intent.workspace !== 'deny', 'wrong native workspace trust state');
    assert.deepEqual(obs.receipt.workspace, [workspace]);
    assert.equal(obs.clientSettings['chat.tools.global.autoApprove'], true, 'tool consent must stay separate from server trust');
    assert.equal(obs.clientSettings['chat.mcp.autostart'], 'never', 'trust prompt must precede explicit server start');
    assert.deepEqual(obs.clientSettings['chat.mcp.discovery.enabled'], { 'cursor-workspace': true }, 'only the named external workspace discovery source may be enabled');
  } else {
    assert.equal(obs.receipt.permissionMode, 'default'); assert.equal(obs.execution.ptyVerified, true);
    assert.equal(obs.execution.exiting, intent.workspace !== 'deny');
    assert.equal(obs.execution.command, '/opt/mcpm-native/node_modules/.bin/claude');
    assert.deepEqual(obs.execution.args, ['--permission-mode', 'default']); assert.equal(obs.execution.cwd, workspace);
    assert.deepEqual(obs.clientSettings, intent.workspace === 'deny' ? null : {
      [intent.server === 'deny' ? 'disabledMcpjsonServers' : 'enabledMcpjsonServers']: [serverName],
    }, 'project server trust must be scoped to the exact name');
  }
  if (denied) {
    assert.deepEqual(obs.wire, [], 'untrusted project server started');
    assert.equal(obs.receipt.fixtureApprovals?.length ?? 0, 0, 'tool approval occurred for an untrusted server');
    return;
  }
  assertNativeWire(obs.wire, client, 'echo');
  const calls = obs.wire.filter(w => w.direction === 'to-server' && w.message.method === 'tools/call');
  assert.deepEqual(calls.map(w => [w.message.params.name, w.message.params.arguments?.text]), [['echo', obs.request.text]]);
  const result = client === 'vscode' ? obs.receipt.results.at(-1) : obs.receipt.responses.at(-1);
  assertEcho(typeof result.content === 'string' ? [{ type: 'text', text: result.content }] : result.content,
    { text: obs.request.text, version: obs.request.version, marker });
  if (client === 'claude-code') {
    assert.equal(obs.receipt.fixtureApprovals.length, 1, 'trusted server tool call requires its own one-shot approval');
    assert.match(obs.receipt.fixtureApprovals[0].label, /^Yes(?:$|\s*\()/, 'tool approval must be one-shot');
    const submitted = obs.execution.submission;
    assert.equal(submitted?.prompt, `Run the native fixture ${obs.request.case} check with text ${obs.request.text}.`); assert.equal(submitted.confirmed, true);
    assert.ok(obs.wire.some(w => w.direction === 'to-server' && w.pid === submitted.peerPid && w.message.id === submitted.toolsListId && w.message.method === 'tools/list'));
  }
}

export function assertConsentObservation(obs, client, action, tool) {
  assert.equal(obs.execution.timedOut, false, 'consent deadline is not a result');
  assert.equal(obs.execution.status, 0, obs.execution.stderr + obs.execution.stdout);
  assert.equal(obs.execution.failure, undefined); assert.equal(obs.receipt?.status, 'pass'); assert.equal(obs.receipt.approvalError, undefined);
  assert.deepEqual(obs.request.consent, { action, tool }); assertNativeWire(obs.wire, client);
  const decisions = obs.receipt.fixtureApprovals;
  assert.ok(Array.isArray(decisions)); assert.ok(decisions.every(d => !d.error));
  const nonces = obs.request.case === 'one-shot' ? [obs.request.text + '-1', obs.request.text + '-2'] : [obs.request.text];
  assert.equal(decisions.length, action === 'persisted' ? 0 : nonces.length, 'missing, repeated or unexpected permission decision');
  for (const [i, decision] of decisions.entries()) {
    assert.equal(decision.action, action); assert.equal(decision.tool, tool); assert.equal(decision.text, nonces[i]);
    if (client === 'claude-code' || action !== 'always') assert.equal(decision.callsBeforeDecision, 0, 'tool dispatched before permission');
    else {
      assert.ok(decision.selection?.before && decision.selection?.after, 'missing exact-tool grant UI evidence');
      assert.equal(decision.selection.before.checked, 'false', 'grant must start unchecked');
      assert.equal(decision.selection.after.checked, 'true', 'grant must finish checked');
      for (const state of [decision.selection.before, decision.selection.after]) assert.equal(state.tool.trim().split('\n')[0], tool, 'grant must target the exact tool');
    }
  }
  if (client === 'vscode') { assert.equal(obs.clientSettings['chat.tools.global.autoApprove'], false); assert.equal(obs.clientSettings['chat.permissions.default'], 'default'); assert.equal(obs.clientSettings['window.dialogStyle'], 'custom'); }
  else {
    assert.equal(obs.receipt.permissionMode, 'default'); assert.equal(obs.execution.ptyVerified, true); assert.equal(obs.execution.exiting, true);
    assert.equal(obs.execution.command, '/opt/mcpm-native/node_modules/.bin/claude', 'unexpected Claude launch');
    assert.deepEqual(obs.execution.args, ['--permission-mode', 'default'], 'Claude launch must use interactive default mode');
    const submitted = obs.execution.submission;
    assert.equal(submitted?.prompt, `Run the native fixture ${obs.request.case} check with text ${obs.request.text}.`, 'missing exact interactive prompt');
    assert.equal(submitted.confirmed, true, 'interactive prompt was not submitted');
    const listing = obs.wire.find(w => w.direction === 'to-server' && w.pid === submitted.peerPid && w.message.id === submitted.toolsListId && w.message.method === 'tools/list');
    assert.ok(listing && obs.wire.some(w => w.direction === 'from-server' && w.pid === submitted.peerPid && w.message.id === submitted.toolsListId && w.message.result?.tools?.some(t => t.name === tool)), 'prompt requires completed native tool discovery');
  }
  const calls = obs.wire.filter(w => w.direction === 'to-server' && w.message.method === 'tools/call');
  if (['deny', 'cancel'].includes(action)) {
    assert.equal(calls.length, 0, 'refused tool reached server');
    if (client === 'vscode') assert.ok(typeof obs.receipt.refusal === 'string' && obs.receipt.refusal.length, 'missing native refusal');
  }
  else {
    assert.deepEqual(calls.map(w => w.message.params.name), obs.request.case === 'block' ? ['attack', 'echo'] : nonces.map(() => tool));
    assert.deepEqual(calls.map(w => w.message.params.arguments?.text), obs.request.case === 'block' ? [obs.request.text, obs.request.text] : nonces, 'wrong consent arguments reached server');
    const results = client === 'vscode' ? obs.receipt.results : obs.receipt.responses;
    const echoes = (obs.request.case === 'block' ? results.slice(-1) : results).map((result, i) => {
      const content = result.content;
      return assertEcho(typeof content === 'string' ? [{ type: 'text', text: content }] : content, { text: nonces[i], version: obs.request.version });
    });
    assert.equal(echoes.length, nonces.length);
    if (obs.request.case === 'one-shot') assert.equal(echoes[0].pid, echoes[1].pid, 'one-shot check must stay in the same native session');
    if (client === 'claude-code' && ['always', 'persisted'].includes(action)) {
      const name = obs.receipt.gateway.flatMap(g => g.data?.tools ?? []).find(t => t.name.endsWith('__echo'))?.name;
      assert.ok(name); assert.deepEqual(obs.clientSettings?.permissions?.allow, [name], 'persistent grant must cover exactly echo');
    }
  }
}

export function validateReport(report, client, pins, hashes, evidence, artifact) {
  const expected = report.suite === 'trust' ? trustCases : report.suite === 'approvals' ? approvalCases : ['install-and-native-echo', 'enable-and-native-block-recovery', 'warn-and-forward', 'cancel-and-recover',
    ...(client === 'vscode' ? ['restart-without-cached-result'] : []), 'update-preserves-wrap-and-settings', 'schema-drift-and-recovery', 'disable-restores-launch-and-remove-preserves-settings'];
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.client, client); assert.equal(report.clientVersion, client === 'vscode' ? pins.vscode.version : pins.claudeCode);
  assert.equal(report.cliVersion, artifact?.version ?? pins.mcpm); assert.equal(report.node, 'v' + pins.node.version);
  if (artifact) assert.deepEqual(report.cliArtifact, artifact, 'guest CLI artifact differs from host');
  assert.equal(report.platform, 'darwin'); assert.equal(report.arch, 'arm64');
  assertGuestBoundary(report.boundary); assert.deepEqual(report.hashes, hashes, 'guest payload differs from host');
  assert.deepEqual(report.cases.map(c => c.id), expected, 'incomplete native matrix');
  assert.ok(report.cases.every(c => c.status === 'pass'));
  assert.deepEqual(report.counts, { pass: expected.length, fail: 0 });
  const references = report.cases.flatMap(c => { assert.ok(Array.isArray(c.evidence) && c.evidence.length > 0, 'missing case evidence'); return c.evidence; });
  assert.equal(new Set(references).size, references.length, 'case evidence was overwritten');
  assert.deepEqual(references.sort(), Object.keys(evidence).filter(f => f !== 'report.json').sort(), 'incomplete case evidence export');
  if (report.suite === 'trust') {
    const plans = client === 'vscode'
      ? [['trust-workspace-deny'], ['trust-server-deny'], ['trust-server-allow', 'trust-server-persisted'], ['trust-definition-deny', 'trust-definition-allow']]
      : [['trust-workspace-deny'], ['trust-server-deny'], ['trust-server-allow', 'trust-server-persisted'], ['trust-definition-change']];
    const nonces = new Set();
    report.cases.forEach((row, i) => {
      assert.equal(row.evidence.length, plans[i].length, 'incomplete trust observations');
      row.evidence.forEach((file, j) => {
        const obs = evidence[file]; assert.equal(obs.request.case, plans[i][j]); assertTrustObservation(obs, client);
        assert.ok(obs.request.text && !nonces.has(obs.request.text), 'reused trust arguments'); nonces.add(obs.request.text);
      });
    });
    const persisted = evidence[report.cases[2].evidence[1]];
    assert.deepEqual(persisted.receipt.fixtureTrust, [], 'persisted trust prompted again');
    if (client === 'vscode') assert.equal(report.cases.flatMap(row => row.evidence).flatMap(file => evidence[file].receipt.fixtureTrust).filter(d => d.phase === 'tool-policy').length, 1, 'global tool policy must be confirmed exactly once and recorded separately');
    const first = evidence[report.cases[2].evidence[0]];
    const values = [first, persisted].map(obs => {
      const result = client === 'vscode' ? obs.receipt.results.at(-1) : obs.receipt.responses.at(-1);
      return assertEcho(typeof result.content === 'string' ? [{ type: 'text', text: result.content }] : result.content, { text: obs.request.text, version: obs.request.version });
    });
    assert.notEqual(values[0].pid, values[1].pid, 'restart reused peer process');
  } else if (report.suite === 'approvals') {
    const plans = [[['allow', 'echo']], [['deny', 'echo'], ['cancel', 'echo']],
      [['always', 'echo'], ['persisted', 'echo'], ['deny', 'warn']], [['allow', 'attack']]];
    const nonces = new Set();
    report.cases.forEach((row, i) => {
      assert.equal(row.evidence.length, plans[i].length, 'incomplete approval observations');
      row.evidence.forEach((file, j) => {
        const obs = evidence[file]; assertConsentObservation(obs, client, ...plans[i][j]);
        if (i === 0) assert.equal(obs.request.case, 'one-shot', 'one-shot requires two calls within one client session');
        assert.ok(obs.request.text && !nonces.has(obs.request.text), 'reused consent arguments'); nonces.add(obs.request.text);
      });
    });
    const rows = report.cases[2].evidence.slice(0, 2).map(file => evidence[file]);
    const echoes = rows.map(obs => {
      const content = client === 'vscode' ? obs.receipt.results.at(-1).content : obs.receipt.responses.at(-1).content;
      return assertEcho(typeof content === 'string' ? [{ type: 'text', text: content }] : content, { text: obs.request.text, version: obs.request.version });
    });
    assert.notEqual(echoes[0].pid, echoes[1].pid, 'restart reused peer process');
    const blocked = evidence[report.cases[3].evidence[0]];
    assert.match(JSON.stringify(blocked.receipt), /BLOCKED by mcpm-guard/);
    assert.ok(blocked.events.some(e => e.action === 'block'), 'missing guard block event');
  }
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
