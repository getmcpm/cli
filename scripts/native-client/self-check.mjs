import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtureMetadata, serverName } from './fixture-registry.mjs';
import { assertEcho, assertNativeWire, assertGuestBoundary, assertConsentObservation, assertTrustObservation, trustCases, checkPayload, cliArtifact, evidenceFiles, validateReport } from './checks.mjs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { exchange } from '../protocol-sandbox/harness.mjs';
import { gateway } from './gateway.mjs';
import { fixtureApproval, fixtureInput, fixtureInputPrompt, fixtureInputValue } from './approval.mjs';
import { command } from './command.mjs';
import { runInNewContext } from 'node:vm';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { consentButton, consentDialogs, fixtureGrantTarget } from './consent-vscode.mjs';
import { TerminalScreen } from './terminal.mjs';
import { claudeConsent, claudeStartup, interactiveClaude, terminalChoices } from './consent-claude.mjs';
import { vscodeTrustButton } from './trust-vscode.mjs';
import { claudeProjectTrust, interactiveClaudeTrust } from './trust-claude.mjs';

test('macOS PTY driver uses the visible choice and exits after success or pre-dispatch refusal', { skip: process.platform !== 'darwin', timeout: 30000 }, async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-consent-pty-');
  try {
    const script = `${work}/mock.mjs`;
    await writeFile(script, `import fs from 'node:fs';
const [work,action]=process.argv.slice(2);process.stdin.setRawMode(true);let input='';let count=0;let done=false;
let trusting=false,moving=false,submitted=false;process.stdout.write('\\x1b[2J\\x1b[HAccessing workspace:\\r\\n'+work+'\\r\\nQuick safety check:\\r\\n❯ No, exit\\r\\n  Yes, I trust this folder\\r\\n');\nconst prompt=()=>process.stdout.write('\\x1b[2J\\x1b[Hio.github.getmcpm/native-fixture — echo Tool:\\r\\ntext: nonce'+(action==='one-shot'?'-'+(count+1):'')+'\\r\\nDo you want to proceed?\\r\\n  1. No\\r\\n❯ 2. Yes\\r\\n');
process.stdin.on('data',b=>{if(!trusting){if(b.toString()==='\\x1b[B'){if(moving)throw Error('navigation repeated before redraw');moving=true;process.stdout.write('\\r\\nRedrawing selection...');setTimeout(()=>process.stdout.write('\\x1b[2J\\x1b[HAccessing workspace:\\r\\n'+work+'\\r\\nQuick safety check:\\r\\n  No, exit\\r\\n❯ Yes, I trust this folder\\r\\n'),250);return;}if(b.toString()==='\\r'){trusting=true;fs.writeFileSync(work+'/wire.jsonl',[{pid:process.pid,direction:'to-server',message:{id:7,method:'tools/list'}},{pid:process.pid,direction:'from-server',message:{id:7,result:{tools:[{name:'echo'}]}}}].map(x=>JSON.stringify(x)+'\\n').join(''));process.stdout.write('\\x1b[2J\\x1b[HClaude fixture ready\\r\\n❯ \\r\\n');return;}throw Error('navigation and confirmation must be separate input events');}if(!submitted){input+=b.toString();if(!input.endsWith('\\r'))process.stdout.write('\\x1b[2J\\x1b[H❯ '+input+'\\r\\n');if(input.endsWith('\\r')){if(!input.startsWith('Run the native fixture '))throw Error('missing typed prompt');submitted=true;input='';prompt();}return;}input+=b.toString();if(!done&&(input.includes('\\r')||input.includes('\\x1b'))){count++;fs.appendFileSync(work+'/selected',input);input='';
if(action==='allow'||action==='one-shot'){fs.writeFileSync(work+'/result',String(count));if(action==='one-shot'&&count===1){prompt();return;}done=true;process.stdout.write('\\x1b[2J\\x1b[HSynthetic gateway observed the native tool result.\\r\\n❯ \\r\\n');}
else {done=true;process.stdout.write('\\x1b[2J\\x1b[HInterrupted. What should Claude do instead?\\r\\n❯ \\r\\n');}}
else if(done){if(input.includes('/exit\\r'))process.exit(0);if(input==='/exit')process.stdout.write('\\x1b[2J\\x1b[H❯ /exit\\r\\n');}});`);
    for (const action of ['allow', 'deny', 'cancel', 'one-shot']) {
      for (const name of ['result', 'selected']) await rm(`${work}/${name}`, { force: true });
      const model = { get results() { try { return Array(Number(readFileSync(`${work}/result`, 'utf8'))).fill({}); } catch { return []; } } };
      const result = await interactiveClaude(process.execPath, [script, work, action],
        { PATH: process.env.PATH, HOME: work, ANTHROPIC_BASE_URL: 'http://127.0.0.1:1', ANTHROPIC_API_KEY: 'synthetic-native-fixture-key' }, work, work,
        { case: action === 'one-shot' ? action : 'echo', text: 'nonce', consent: { action: action === 'one-shot' ? 'allow' : action, tool: 'echo' } }, model);
      assert.equal(result.status, 0, result.stdout + result.stderr + (result.failure ?? '')); assert.equal(result.exiting, true); assert.equal(result.ptyVerified, true);
      assert.match(result.submission.prompt, /^Run the native fixture /); assert.equal(result.submission.toolsListId, 7);
      assert.equal(result.decisions.length, action === 'one-shot' ? 2 : 1); assert.equal(result.decisions[0].action, action === 'one-shot' ? 'allow' : action);
      assert.equal(await readFile(`${work}/selected`, 'utf8'), action === 'one-shot' ? '2\r2\r' : action === 'cancel' ? '\x1b' : action === 'deny' ? '1\r' : '2\r');
    }
  } finally { await rm(work, { recursive: true, force: true }); }
});

test('PTY bridge reports signal termination as failure', { skip: process.platform !== 'darwin' }, async () => {
  const result = await command('/usr/bin/expect', ['-f', new URL('./pty.tcl', import.meta.url).pathname, '--', '/bin/sh', '-c', 'kill -TERM $$']);
  assert.equal(result.status, 125); assert.match(result.stdout, /native-fixture PTY verified/);
});

test('trust PTY driver selects numbered server refusal before confirming', { skip: process.platform !== 'darwin', timeout: 10000 }, async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-trust-pty-');
  try {
    const script = `${work}/mock.mjs`;
    await writeFile(script, `#!${process.execPath}
process.stdin.setRawMode(true); let input = '', denied = false;
process.stdout.write('\\x1b[2J\\x1b[HNew MCP server found in this project:\\r\\nio.github.getmcpm/native-fixture\\r\\n❯ 1. Use this MCP server\\r\\n  2. Use this and all future MCP servers in this project\\r\\n  3. Continue without using this MCP server\\r\\n');
process.stdin.on('data', bytes => {
  input += bytes.toString();
  if (!denied && input.includes('\\r')) {
    if (input !== '3\\r') throw Error('wrong server trust choice: ' + JSON.stringify(input));
    denied = true; input = ''; process.stdout.write('\\x1b[2J\\x1b[H❯ \\r\\n');
  } else if (denied && input === '/exit') process.stdout.write('\\x1b[2J\\x1b[H❯ /exit\\r\\n');
  else if (denied && input === '/exit\\r') process.exit(0);
});`, { mode: 0o755 });
    const result = await interactiveClaudeTrust(script,
      { PATH: process.env.PATH, HOME: work, ANTHROPIC_BASE_URL: 'http://127.0.0.1:1', ANTHROPIC_API_KEY: 'synthetic-native-fixture-key' }, work, work, work,
      { trust: { workspace: 'persisted', server: 'deny' } }, { results: [] });
    assert.equal(result.status, 0, result.stdout + result.stderr + (result.failure ?? ''));
    assert.equal(result.exiting, true); assert.equal(result.trustDecisions[0].key, '3');
    assert.deepEqual(result.toolDecisions, []);
  } finally { await rm(work, { recursive: true, force: true }); }
});

test('native consent selectors accept only the current fixture and explicit narrow decision', () => {
  const dialog = { text: 'Run `echo`\nnative-fixture: Synthetic compatibility fixture.', buttons: ['Yes', 'Cancel'] };
  assert.equal(consentButton(dialog, { action: 'allow', tool: 'echo' }), 'Yes');
  assert.equal(consentButton({ ...dialog, text: 'Cancel\nYes\nRun echo\nnative-fixture: Synthetic compatibility fixture.' }, { action: 'allow', tool: 'echo' }), 'Yes');
  assert.equal(consentButton(dialog, { action: 'deny', tool: 'echo' }), 'Cancel');
  assert.equal(consentButton(dialog, { action: 'cancel', tool: 'echo' }), 'Cancel');
  assert.equal(consentButton(dialog, { action: 'persisted', tool: 'echo' }), undefined);
  for (const text of ['Run `warn`\nnative-fixture: Synthetic compatibility fixture.', 'Run `echo`\nunrelated', dialog.text + '\nSign in to account', 'Enable global auto approve?']) {
    assert.equal(consentButton({ ...dialog, text }, { action: 'allow', tool: 'echo' }), undefined);
  }
  const screen = 'io.github.getmcpm/native-fixture — echo Tool:\ntext: nonce\nDo you want to proceed?\n  1. No\n❯ 2. Yes\n  3. Yes, and don\'t ask again for io.github.getmcpm/native-fixture — echo commands in /opt/mcpm-native';
  const request = { text: 'nonce', consent: { action: 'allow', tool: 'echo' } };
  assert.equal(claudeConsent(screen, request).key, '2');
  const native = 'Tool use\nio.github.getmcpm/native-fixture — Echo Tool: (MCP)\ntext: nonce\nAbout the io.github.getmcpm/native-fixture — Echo Tool:\n│ native-fixture: Synthetic compatibility fixture.\nDo you want to proceed?\n❯ 1. Yes\n  2. Yes, and don\'t ask again for io.github.getmcpm/native-fixture — Echo commands in /opt/mcpm-native\n  3. No';
  assert.equal(claudeConsent(native, request).key, '1');
  assert.equal(claudeConsent(native, { ...request, consent: { action: 'always', tool: 'echo' } }).key, '2');
  assert.equal(claudeConsent(screen, { ...request, consent: { action: 'deny', tool: 'echo' } }).key, '1');
  assert.equal(claudeConsent(screen, { ...request, consent: { action: 'always', tool: 'echo' } }).key, '3');
  assert.equal(claudeConsent(screen, { ...request, consent: { action: 'cancel', tool: 'echo' } }).key, '\x1b');
  assert.throws(() => claudeConsent(screen, { ...request, consent: { action: 'persisted', tool: 'echo' } }), /prompted again/);
  assert.equal(claudeConsent(screen, { ...request, text: 'different' }), undefined);
  assert.equal(claudeConsent(screen.replaceAll('native-fixture', 'unrelated'), request), undefined);
  assert.equal(claudeConsent(screen + '\nBash command\nunexpected command\nDo you want to proceed?\n❯ 1. Yes\n 2. No', request), undefined);
  assert.equal(claudeConsent(screen.replace('Do you want to proceed?', 'Tool completed'), request), undefined);
  const startup = 'Accessing workspace:\n/opt/mcpm-native\nQuick safety check:\n  Yes, I trust this folder\n❯ No, exit';
  assert.equal(claudeStartup(startup, '/opt/mcpm-native').key, '\x1b[A');
  assert.equal(claudeStartup(startup, '/elsewhere'), undefined);
  assert.equal(claudeStartup('Detected a custom API key in your environment\nANTHROPIC_API_KEY: synthetic\nDo you want to use this API key?\n  Yes\n❯ No (recommended)', '/opt/mcpm-native').key, '\x1b[A');
  assert.deepEqual(terminalChoices('❯ 1. Yes, and don\'t ask again\n       for this exact tool\n  2. No'), [{ key: '1', label: "Yes, and don't ask again for this exact tool" }, { key: '2', label: 'No' }]);
});

test('native trust selectors target only project workspace and fixture-server decisions', () => {
  const workspace = '/opt/mcpm-native/trust-vscode-approved';
  const author = { text: 'Do you trust the authors of the files in this folder?', buttons: ["No, I don't trust the authors", 'Trust Folder & Continue'] };
  assert.equal(vscodeTrustButton(author, { workspace: 'allow' }, workspace), 'Trust Folder & Continue');
  assert.equal(vscodeTrustButton(author, { workspace: 'deny' }, workspace), "No, I don't trust the authors");
  assert.equal(vscodeTrustButton({ ...author, buttons: ['Manage', 'Cancel'] }, { workspace: 'deny' }, workspace), 'Cancel');
  assert.equal(vscodeTrustButton({ text: 'Enable global auto approve?', buttons: ['Disable', 'Enable'] }, {}, workspace), 'Enable');
  const server = { text: 'Trust and run MCP server native-fixture?\nThis MCP server definition is defined in your workspace files.', buttons: ['Do not trust', 'Trust'] };
  assert.equal(vscodeTrustButton(server, { server: 'allow' }, workspace), 'Trust');
  assert.equal(vscodeTrustButton(server, { server: 'deny' }, workspace), 'Do not trust');
  assert.throws(() => vscodeTrustButton(server, { server: 'persisted' }, workspace), /prompted again/);
  assert.equal(vscodeTrustButton({ text: 'Sign in to account', buttons: ['Continue'] }, { workspace: 'allow' }, workspace), undefined);
  const claudeWorkspace = `Accessing workspace:\n${workspace}\nQuick safety check:\n❯ No, exit\n  Yes, I trust this folder`;
  assert.equal(claudeProjectTrust(claudeWorkspace, { trust: { workspace: 'allow' } }, workspace).label, 'Yes, I trust this folder');
  assert.equal(claudeProjectTrust(claudeWorkspace, { trust: { workspace: 'deny' } }, workspace).label, 'No, exit');
  const claudeServer = `New MCP server found in this project:\n${serverName}\n❯ 1. Use this MCP server\n  2. Use this and all future MCP servers in this project\n  3. Continue without using this MCP server`;
  assert.equal(claudeProjectTrust(claudeServer, { trust: { server: 'allow' } }, workspace).label, 'Use this MCP server');
  assert.equal(claudeProjectTrust(claudeServer, { trust: { server: 'deny' } }, workspace).label, 'Continue without using this MCP server');
  assert.throws(() => claudeProjectTrust(claudeServer, { trust: { server: 'persisted' } }, workspace), /prompted again/);
  const apiKey = 'Detected a custom API key in your environment\nANTHROPIC_API_KEY: synthetic\nDo you want to use this API key?\n  Yes\n❯ No (recommended)';
  assert.equal(claudeProjectTrust(apiKey, { trust: { workspace: 'persisted' } }, workspace).phase, 'api-key');
});

test('VS Code grant target expands only its exact server and selects only the echo child', () => {
  const rect = { x: 10, y: 20, width: 8, height: 10 };
  const checkbox = checked => ({ getAttribute: () => checked, getBoundingClientRect: () => rect });
  const row = (text, level, checked = 'false') => ({ innerText: level === 2 ? text + 'without approval' : text, getAttribute: name => name === 'aria-level' ? String(level) : text + ', without approval', querySelector: selector => selector === '.monaco-tl-twistie' ? { classList: { contains: () => true }, getBoundingClientRect: () => rect } : checkbox(checked) });
  let rows = [row('native-fixture', 1), row('other', 1), row('echo', 2)];
  const widget = { offsetWidth: 100, innerText: 'fixture tools', querySelector: () => ({ placeholder: 'Configure global tool approvals' }), querySelectorAll: () => rows };
  const target = () => runInNewContext(`(${fixtureGrantTarget.toString()})('echo')`, { document: { querySelectorAll: () => [widget] } });
  assert.equal(target().state, 'expand'); assert.equal(target().point.x, 14);
  rows.splice(1, 0, row('warn', 2), row('echo', 2));
  assert.equal(target().state, 'clicked'); assert.equal(target().tool, 'echo'); assert.equal(target().checked, 'false');
  rows[2] = row('echo', 2, 'true'); assert.equal(target().state, 'checked');
  rows[0] = row('unrelated-native-fixture', 1); assert.equal(target(), undefined);
});

test('VS Code consent observer retries a transient startup fetch timeout', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-consent-observer-');
  const controller = new AbortController(), original = globalThis.fetch, log = [];
  let attempts = 0;
  try {
    await writeFile(`${work}/consent-intent.json`, JSON.stringify({ text: 'nonce', tool: 'echo', action: 'allow' }));
    globalThis.fetch = async () => { if (++attempts === 2) controller.abort(); throw new DOMException('The operation was aborted due to timeout', 'TimeoutError'); };
    await consentDialogs(work, log, controller.signal);
    assert.equal(attempts, 2); assert.deepEqual(log, []);
  } finally { globalThis.fetch = original; await rm(work, { recursive: true, force: true }); }
});

test('VS Code shutdown connection error events never become empty approval decisions', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-consent-socket-');
  const controller = new AbortController(), originalFetch = globalThis.fetch, originalSocket = globalThis.WebSocket, log = [];
  let attempts = 0;
  try {
    await writeFile(`${work}/consent-intent.json`, JSON.stringify({ text: 'nonce', tool: 'echo', action: 'persisted' }));
    globalThis.fetch = async () => { if (++attempts === 2) controller.abort(); return { json: async () => [{ type: 'page', url: 'vscode-file:fixture', webSocketDebuggerUrl: 'ws://fixture' }] }; };
    globalThis.WebSocket = class {
      addEventListener(type, listener) { if (type === 'error') setImmediate(() => listener(new Event('error'))); }
      close() {}
    };
    await consentDialogs(work, log, controller.signal);
    assert.equal(attempts, 2); assert.deepEqual(log, []);
    globalThis.fetch = async () => { throw { message: 'unexpected fixture failure' }; };
    await assert.rejects(consentDialogs(work, log, new AbortController().signal), e => e.message === 'unexpected fixture failure');
    assert.deepEqual(log, [{ error: 'unexpected fixture failure' }]);
  } finally { globalThis.fetch = originalFetch; globalThis.WebSocket = originalSocket; await rm(work, { recursive: true, force: true }); }
});

test('terminal screen tracks chunked cursor movement, erasure and scrolling without stale prompts', () => {
  const screen = new TerminalScreen(40, 4);
  screen.feed('old permission\r\ncurrent');
  screen.feed('\x1b[1A\r\x1b[2Knew permission');
  assert.equal(screen.text, 'new permission\ncurrent');
  screen.feed('\x1b[2'); screen.feed('J\x1b[Hfresh');
  assert.equal(screen.text, 'fresh'); assert.ok(!screen.text.includes('permission'));
  screen.feed('\x1b]0;hidden title\x07\r\nsecond\r\nthird\r\nfourth\r\nfifth');
  assert.equal(screen.text, 'second\nthird\nfourth\nfifth');
  const margin = new TerminalScreen(5, 4); margin.feed('12345\r\nnext'); assert.equal(margin.text, '12345\nnext');
  const wrap = new TerminalScreen(5, 4); wrap.feed('123456'); assert.equal(wrap.text, '12345\n6');
});

test('consent proof rejects dispatch before permission, silent bypass, mismatched arguments and deadlines', () => {
  const obs = { request: { case: 'echo', text: 'nonce', version: '1.0.0', consent: { action: 'allow', tool: 'echo' } }, execution: { status: 0, timedOut: false },
    receipt: { status: 'pass', fixtureApprovals: [{ action: 'allow', tool: 'echo', text: 'nonce', callsBeforeDecision: 0 }], results: [{ content: [{ type: 'text', text: '{"text":"nonce","version":"1.0.0","marker":"retained","pid":1}' }] }] },
    clientSettings: { 'chat.tools.global.autoApprove': false, 'chat.permissions.default': 'default', 'window.dialogStyle': 'custom' },
    wire: [{ direction: 'to-server', message: { method: 'initialize', params: { clientInfo: { name: 'Visual Studio Code' } } } },
      { direction: 'to-server', message: { method: 'tools/call', params: { name: 'echo', arguments: { text: 'nonce' } } } }] };
  assertConsentObservation(obs, 'vscode', 'allow', 'echo');
  const changed = structuredClone(obs); changed.receipt.fixtureApprovals[0].callsBeforeDecision = 1;
  assert.throws(() => assertConsentObservation(changed, 'vscode', 'allow', 'echo'), /dispatched before permission/);
  for (const change of [{ execution: { status: 0, timedOut: true } }, { receipt: { status: 'pass', fixtureApprovals: [] } },
    { clientSettings: { 'chat.tools.global.autoApprove': true } }]) assert.throws(() => assertConsentObservation({ ...obs, ...change }, 'vscode', 'allow', 'echo'));
  const denied = structuredClone(obs); denied.request.consent.action = 'deny'; denied.receipt.fixtureApprovals[0].action = 'deny';
  assert.throws(() => assertConsentObservation(denied, 'vscode', 'deny', 'echo'), /refused tool reached server/);
  denied.wire.pop(); denied.receipt.refusal = 'User cancelled tool invocation'; assertConsentObservation(denied, 'vscode', 'deny', 'echo');
  const noRefusal = structuredClone(denied); delete noRefusal.receipt.refusal;
  assert.throws(() => assertConsentObservation(noRefusal, 'vscode', 'deny', 'echo'), /refusal/);
  const grant = structuredClone(obs); grant.request.consent.action = 'always'; grant.receipt.fixtureApprovals[0].action = 'always';
  assert.throws(() => assertConsentObservation(grant, 'vscode', 'always', 'echo'), /grant/);
  grant.receipt.fixtureApprovals[0].selection = { before: { checked: 'false', tool: 'echo' }, after: { checked: 'true', tool: 'echo' } };
  assertConsentObservation(grant, 'vscode', 'always', 'echo');
  grant.receipt.fixtureApprovals[0].selection.before.checked = 'true';
  assert.throws(() => assertConsentObservation(grant, 'vscode', 'always', 'echo'), /unchecked/);
  const claude = structuredClone(obs); claude.wire[0].message.params.clientInfo.name = 'claude';
  claude.receipt.permissionMode = 'default'; claude.receipt.responses = claude.receipt.results;
  Object.assign(claude.execution, { ptyVerified: true, exiting: true, command: '/opt/mcpm-native/node_modules/.bin/claude', args: ['--permission-mode', 'default'], submission: { prompt: 'Run the native fixture echo check with text nonce.', toolsListId: 7, peerPid: 2, confirmed: true } });
  claude.wire.push({ pid: 2, direction: 'to-server', message: { id: 7, method: 'tools/list' } }, { pid: 2, direction: 'from-server', message: { id: 7, result: { tools: [{ name: 'echo' }] } } });
  assertConsentObservation(claude, 'claude-code', 'allow', 'echo');
  const premature = structuredClone(claude); premature.wire.pop();
  assert.throws(() => assertConsentObservation(premature, 'claude-code', 'allow', 'echo'), /discovery/);
  const wrongPrompt = structuredClone(claude); wrongPrompt.execution.submission.prompt = 'other';
  assert.throws(() => assertConsentObservation(wrongPrompt, 'claude-code', 'allow', 'echo'), /interactive prompt/);
  claude.execution.args.push('--dangerously-skip-permissions');
  assert.throws(() => assertConsentObservation(claude, 'claude-code', 'allow', 'echo'), /launch/);
  const wrong = structuredClone(obs); wrong.wire[1].message.params.arguments.text = 'other';
  assert.throws(() => assertConsentObservation(wrong, 'vscode', 'allow', 'echo'), /wrong consent arguments/);
});

test('trust proof rejects launch before trust and requires persisted restart evidence', () => {
  let pid = 10;
  const observation = (caseName, workspaceDecision, serverDecision, marker = 'retained') => {
    const workspace = `/opt/mcpm-native/trust-vscode-${['trust-workspace-deny', 'trust-server-deny'].includes(caseName) ? caseName.slice(6) : 'approved'}`;
    const configPath = caseName === 'trust-workspace-deny' ? `${workspace}/.vscode/mcp.json` : `${workspace}/.cursor/mcp.json`;
    const denied = workspaceDecision === 'deny' || serverDecision === 'deny';
    const decisions = [
      ...(workspaceDecision === 'persisted' ? [] : [{ phase: 'workspace', button: workspaceDecision === 'allow' ? 'Trust Folder & Continue' : "No, I don't trust the authors" }]),
      ...(workspaceDecision === 'deny' || serverDecision === 'persisted' ? [] : [{ phase: 'server', button: serverDecision === 'deny' ? 'Do not trust' : 'Trust' }]),
    ];
    const text = `native-${caseName}`, currentPid = pid++;
    const config = { [caseName === 'trust-workspace-deny' ? 'servers' : 'mcpServers']: { [serverName]: {
      ...(caseName === 'trust-workspace-deny' ? { type: 'stdio' } : {}), command: '/opt/mcpm-native/bin/npx',
      args: ['-y', '@mcpm/native-fixture@1.0.0', '--native-marker', marker],
    } } };
    return { request: { case: caseName, text, version: '1.0.0', trust: { workspace: workspaceDecision, server: serverDecision, workspacePath: workspace, configPath } },
      execution: { status: 0, timedOut: false }, receipt: { status: 'pass', workspaceTrusted: workspaceDecision !== 'deny', workspace: [workspace], fixtureTrust: decisions, results: denied ? [] : [{ content: [{ type: 'text', text: JSON.stringify({ text, version: '1.0.0', marker, pid: currentPid }) }] }] },
      configPath, config, configText: JSON.stringify(config), clientSettings: { 'chat.tools.global.autoApprove': true, 'chat.mcp.autostart': 'never', 'chat.mcp.discovery.enabled': { 'cursor-workspace': true } },
      wire: denied ? [] : [{ direction: 'to-server', message: { method: 'initialize', params: { clientInfo: { name: 'Visual Studio Code' } } } },
        { direction: 'to-server', message: { method: 'tools/call', params: { name: 'echo', arguments: { text } } } }] };
  };
  const observations = [observation('trust-workspace-deny', 'deny', 'deny'), observation('trust-server-deny', 'allow', 'deny'),
    observation('trust-server-allow', 'allow', 'allow'), observation('trust-server-persisted', 'persisted', 'persisted'),
    observation('trust-definition-deny', 'persisted', 'deny', 'changed'), observation('trust-definition-allow', 'persisted', 'allow', 'changed')];
  observations[0].receipt.fixtureTrust.push({ phase: 'tool-policy', button: 'Enable' });
  observations.forEach(obs => assertTrustObservation(obs, 'vscode'));
  const premature = structuredClone(observations[1]); premature.wire.push({ direction: 'to-server', message: { method: 'initialize', params: { clientInfo: { name: 'Visual Studio Code' } } } });
  assert.throws(() => assertTrustObservation(premature, 'vscode'), /untrusted project server started/);
  for (const mutate of [
    obs => { obs.request.trust.workspace = 'deny'; },
    obs => { obs.config = {}; obs.configText = '{}'; },
    obs => { obs.request.trust.workspacePath += '-different'; },
    obs => { obs.receipt.workspaceTrusted = false; },
    obs => { obs.receipt.fixtureTrust[0].button = "No, I don't trust the authors"; },
    obs => { obs.clientSettings['chat.mcp.discovery.enabled'] = {}; },
  ]) {
    const wrong = structuredClone(observations[1]); mutate(wrong);
    assert.throws(() => assertTrustObservation(wrong, 'vscode'));
  }
  const files = Object.fromEntries(observations.map((obs, i) => [`trust-${i}.json`, obs]));
  const groups = [[0], [1], [2, 3], [4, 5]];
  const pins = { vscode: { version: '1.141.0' }, claudeCode: '2.1.296', mcpm: '0.47.1', node: { version: '26.11.1' } }, hashes = { 'fixture.mjs': 'sha256-fixture' };
  const report = { schemaVersion: 1, suite: 'trust', client: 'vscode', clientVersion: pins.vscode.version, cliVersion: pins.mcpm, node: 'v' + pins.node.version,
    platform: 'darwin', arch: 'arm64', hashes, boundary: { model: 'VirtualMac2,1', mounts: '', pfStatus: 'Status: Enabled', pfRules: 'block drop all' },
    cases: trustCases.map((id, i) => ({ id, status: 'pass', evidence: groups[i].map(n => `trust-${n}.json`) })), counts: { pass: 4, fail: 0 } };
  validateReport(report, 'vscode', pins, hashes, files);
  files['trust-3.json'].receipt.fixtureTrust.push({ phase: 'server', button: 'Trust' });
  assert.throws(() => validateReport(report, 'vscode', pins, hashes, files), /persisted|unexpected/);
  const claude = structuredClone(observations[2]);
  const workspace = '/opt/mcpm-native/trust-claude-code-approved';
  claude.request.trust.workspacePath = workspace;
  claude.configPath = claude.request.trust.configPath = `${workspace}/.mcp.json`;
  claude.receipt.permissionMode = 'default'; claude.receipt.responses = claude.receipt.results;
  claude.receipt.fixtureApprovals = [{ label: 'Yes' }];
  claude.clientSettings = { enabledMcpjsonServers: [serverName] };
  Object.assign(claude.execution, { ptyVerified: true, exiting: true, command: '/opt/mcpm-native/node_modules/.bin/claude', args: ['--permission-mode', 'default'], cwd: workspace,
    submission: { prompt: `Run the native fixture ${claude.request.case} check with text ${claude.request.text}.`, confirmed: true, peerPid: 10, toolsListId: 1 } });
  claude.wire[0].message.params.clientInfo.name = 'claude-code';
  claude.wire.push({ direction: 'to-server', pid: 10, message: { id: 1, method: 'tools/list' } });
  assertTrustObservation(claude, 'claude-code');
  for (const mutate of [
    obs => { obs.clientSettings.enableAllProjectMcpServers = true; },
    obs => { obs.clientSettings.enabledMcpjsonServers.push('unrelated'); },
    obs => { obs.receipt.fixtureApprovals[0].label = "Yes, and don't ask again"; },
    obs => { obs.execution.ptyVerified = false; },
  ]) {
    const wrong = structuredClone(claude); mutate(wrong);
    assert.throws(() => assertTrustObservation(wrong, 'claude-code'));
  }
});

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
  assert.equal(fixtureInput({ text: fixtureInputPrompt, value: fixtureInputValue }), true);
  assert.equal(fixtureInput({ text: fixtureInputPrompt, value: 'different' }), false);
  assert.equal(fixtureInput({ text: 'Sign in to account ' + fixtureInputPrompt, value: fixtureInputValue }), false);
});
test('candidate identity binds archive, lock, version and every installed dist file', async () => {
  const root = await mkdtemp(tmpdir() + '/mcpm-candidate-');
  const entry = 'public fixture entry';
  try {
    await mkdir(`${root}/package/dist`, { recursive: true });
    await mkdir(`${root}/node_modules/@getmcpm/cli/dist`, { recursive: true });
    await writeFile(`${root}/package/dist/index.js`, entry);
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/index.js`, entry);
    await writeFile(`${root}/package/dist/chunk.js`, 'public lazy chunk');
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/chunk.js`, 'public lazy chunk');
    await writeFile(`${root}/package/package.json`, '{"name":"@getmcpm/cli","version":"0.15.0"}');
    await writeFile(`${root}/node_modules/@getmcpm/cli/package.json`, '{"name":"@getmcpm/cli","version":"0.15.0"}');
    execFileSync('/usr/bin/tar', ['-czf', `${root}/candidate.tgz`, '-C', root, 'package']);
    const tar = await readFile(`${root}/candidate.tgz`);
    const integrity = 'sha512-' + createHash('sha512').update(tar).digest('base64');
    await writeFile(`${root}/package.json`, '{"dependencies":{"@getmcpm/cli":"file:./candidate.tgz"}}');
    await writeFile(`${root}/package-lock.json`, JSON.stringify({ packages: { 'node_modules/@getmcpm/cli': { version: '0.15.0', resolved: 'file:candidate.tgz', integrity } } }));
    const artifact = await cliArtifact(root, true);
    assert.equal(artifact.kind, 'candidate'); assert.equal(artifact.version, '0.15.0'); assert.equal(artifact.integrity, integrity);
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/chunk.js`, 'changed lazy chunk');
    await assert.rejects(cliArtifact(root, true), /differs from archive/);
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/chunk.js`, 'public lazy chunk');
    assert.equal(artifact.filesSha256['dist/chunk.js'], createHash('sha256').update('public lazy chunk').digest('hex'));
    await rm(`${root}/node_modules/@getmcpm/cli/dist/chunk.js`);
    await assert.rejects(cliArtifact(root, true), /file set differs/);
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/chunk.js`, 'public lazy chunk');
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/extra.js`, 'extra');
    await assert.rejects(cliArtifact(root, true), /file set differs/);
    await rm(`${root}/node_modules/@getmcpm/cli/dist/extra.js`);
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/index.js`, 'changed');
    await assert.rejects(cliArtifact(root, true), /index.js differs/);
    await writeFile(`${root}/node_modules/@getmcpm/cli/dist/index.js`, entry);
    await writeFile(`${root}/candidate.tgz`, 'changed');
    await assert.rejects(cliArtifact(root, true), /integrity mismatch/);
    await truncate(`${root}/candidate.tgz`, 33 * 1024 * 1024);
    await assert.rejects(cliArtifact(root, true), /invalid candidate archive/);
  } finally { await rm(root, { recursive: true, force: true }); }
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
  const artifact = { kind: 'candidate', version: '0.15.0', sha256: 'synthetic' };
  const candidate = { ...report, cliVersion: artifact.version, cliArtifact: artifact };
  validateReport(candidate, 'vscode', pins, hashes, evidence, artifact);
  assert.throws(() => validateReport({ ...candidate, cliArtifact: {} }, 'vscode', pins, hashes, evidence, artifact), /CLI artifact differs/);
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
test('VS Code cancellation waits for its current wire call and fails when that call never starts', { timeout: 5000 }, async () => {
  const source = await readFile(new URL('./vscode-extension/tests.cjs', import.meta.url), 'utf8');
  for (const mode of ['delayed', 'missing', 'rejected']) {
    let receipt, startTimer, disposed = false, echoCalls = 0;
    const frame = id => ({ direction: 'to-server', message: { id, method: 'tools/call', params: { name: 'slow', arguments: { text: 'nonce' } } } });
    const wire = [frame('stale')];
    class CancellationTokenSource {
      token = { isCancellationRequested: false };
      cancel() { if (!this.token.isCancellationRequested) { this.token.isCancellationRequested = true; clearTimeout(startTimer); this.token.reject?.(Error('cancelled')); } }
      dispose() { disposed = true; }
    }
    const vscode = { version: '1.141.0', CancellationTokenSource,
      window: { activeTextEditor: { document: { uri: { fsPath: '/Users/admin/Library/Application Support/Code/User/mcp.json' } } } },
      commands: { executeCommand: () => Promise.resolve() },
      lm: { tools: [{ name: 'slow' }, { name: 'echo' }], invokeTool: (name, options, token) => {
        if (name === 'echo') { echoCalls++; return Promise.resolve({ content: [] }); }
        if (mode === 'rejected') return Promise.reject(Error('fixture launch failed'));
        return new Promise((resolve, reject) => {
          token.reject = reject;
          if (mode === 'delayed') startTimer = setTimeout(() => wire.push(frame('current')), 650);
        });
      } } };
    const fs = { existsSync: () => true, readFileSync: name => name.endsWith('request.json') ? '{"case":"cancel","text":"nonce"}' : wire.map(w => JSON.stringify(w) + '\n').join(''),
      writeFileSync: (name, content) => { receipt = JSON.parse(content); } };
    const exports = {};
    runInNewContext(source, {
      exports, __dirname: '/fixture/vscode-extension', console,
      setTimeout: (fn, delay) => delay === 45000 ? undefined : setTimeout(fn, delay === 300 || mode !== 'delayed' ? 0 : delay), clearTimeout,
      require: name => ({ vscode, 'node:fs': fs, 'node:path': path, 'node:assert/strict': assert })[name],
    });
    try {
      if (mode === 'delayed') {
        await exports.run();
        assert.equal(wire.at(-1).message.id, 'current', 'cancellation must not prevent the slow call reaching the peer');
        assert.equal(receipt.cancelledRequestId, 'current'); assert.equal(receipt.status, 'pass'); assert.equal(echoCalls, 1);
      } else {
        await assert.rejects(exports.run(), /slow call did not reach the peer/);
        assert.equal(receipt.status, 'fail'); assert.equal(echoCalls, 0);
      }
      assert.equal(disposed, true);
    } finally { clearTimeout(startTimer); }
  }
});
test('synthetic gateway emits a real tool-use round and accepts only its correlated results', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-gateway-');
  const g = await gateway(work, { case: 'echo', text: 'nonce' });
  try {
    const request = { model: 'synthetic', stream: false, tools: [{ name: 'mcp__native__echo' }], messages: [] };
    const response = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify(request) });
    const body = await response.json(); assert.equal(body.stop_reason, 'tool_use'); assert.equal(body.content[0].name, 'mcp__native__echo');
    assert.deepEqual(body.content[0].input, { text: 'nonce' });
    const title = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify({ ...request, tools: [], messages: [{ role: 'user', content: [{ type: 'text', text: '<session>\nRun the native fixture echo check with text nonce.\n</session>\n\nWrite the title in the predominant language of the session' }] }] }) });
    assert.equal((await title.json()).content[0].text, 'Native fixture check'); assert.equal(g.results.length, 0);
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
test('one-shot gateway issues two distinct arguments in one conversation before completion', async () => {
  const work = await mkdtemp(tmpdir() + '/mcpm-gateway-');
  const g = await gateway(work, { case: 'one-shot', text: 'nonce' });
  try {
    const request = { model: 'synthetic', stream: false, tools: [{ name: 'mcp__native__echo' }], messages: [] };
    for (let i = 1; i <= 2; i++) {
      const response = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify(request) });
      const body = await response.json();
      assert.equal(body.stop_reason, 'tool_use'); assert.equal(body.content[0].input.text, `nonce-${i}`);
      request.messages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: body.content[0].id, content: `result-${i}` }] });
    }
    const done = await fetch(g.url + '/v1/messages', { method: 'POST', body: JSON.stringify(request) });
    assert.equal((await done.json()).stop_reason, 'end_turn'); assert.equal(g.results.length, 2);
  } finally { await g.close(); await rm(work, { recursive: true, force: true }); }
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
