import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
import { checkPluginLifecycle } from './plugin-lifecycle-checks.mjs';

const runId = randomUUID(), wire = [], api = [], actions = [], probes = [];
const hash = b => createHash('sha256').update(b).digest('hex');
const report = { schemaVersion: 1, runId, status: 'incomplete', node: process.version, platform: process.platform, arch: process.arch, wire, api, actions, probes, sessions: [], inspections: [], limits: ['Executed hook command only; text skill activation, publisher authenticity and enforcement remain unknown', 'Inline local update, not marketplace/cache update', 'One measured Linux arm64 host version; other platforms and versions unknown'] };
let child, tripwire, failure;
const waiters = [];
let stdout = '', stderr = '';
const deadline = setTimeout(() => { failure = Error('probe deadline'); child?.kill('SIGKILL'); }, 90000);
function record(direction, message, nativePid = child?.pid) {
  const row = { sequence: wire.length, direction, nativePid, message }; wire.push(row);
  for (const waiter of [...waiters]) if (waiter.test(row)) { waiters.splice(waiters.indexOf(waiter), 1); clearTimeout(waiter.timer); waiter.resolve(row); }
}
function awaitRow(test, label) {
  const old = wire.find(test); if (old) return Promise.resolve(old);
  return new Promise((resolve, reject) => { const waiter = { test, resolve, timer: setTimeout(() => { waiters.splice(waiters.indexOf(waiter), 1); reject(Error(`timeout ${label}`)); }, 12000) }; waiters.push(waiter); });
}
function send(message) { record('to-native', message); child.stdin.write(JSON.stringify(message) + '\n'); }
async function request(request) {
  const request_id = randomUUID();
  const result = awaitRow(row => row.direction === 'from-native' && row.message.type === 'control_response' && row.message.response?.request_id === request_id, request.subtype);
  send({ type: 'control_request', request_id, request });
  const row = await result; assert.equal(row.message.response.subtype, 'success', JSON.stringify(row.message)); return row.message.response.response;
}
async function markers() {
  const text = await readFile('/work/markers.jsonl', 'utf8').catch(e => { if (e.code === 'ENOENT') return ''; throw e; });
  assert.ok(text.length < 1024 * 1024); return text.trim() ? text.trim().split('\n').map(JSON.parse) : [];
}
async function settings(enabled, blocker) {
  const value = { enabledPlugins: { 'mcpm-lifecycle@inline': enabled }, hooks: { UserPromptSubmit: [{ hooks: [{ type: 'command', command: `node /probe/marker.mjs ${blocker}`, timeout: 5 }] }] } };
  const bytes = JSON.stringify(value);
  await writeFile('/work/home/.claude/settings.json.tmp', bytes);
  await rename('/work/home/.claude/settings.json.tmp', '/work/home/.claude/settings.json');
  actions.push({ action: 'settings', enabled, blocker, text: bytes, sha256: hash(bytes), wireOffset: wire.length });
}
async function install(version) {
  const files = Object.fromEntries(await Promise.all(['.claude-plugin/plugin.json', 'hooks/hooks.json', 'skills/inert/SKILL.md'].map(async name => [name, await readFile(`/probe/plugin-lifecycle-fixtures/${version}/${name}`, 'utf8')])));
  for (const [name, bytes] of Object.entries(files)) { await writeFile(`/work/plugin/${name}.tmp`, bytes); await rename(`/work/plugin/${name}.tmp`, `/work/plugin/${name}`); actions.push({ action: 'replace-file', version, name, text: bytes, sha256: hash(bytes), wireOffset: wire.length }); }
  actions.push({ action: 'inline-update', version, files: Object.fromEntries(Object.entries(files).map(([name, bytes]) => [name, { sha256: hash(bytes), bytes: Buffer.byteLength(bytes) }])), wireOffset: wire.length });
}
async function prompt(phase) {
  const uuid = randomUUID(), nonce = `${runId}:${phase}:${uuid}`, before = (await markers()).length;
  const result = awaitRow(row => row.direction === 'from-native' && row.message.type === 'result' && (row.message.user_message_uuid === uuid || row.message.user_message_uuids?.includes(uuid)), phase);
  const completed = awaitRow(row => row.direction === 'from-native' && row.message.type === 'command_lifecycle' && row.message.command_uuid === uuid && row.message.state === 'completed', `${phase} completion`);
  send({ type: 'user', message: { role: 'user', content: nonce }, parent_tool_use_id: null, session_id: '', uuid });
  const frame = (await result).message;
  await completed;
  const rows = (await markers()).slice(before).filter(row => row.input.prompt === nonce);
  // Progress notifications can lag the blocked result. Join owned starts by ID;
  // do not advance to another action until every observed hook has completed.
  await awaitRow(() => {
    const sent = wire.find(row => row.direction === 'to-native' && row.message.uuid === uuid);
    const starts = wire.filter(row => row.sequence > sent.sequence && row.message.subtype === 'hook_started' && row.message.hook_event === 'UserPromptSubmit' && row.message.session_id === frame.session_id);
    return starts.length === rows.length && starts.every(start => wire.some(row => row.message.subtype === 'hook_response' && row.message.hook_id === start.message.hook_id));
  }, `${phase} hook notifications`);
  probes.push({ phase, uuid, nonce, frame, markers: rows, pid: child.pid });
  assert.equal(rows.filter(row => row.component.startsWith('blocker')).length, 1, 'independent blocking hook did not complete exactly once');
  assert.equal(frame.num_turns, 0, 'blocked probe entered model turn');
  assert.equal(api.length, 0, 'API attempt');
  return rows;
}
try {
  report.inputs = JSON.parse(await readFile('/probe/inputs.json', 'utf8'));
  const pins = JSON.parse(await readFile('/probe/plugin-lifecycle-pins.json', 'utf8'));
  assert.equal(process.platform, pins.platform); assert.equal(process.arch, pins.arch);
  assert.equal(hash(await readFile('/opt/claude')), pins.binarySha256);
  await mkdir('/work/home/.claude', { recursive: true });
  for (const dir of ['.claude-plugin', 'hooks', 'skills/inert']) await mkdir(`/work/plugin/${dir}`, { recursive: true });
  const onboarding = JSON.stringify({ hasCompletedOnboarding: true });
  await writeFile('/work/home/.claude.json', onboarding);
  actions.push({ action: 'onboarding-fixture', text: onboarding, sha256: hash(onboarding), wireOffset: wire.length });
  await install('v1'); await settings(true, 'blocker-file-enabled');
  tripwire = createServer((req, res) => { api.push({ method: req.method, url: req.url }); req.resume(); res.writeHead(503, { 'content-type': 'application/json' }); res.end('{"error":{"type":"fixture_api_forbidden","message":"No model calls allowed"}}'); });
  await new Promise(resolve => tripwire.listen(0, '127.0.0.1', resolve));
  const env = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/work/home', TMPDIR: '/work', CLAUDE_CONFIG_DIR: '/work/home/.claude', CLAUDE_CODE_ENTRYPOINT: 'sdk-ts', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1', DISABLE_UPDATES: '1', ENABLE_TOOL_SEARCH: 'false', ANTHROPIC_API_KEY: 'synthetic-offline-fixture-key', ANTHROPIC_BASE_URL: `http://127.0.0.1:${tripwire.address().port}` };
  const args = ['--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose', '--include-hook-events', '--setting-sources', 'user', '--plugin-dir', '/work/plugin', '--permission-mode', 'default', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--tools', ''];
  async function start(label) {
  child = spawn('/opt/claude', args, { cwd: '/work', env, stdio: ['pipe', 'pipe', 'pipe'] });
  const session = { label, pid: child.pid, startWireOffset: wire.length, args, executableSha256: hash(await readFile('/opt/claude')) }; report.sessions.push(session);
  child.on('error', e => { failure = e; });
  child.on('close', (code, signal) => { session.exit = { code, signal }; session.exitWireOffset = wire.length; });
  child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 1024 * 1024) { failure = Error('stderr budget'); child.kill('SIGKILL'); } });
  child.stdout.on('data', chunk => {
    stdout += chunk; if (stdout.length > 4 * 1024 * 1024 || wire.length > 600) { failure = Error('wire budget'); child.kill('SIGKILL'); return; }
    while (stdout.includes('\n')) { const end = stdout.indexOf('\n'), line = stdout.slice(0, end); stdout = stdout.slice(end + 1); if (line) { try { record('from-native', JSON.parse(line), session.pid); } catch (e) { failure = e; child.kill('SIGKILL'); } } }
  });
  session.initialize = await request({ subtype: 'initialize' });
  }
  async function stop() {
    const old = child; old.stdin.end();
    if (old.exitCode === null) await Promise.race([new Promise(resolve => old.once('close', resolve)), new Promise(resolve => setTimeout(() => { old.kill('SIGKILL'); resolve(); }, 3000))]);
    assert.equal(old.exitCode, 0, 'native process did not exit cleanly');
  }
  async function optional(requestValue) { try { return await request(requestValue); } catch (e) { return { failedObservation: String(e.stack || e) }; } }
  async function inspect(phase) { report.inspections.push({ phase, pid: child.pid, settings: await optional({ subtype: 'get_settings' }), hooks: await optional({ subtype: 'get_hooks_listing' }) }); }
  await start('A'); await inspect('baseline');
  await prompt('baseline');
  await install('v2'); await prompt('updated-before-reload');
  report.reload = await request({ subtype: 'reload_plugins' }); await prompt('updated-after-reload');
  await settings(false, 'blocker-file-disabled');
  await inspect('false-file-before-reload'); await prompt('false-file-before-reload');
  report.disableReload = await request({ subtype: 'reload_plugins' }); await inspect('false-file-after-reload'); await prompt('false-file-after-reload');
  report.flagDisable = await optional({ subtype: 'apply_flag_settings', settings: { enabledPlugins: { 'mcpm-lifecycle@inline': false } } });
  await inspect('false-flag-before-reload');
  report.flagDisableReload = await request({ subtype: 'reload_plugins' }); await prompt('false-flag-after-reload');
  await stop(); await start('B-file-disabled'); await inspect('restart-file-disabled'); await prompt('restart-file-disabled'); await stop();
  await settings(true, 'blocker-file-reenabled');
  await start('C-file-enabled'); await inspect('restart-file-enabled'); await prompt('restart-file-enabled'); await stop();
  report.status = 'observed';
} catch (e) { report.error = String(e.stack || e); }
finally {
  child?.stdin.end();
  if (child && child.exitCode === null) await Promise.race([new Promise(resolve => child.once('exit', resolve)), new Promise(resolve => setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 3000))]);
  if (tripwire) await new Promise(resolve => tripwire.close(resolve));
  clearTimeout(deadline); report.markers = await markers(); report.stderr = stderr; report.unframedStdout = stdout; if (failure) report.failure = String(failure);
  if (report.status === 'observed') {
    try {
      report.verification = checkPluginLifecycle(report);
      const corrupted = structuredClone(report); corrupted.wire.find(row => row.message.type === 'result').message.num_turns = 1;
      assert.throws(() => checkPluginLifecycle(corrupted));
      report.negativeControl = { status: 'pass', mutation: 'actual retained blocked result relabeled as one model turn', outcome: 'rejected' };
      report.status = 'pass';
    } catch (e) { report.status = 'fail'; report.error = String(e.stack || e); }
  }
  await writeFile('/evidence/report.json', JSON.stringify(report, null, 2) + '\n');
  const reloadSummary = value => value ? { plugins: value.plugins, error_count: value.error_count, held: value.held, plugin_errors: value.plugin_errors } : null;
  console.log(JSON.stringify({ status: report.status, error: report.error, api: api.length, probes: probes.map(p => ({ phase: p.phase, components: p.markers.map(m => m.component), session: p.frame.session_id })), sessions: report.sessions.map(s => ({ label: s.label, pid: s.pid, version: s.initialize?.claude_code_version, exit: s.exit })), reload: reloadSummary(report.reload), disableReload: reloadSummary(report.disableReload), flagDisableReload: reloadSummary(report.flagDisableReload) }));
  if (report.status !== 'pass' || failure || api.length) process.exitCode = 1;
}
