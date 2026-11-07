import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const pluginPhases = ['baseline', 'updated-before-reload', 'updated-after-reload', 'false-file-before-reload', 'false-file-after-reload', 'false-flag-after-reload', 'restart-file-disabled', 'restart-file-enabled'];
const pluginKey = 'mcpm-lifecycle@inline';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const blockers = ['blocker-file-enabled', 'blocker-file-disabled', 'blocker-file-reenabled'];
const fixtureNames = ['.claude-plugin/plugin.json', 'hooks/hooks.json', 'skills/inert/SKILL.md'];
export const pluginArgs = ['--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose', '--include-hook-events', '--setting-sources', 'user', '--plugin-dir', '/work/plugin', '--permission-mode', 'default', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--tools', ''];
const pins = JSON.parse(readFileSync(new URL('./plugin-lifecycle-pins.json', import.meta.url)));

// A bounded fixture predicate, not an authenticated-report or arbitrary-host verifier.
export function checkPluginLifecycle(report) {
  assert.ok(Buffer.byteLength(JSON.stringify(report)) <= 8 * 1024 * 1024, 'report budget');
  assert.equal(report.schemaVersion, 1); assert.equal(report.platform, 'linux'); assert.equal(report.arch, 'arm64');
  assert.ok(typeof report.runId === 'string' && report.runId.length > 0);
  assert.ok(Array.isArray(report.api)); assert.equal(report.api.length, 0, 'API attempt');
  assert.ok(!report.error && !report.failure && !report.unframedStdout, 'incomplete runner');
  const { wire, markers, sessions, actions } = report;
  assert.ok(Array.isArray(wire) && wire.length > 0 && wire.length <= 600);
  assert.ok(Array.isArray(markers) && markers.length <= 32);
  assert.ok(Array.isArray(actions) && actions.length <= 24);
  assert.equal(sessions?.length, 3);
  assert.deepEqual(sessions.map(s => s.label), ['A', 'B-file-disabled', 'C-file-enabled']);
  assert.equal(new Set(sessions.map(s => s.pid)).size, 3, 'restart needs a fresh process');
  for (const [index, session] of sessions.entries()) {
    assert.ok(Number.isSafeInteger(session.pid) && session.pid > 0);
    assert.deepEqual(session.exit, { code: 0, signal: null });
    assert.equal(session.initialize?.claude_code_version, '2.1.296');
    assert.deepEqual(session.args, pluginArgs, 'unreviewed launch arguments');
    assert.equal(session.executableSha256, pins.binarySha256);
    assert.ok(Number.isInteger(session.startWireOffset) && Number.isInteger(session.exitWireOffset) && session.startWireOffset >= 0 && session.exitWireOffset > session.startWireOffset && session.exitWireOffset <= wire.length);
    if (index) assert.ok(session.startWireOffset >= sessions[index - 1].exitWireOffset, 'restart started before prior process exited');
  }
  wire.forEach((row, sequence) => {
    assert.ok(row && row.sequence === sequence && row.message && sessions.some(s => s.pid === row.nativePid), 'malformed wire row');
    const session = sessions.find(s => s.pid === row.nativePid); assert.ok(sequence >= session.startWireOffset && sequence < session.exitWireOffset, 'wire outside process lifetime');
    assert.ok(['to-native', 'from-native'].includes(row.direction));
    const m = row.message;
    assert.ok(!m.plugin_errors?.length && !m.error, 'native error');
    assert.ok(row.direction === 'to-native' ? ['user', 'control_request'].includes(m.type) : ['control_response', 'system', 'result', 'command_lifecycle'].includes(m.type), 'unexpected message');
  });
  const outgoing = wire.filter(w => w.direction === 'to-native');
  const controls = outgoing.filter(w => w.message.type === 'control_request');
  assert.deepEqual(controls.map(w => w.message.request?.subtype), ['initialize', 'get_settings', 'get_hooks_listing', 'reload_plugins', 'get_settings', 'get_hooks_listing', 'reload_plugins', 'get_settings', 'get_hooks_listing', 'apply_flag_settings', 'get_settings', 'get_hooks_listing', 'reload_plugins', 'initialize', 'get_settings', 'get_hooks_listing', 'initialize', 'get_settings', 'get_hooks_listing']);
  assert.equal(new Set(controls.map(w => w.message.request_id)).size, controls.length);
  const responses = wire.filter(w => w.message.type === 'control_response');
  assert.equal(responses.length, controls.length, 'lost or extra control response');
  const pairs = controls.map(request => {
    const matches = responses.filter(w => w.message.response?.request_id === request.message.request_id);
    assert.equal(matches.length, 1); const response = matches[0];
    assert.ok(response.sequence > request.sequence && response.nativePid === request.nativePid, 'control causality');
    assert.equal(response.message.response.subtype, 'success');
    return { request, response, value: response.message.response.response };
  });
  const initializations = pairs.filter(p => p.request.message.request.subtype === 'initialize');
  assert.deepEqual(initializations.map(p => p.request.nativePid), sessions.map(s => s.pid));
  for (const pair of initializations) {
    assert.equal(pair.value.claude_code_version, '2.1.296');
    assert.equal(pair.value.pid, pair.request.nativePid); assert.equal(pair.value.current_permission_mode, 'default');
  }
  const reloads = pairs.filter(p => p.request.message.request.subtype === 'reload_plugins');
  for (const { value } of reloads) {
    assert.equal(value.error_count, 0); assert.notEqual(value.held, true, 'held reload was not applied');
    assert.ok(!value.plugin_errors?.length);
  }
  const users = outgoing.filter(w => w.message.type === 'user'); assert.equal(users.length, 8);
  assert.equal(new Set(users.map(w => w.message.uuid)).size, 8);
  const usedMarkers = new Set(), sessionIds = new Map();
  const phases = users.map((request, index) => {
    const m = request.message, phase = pluginPhases[index];
    assert.equal(m.message?.content, `${report.runId}:${phase}:${m.uuid}`, 'missing/reordered phase');
    const pid = sessions[index < 6 ? 0 : index === 6 ? 1 : 2].pid; assert.equal(request.nativePid, pid);
    const results = wire.filter(w => w.direction === 'from-native' && w.message.type === 'result' && (w.message.user_message_uuid === m.uuid || w.message.user_message_uuids?.includes(m.uuid)));
    assert.equal(results.length, 1, 'missing/duplicate blocked result'); const result = results[0];
    assert.ok(result.sequence > request.sequence && result.nativePid === pid);
    const value = result.message;
    assert.equal(value.subtype, 'success'); assert.equal(value.is_error, false);
    assert.equal(value.num_turns, 0); assert.equal(value.total_cost_usd, 0); assert.equal(value.duration_api_ms, 0);
    assert.ok(value.result.includes(`offline-fixture-block:${m.message.content}`), 'no positive blocking receipt');
    const sid = value.session_id; assert.ok(typeof sid === 'string' && sid.length > 0);
    if (sessionIds.has(pid)) assert.equal(sessionIds.get(pid), sid); else sessionIds.set(pid, sid);
    const lifecycle = wire.filter(w => w.message.type === 'command_lifecycle' && w.message.command_uuid === m.uuid);
    assert.deepEqual(lifecycle.map(w => w.message.state), ['queued', 'started', 'completed']);
    assert.ok(lifecycle[0].sequence > request.sequence && lifecycle[1].sequence < result.sequence && lifecycle[2].sequence > result.sequence);
    assert.ok(lifecycle.every(w => w.nativePid === pid && w.message.session_id === sid));
    if (users[index + 1]) assert.ok(lifecycle[2].sequence < users[index + 1].sequence, 'overlapping probes');
    const window = wire.filter(w => w.sequence > request.sequence && w.sequence < result.sequence);
    assert.ok(window.every(w => w.nativePid === pid));
    const initialization = initializations.find(p => p.request.nativePid === pid);
    assert.ok(initialization.response.sequence < request.sequence, 'prompt before native initialization');
    const initFrames = window.filter(w => w.message.subtype === 'init'); assert.equal(initFrames.length, 1);
    assert.equal(initFrames[0].message.permissionMode, 'default'); assert.equal(initFrames[0].message.claude_code_version, '2.1.296');
    assert.equal(initFrames[0].message.session_id, sid);
    const rows = markers.filter(marker => marker.input?.prompt === m.message.content);
    for (const row of rows) { assert.equal(row.input.session_id, sid); assert.equal(row.input.hook_event_name, 'UserPromptSubmit'); usedMarkers.add(row); }
    const blocker = rows.filter(row => blockers.includes(row.component)); assert.equal(blocker.length, 1, 'missing/duplicate independent blocker');
    const component = rows.filter(row => ['v1', 'v2'].includes(row.component)); assert.ok(component.length <= 1);
    assert.equal(rows.length, blocker.length + component.length, 'unknown component');
    const observed = component[0]?.component ?? null;
    if (index === 0) assert.equal(observed, 'v1');
    if (index === 1) assert.equal(component.length, 1, 'enabled update needs an executed known-version marker');
    if (index === 2 || index === 7) assert.equal(observed, 'v2');
    if ([4, 5, 6].includes(index)) assert.equal(observed, null, 'disabled component executed');
    // Pre-reload identity is observed, not a universal stale-cache promise.
    const started = window.filter(w => w.message.subtype === 'hook_started');
    const completed = wire.filter(w => w.message.subtype === 'hook_response' && started.some(start => start.message.hook_id === w.message.hook_id));
    assert.equal(started.length, rows.length); assert.equal(completed.length, rows.length);
    for (const row of [...started, ...completed]) { assert.equal(row.message.hook_event, 'UserPromptSubmit'); assert.equal(row.message.session_id, sid); assert.equal(row.nativePid, pid); }
    assert.ok(completed.some(w => w.message.stdout?.includes(`offline-fixture-block:${m.message.content}`)));
    return { phase, pid, sessionId: sid, component: observed, blocker: blocker[0].component, request: request.sequence, result: result.sequence, nextProbe: users[index + 1]?.sequence ?? wire.length };
  });
  assert.equal(new Set(sessionIds.values()).size, 3, 'restart reused session');
  assert.equal(wire.filter(w => w.message.type === 'result').length, 8, 'unassigned result');
  assert.equal(wire.filter(w => w.message.type === 'command_lifecycle').length, 24, 'unassigned command');
  const started = wire.filter(w => w.message.subtype === 'hook_started'), completed = wire.filter(w => w.message.subtype === 'hook_response');
  assert.equal(started.length, markers.length); assert.equal(completed.length, markers.length);
  assert.equal(new Set(started.map(w => w.message.hook_id)).size, started.length);
  for (const start of started) {
    const matches = completed.filter(w => w.message.hook_id === start.message.hook_id); assert.equal(matches.length, 1);
    const done = matches[0]; assert.ok(done.sequence > start.sequence && done.nativePid === start.nativePid);
    assert.equal(done.message.session_id, start.message.session_id); assert.equal(done.message.hook_event, start.message.hook_event);
    assert.equal(done.message.exit_code, 0); assert.equal(done.message.outcome, 'success');
    if (start.message.hook_event === 'SessionStart') {
      const phase = phases.find(p => p.pid === start.nativePid);
      assert.ok(phase && ['baseline', 'restart-file-enabled'].includes(phase.phase));
      assert.equal(start.message.session_id, phase.sessionId);
      assert.ok(start.sequence > initializations.find(p => p.request.nativePid === phase.pid).request.sequence && done.sequence < phase.request);
    } else {
      assert.equal(start.message.hook_event, 'UserPromptSubmit');
      assert.ok(phases.some(p => start.nativePid === p.pid && start.message.session_id === p.sessionId && start.sequence > p.request && start.sequence < p.result && done.sequence < p.nextProbe), 'unassigned hook');
    }
  }
  for (const marker of markers.filter(row => !usedMarkers.has(row))) {
    assert.equal(marker.input?.hook_event_name, 'SessionStart'); assert.equal(marker.input.source, 'startup');
    const pid = [...sessionIds].find(([, sid]) => sid === marker.input.session_id)?.[0];
    assert.ok(pid === sessions[0].pid || pid === sessions[2].pid, 'foreign startup marker');
    assert.equal(marker.component, pid === sessions[0].pid ? 'v1' : 'v2');
    assert.equal(markers.filter(row => row.input?.hook_event_name === 'SessionStart' && row.input.session_id === marker.input.session_id).length, 1);
  }
  assert.equal(markers.filter(row => row.input?.hook_event_name === 'SessionStart').length, 2);
  for (const [index, expected] of [[0, 'v2'], [1, null], [2, null]]) {
    const members = reloads[index].value.plugins.filter(p => p.source === pluginKey);
    assert.equal(members.length, expected ? 1 : 0);
    if (expected) { assert.equal(members[0].path, '/work/plugin'); assert.equal(members[0].version, '2.0.0'); }
    const before = index === 0 ? phases[1] : index === 1 ? phases[3] : phases[4], after = phases[index === 0 ? 2 : index === 1 ? 4 : 5];
    assert.ok(reloads[index].request.sequence > before.result && reloads[index].response.sequence < after.request, 'reload outside live transition');
    assert.equal(reloads[index].request.nativePid, sessions[0].pid);
  }
  const settings = pairs.filter(p => p.request.message.request.subtype === 'get_settings');
  assert.deepEqual(settings.map(p => p.value.effective?.enabledPlugins?.[pluginKey]), [true, false, false, false, false, true]);
  assert.ok(settings[1].response.sequence < reloads[1].request.sequence, 'missing file-inspection-reload path');
  const flag = pairs.find(p => p.request.message.request.subtype === 'apply_flag_settings');
  assert.deepEqual(flag.request.message.request.settings, { enabledPlugins: { [pluginKey]: false } });
  assert.ok(flag.request.sequence > phases[4].result && flag.response.sequence < reloads[2].request.sequence);
  for (const version of ['v1', 'v2']) for (const name of fixtureNames) {
    const file = readFileSync(new URL(`./plugin-lifecycle-fixtures/${version}/${name}`, import.meta.url));
    const rows = actions.filter(a => a.action === 'replace-file' && a.version === version && a.name === name); assert.equal(rows.length, 1);
    assert.equal(rows[0].text, file.toString('utf8')); assert.equal(rows[0].sha256, sha(file));
    assert.ok(Number.isInteger(rows[0].wireOffset) && rows[0].wireOffset <= phases[version === 'v1' ? 0 : 1].request);
    if (version === 'v1') assert.ok(rows[0].wireOffset <= sessions[0].startWireOffset, 'initial fixture written after native startup');
    if (version === 'v2') assert.ok(rows[0].wireOffset > phases[0].result, 'update did not occur in live A');
  }
  const configs = actions.filter(a => a.action === 'settings'); assert.equal(configs.length, 3);
  for (const action of actions) assert.ok(Number.isInteger(action.wireOffset) && action.wireOffset >= 0 && action.wireOffset <= wire.length);
  assert.deepEqual(configs.map(a => a.enabled), [true, false, true]);
  assert.ok(configs[0].wireOffset <= initializations[0].request.sequence, 'configuration after startup');
  for (const config of configs) { assert.equal(config.sha256, sha(config.text)); assert.equal(JSON.parse(config.text).enabledPlugins[pluginKey], config.enabled); }
  settings.forEach((pair, index) => {
    const configured = JSON.parse(configs[index === 0 ? 0 : index === 5 ? 2 : 1].text);
    const user = pair.value.sources.filter(source => source.source === 'userSettings'); assert.equal(user.length, 1);
    assert.deepEqual(user[0].settings, configured, 'configured bytes disagree with native user settings');
    assert.deepEqual(pair.value.effective, configured, 'native effective settings differ');
    assert.deepEqual(pair.value.sources.map(source => source.source), index === 3 ? ['userSettings', 'flagSettings'] : ['userSettings']);
    if (index === 3) assert.deepEqual(pair.value.sources[1].settings, { enabledPlugins: { [pluginKey]: false } });
  });
  assert.ok(configs[1].wireOffset > phases[2].result && configs[1].wireOffset <= settings[1].request.sequence);
  assert.ok(configs[2].wireOffset > phases[6].result && configs[2].wireOffset <= initializations[2].request.sequence);
  for (const phase of phases) if (phase.component) {
    const hooks = JSON.parse(readFileSync(new URL(`./plugin-lifecycle-fixtures/${phase.component}/hooks/hooks.json`, import.meta.url)));
    const manifest = JSON.parse(readFileSync(new URL(`./plugin-lifecycle-fixtures/${phase.component}/.claude-plugin/plugin.json`, import.meta.url)));
    phase.executedCommandSha256 = sha(hooks.hooks.UserPromptSubmit[0].hooks[0].command);
    phase.declaredBundleVersion = manifest.version;
  }
  return { scope: 'Claude Code 2.1.296 Linux arm64 inline hook command only; bundle version is author-declared', phases, wireSha256: sha(JSON.stringify(wire)), markersSha256: sha(JSON.stringify(markers)), textSkillActivation: 'unknown' };
}
