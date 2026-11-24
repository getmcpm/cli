import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { checkPluginLifecycle } from './plugin-lifecycle-checks.mjs';

const original = JSON.parse(readFileSync(new URL('./plugin-lifecycle-fixtures/unit-capture.json', import.meta.url)));
const fromNative = row => row.direction === 'from-native';
test('native plugin predicate derives all phases from raw traffic, not copied summaries', () => {
  const report = structuredClone(original);
  report.probes = [{ phase: 'fabricated', markers: [], frame: { num_turns: 99 } }];
  const phases = checkPluginLifecycle(report).phases;
  assert.equal(phases.length, 8);
  assert.deepEqual(phases.map(p => p.component), ['v1', 'v1', 'v2', 'v2', null, null, null, 'v2']);
});
test('native plugin predicate records a known automatically updated pre-reload build', () => {
  const report = structuredClone(original);
  report.markers.find(m => m.input.prompt?.includes(':updated-before-reload:') && m.component === 'v1').component = 'v2';
  assert.equal(checkPluginLifecycle(report).phases[1].component, 'v2');
});
test('native hook completion may arrive after its blocked result and across a control request', () => {
  const report = structuredClone(original);
  const request = report.wire.find(w => w.message.type === 'user' && w.message.message.content.includes(':false-file-before-reload:'));
  const result = report.wire.find(w => w.message.user_message_uuid === request.message.uuid);
  const index = report.wire.findIndex(w => w.sequence > request.sequence && w.sequence < result.sequence && w.message.subtype === 'hook_response' && w.message.stdout === '');
  const [late] = report.wire.splice(index, 1);
  const control = report.wire.findIndex(w => w.sequence > result.sequence && w.message.request?.subtype === 'reload_plugins');
  report.wire.splice(control + 1, 0, late);
  report.wire.forEach((row, sequence) => { row.sequence = sequence; });
  assert.equal(checkPluginLifecycle(report).phases[3].component, 'v2');
});
test('owned completion arriving after the next probe fails the phase boundary', () => {
  const report = structuredClone(original);
  const request = report.wire.find(w => w.message.type === 'user');
  const result = report.wire.find(w => w.message.user_message_uuid === request.message.uuid);
  const index = report.wire.findIndex(w => w.sequence > request.sequence && w.sequence < result.sequence && w.message.subtype === 'hook_response' && w.message.stdout === '');
  const boundaries = [...report.actions.map(a => [a, 'wireOffset']), ...report.sessions.flatMap(s => [[s, 'startWireOffset'], [s, 'exitWireOffset']])].map(([row, key]) => [row, key, report.wire[row[key]]]);
  const [late] = report.wire.splice(index, 1);
  const next = report.wire.findIndex(w => w.message.type === 'user' && w.message.uuid !== request.message.uuid);
  report.wire.splice(next + 1, 0, late);
  for (const [row, key, frame] of boundaries) row[key] = frame ? report.wire.indexOf(frame) : report.wire.length;
  report.wire.forEach((row, sequence) => { row.sequence = sequence; });
  assert.throws(() => checkPluginLifecycle(report), /unassigned hook/);
});
const mutations = {
  'missing entire phase': r => { const uuid = r.wire.find(w => w.message.type === 'user').message.uuid; r.wire = r.wire.filter(w => w.message.uuid !== uuid && w.message.user_message_uuid !== uuid); },
  'stale executed marker': r => { r.markers.find(m => m.component === 'v2' && m.input.prompt).component = 'v1'; },
  'duplicate marker': r => r.markers.push(structuredClone(r.markers[0])),
  'foreign session marker': r => { r.markers[0].input.session_id = 'foreign'; },
  'unassigned marker': r => { r.markers.find(m => m.input.prompt).input.prompt = 'unassigned'; },
  'lost blocked result': r => { r.wire.splice(r.wire.findIndex(w => fromNative(w) && w.message.type === 'result'), 1); },
  'result before own request': r => { const i = r.wire.findIndex(w => w.message.type === 'result'); const [row] = r.wire.splice(i, 1); r.wire.unshift(row); },
  'missing hook completion': r => { r.wire.splice(r.wire.findIndex(w => w.message.subtype === 'hook_response'), 1); },
  'failed hook completion': r => { r.wire.find(w => w.message.subtype === 'hook_response').message.exit_code = 1; },
  'held reload': r => { r.wire.find(w => fromNative(w) && w.message.response?.response?.error_count === 0).message.response.response.held = true; },
  'native load error': r => { r.wire.find(w => fromNative(w) && w.message.response?.response?.error_count === 0).message.response.response.error_count = 1; },
  'unassigned selected reload': r => { r.wire.push({ direction: 'to-native', nativePid: 19, message: { type: 'control_request', request_id: 'lost', request: { subtype: 'reload_plugins' } } }); },
  'new PID substituted for reload': r => { r.wire.find(w => w.message.type === 'user' && w.message.message.content.includes(':updated-after-reload:')).nativePid = 999; },
  'restart reuses session': r => { const a = r.markers[0].input.session_id; const last = r.sessions[2].pid; for (const row of r.wire.filter(w => w.nativePid === last)) if (row.message.session_id) row.message.session_id = a; },
  'unclean process exit': r => { r.sessions[0].exit.code = 1; },
  'provider attempt': r => r.api.push({ method: 'POST', url: '/v1/messages' }),
  'model turn': r => { r.wire.find(w => w.message.type === 'result').message.num_turns = 1; },
  'cost': r => { r.wire.find(w => w.message.type === 'result').message.total_cost_usd = 0.01; },
  'missing configuration observation': r => { const req = r.wire.find(w => w.message.request?.subtype === 'get_settings'); req.message.request.subtype = 'unsupported'; },
  'corrupt fixture snapshot': r => { r.actions.find(a => a.action === 'replace-file').text += 'drift'; },
  'missing wire': r => { delete r.wire; },
  'malformed wire member': r => r.wire.push(null),
  'native bypass mode': r => { r.wire.find(w => w.message.response?.response?.claude_code_version).message.response.response.current_permission_mode = 'bypassPermissions'; },
  'native PID disagrees with launcher': r => { r.wire.find(w => w.message.response?.response?.claude_code_version).message.response.response.pid = 99999; },
  'unknown startup hook event': r => { for (const w of r.wire) if (w.message.hook_event === 'SessionStart') w.message.hook_event = 'UnknownEvent'; },
  'unknown prompt hook event': r => { for (const w of r.wire) if (w.message.hook_event === 'UserPromptSubmit') w.message.hook_event = 'UnknownEvent'; },
  'split bypass argument': r => { for (const s of r.sessions) s.args[s.args.indexOf('default')] = 'bypassPermissions'; },
  'missing launch scope': r => { for (const s of r.sessions) s.args = []; },
  'foreign raw hook session': r => { for (const w of r.wire) if (w.message.hook_event === 'UserPromptSubmit') w.message.session_id = 'foreign'; },
  'late initial configuration': r => { r.actions.find(a => a.action === 'settings').wireOffset = 500; },
  'wrong native binary': r => { for (const s of r.sessions) s.executableSha256 = '0'.repeat(64); },
  'configured hooks differ from native source': r => { const a = r.actions.find(a => a.action === 'settings'); const value = JSON.parse(a.text); value.hooks = {}; a.text = JSON.stringify(value); a.sha256 = createHash('sha256').update(a.text).digest('hex'); },
  'raw restart opening belongs to A': r => { for (const w of r.wire) if ((w.message.request?.subtype === 'initialize' || w.message.response?.response?.claude_code_version) && w.nativePid !== r.sessions[0].pid) w.nativePid = r.sessions[0].pid; },
  'lost enabled update marker and hook pair': r => {
    const request = r.wire.find(w => w.message.type === 'user' && w.message.message.content.includes(':updated-before-reload:'));
    const result = r.wire.find(w => w.message.user_message_uuid === request.message.uuid);
    const done = r.wire.find(w => w.sequence > request.sequence && w.sequence < result.sequence && w.message.subtype === 'hook_response' && w.message.stdout === '');
    const removed = r.wire.filter(w => w.message.hook_id === done.message.hook_id);
    r.wire = r.wire.filter(w => !removed.includes(w));
    for (const a of r.actions) a.wireOffset -= removed.filter(w => w.sequence < a.wireOffset).length;
    for (const s of r.sessions) for (const key of ['startWireOffset', 'exitWireOffset']) s[key] -= removed.filter(w => w.sequence < s[key]).length;
    r.markers = r.markers.filter(m => !(m.input.prompt === request.message.message.content && ['v1', 'v2'].includes(m.component)));
  },
  'restart starts before prior exit': r => { r.sessions[1].startWireOffset = 0; },
  'process exits before last completed probe': r => { r.sessions[0].exitWireOffset = 3; },
  'initial fixture written after native startup': r => { for (const a of r.actions) if (a.action === 'replace-file' && a.version === 'v1') a.wireOffset = r.wire.find(w => w.message.type === 'user').sequence; },
};
for (const [name, mutate] of Object.entries(mutations)) test(`native plugin gate rejects ${name}`, () => {
  const report = structuredClone(original); mutate(report);
  report.wire?.forEach((row, sequence) => { if (row) row.sequence = sequence; });
  assert.throws(() => checkPluginLifecycle(report));
});
