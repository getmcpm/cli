import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, derive, signalIdentity } from './verify.mjs';
import { createHash } from 'node:crypto';

const valid = () => ({
  cohort: ['syntax', 'tests', 'inspect-allow', 'inspect-block', 'pack'].map(id => ({ id, baseline: true, strict: true })),
  effects: ['parent', 'child', 'detached'].map(role => ({ role, baseline: { read: true, symlink: true, write: true, tcp: true, udp: true }, strict: { read: 'EPERM', symlink: 'EPERM', write: 'EACCES', tcp: 'EPERM', udp: 'EPERM' }, unchanged: true, sinkBytes: 0 })),
  cancellation: { parentClosed: true, childClosed: true, detachedSurvived: true, identityVerified: true, cleanupComplete: true },
});

test('detached survival is a measured NO-GO, separate from safe cleanup', () => {
  assert.deepEqual(evaluate(valid()), { decision: 'NO-GO', reasons: ['detached descendant survived group cancellation'] });
});
for (const [name, change] of [
  ['missing benign task', r => r.cohort.pop()],
  ['failed baseline', r => { r.cohort[0].baseline = false; }],
  ['missing detached effects', r => r.effects.pop()],
  ['ENOENT is not denial', r => { r.effects[0].strict.read = 'ENOENT'; }],
  ['lost identity', r => { r.cancellation.identityVerified = false; }],
  ['missing cleanup', r => { r.cancellation.cleanupComplete = false; }],
  ['parent-only cancellation', r => { delete r.cancellation.detachedSurvived; }],
]) test(name, () => { const r = valid(); change(r); assert.throws(() => evaluate(r)); });

test('compatible tasks alone cannot hide a confinement failure', () => {
  const r = valid(); r.effects[2].strict.read = true;
  assert.equal(evaluate(r).decision, 'NO-GO');
});
for (const field of ['unchanged', 'sinkBytes']) test(`measured ${field} effect is NO-GO, not invalid evidence`, () => {
  const row = valid(); row.effects[0][field] = field === 'unchanged' ? false : 1;
  assert.equal(evaluate(row).decision, 'NO-GO');
});

// Authored unit-only raw projection, not a native receipt or measured result.
function rawProjection() {
  const hash = createHash('sha256').update('canary').digest('hex');
  const raw = { policy: 'unit-only', policySha256: createHash('sha256').update('unit-only').digest('hex'), commands: [], attacks: [], tcp: [], udp: [] };
  for (const mode of ['baseline', 'strict']) {
    for (const id of ['syntax', 'tests', 'inspect-allow', 'inspect-block', 'pack']) raw.commands.push({ id, mode, pid: 11, started: 1, closed: 2, exit: { code: id === 'inspect-block' ? 2 : 0, signal: null }, stdout: id.startsWith('inspect-') ? JSON.stringify({ action: id === 'inspect-block' ? 'block' : 'pass' }) : id === 'tests' ? '# pass 41\n# fail 0\n' : '', archive: { bytes: 10, sha256: 'a'.repeat(64), members: { 'package/dist/index.js': { bytes: 1, sha256: 'b'.repeat(64) } } } });
    const nonce = mode, pids = mode === 'baseline' ? [101, 102, 103] : [201, 202, 203];
    const row = { mode, nonce, pid: pids[0], argv: ['udp'], ready: {}, files: {}, externalWrites: {}, heartbeatBefore: { detached: '' }, heartbeatAfter: { detached: JSON.stringify({ nonce, pid: pids[2], time: 6 }) }, canary: hash, cancel: { targetGroup: pids[0], signal: 'SIGTERM', time: 5 }, cleanupTime: 10, processAfterCleanup: '' };
    const processLines = [];
    for (const [i, role] of ['parent', 'child', 'detached'].entries()) {
      const pid = pids[i], ppid = i ? pids[i - 1] : 1;
      row.ready[role] = { role, nonce, pid, ppid };
      const line = { role, nonce, pid, time: 3 };
      for (const field of ['read', 'symlink', 'write', 'tcp', 'udp']) line[field] = mode === 'strict' ? { error: 'EPERM' } : { value: ['read', 'symlink'].includes(field) ? hash : true };
      row.files[role] = JSON.stringify(line) + '\n' + (role === 'detached' ? JSON.stringify({ ...line, time: 6 }) + '\n' : ''); row.externalWrites[role] = mode === 'baseline' ? nonce : { error: 'ENOENT' };
      processLines.push(`${pid} ${ppid} ${i === 2 ? pid : pids[0]} Sun Nov 8 01:00:00 2026 node probe ${nonce} ${i === 0 ? 'udp' : role}`);
      if (mode === 'baseline') for (const kind of ['tcp', 'udp']) for (let n = 0; n < (role === 'detached' ? 2 : 1); n++) { const bytes = JSON.stringify({ nonce, role, pid }); raw[kind].push({ bytes, chunks: [Buffer.from(bytes + '\n').toString('base64')] }); }
    }
    const args = ['-ww', '-p', pids.join(','), '-o', 'pid=,ppid=,pgid=,lstart=,command='];
    row.processBefore = { args, status: 0, stdout: processLines.join('\n'), stderr: '' };
    row.processAfterCancel = { args, status: 0, stdout: processLines[2], stderr: '' };
    row.processAfterCleanup = { args, status: 1, stdout: '', stderr: '' }; raw.attacks.push(row);
    row.launchIdentity = { ...row.processBefore, args: ['-ww', '-p', String(pids[0]), '-o', 'pid=,ppid=,pgid=,lstart=,command='], stdout: processLines[0] };
    row.signals = [{ reason: 'measured cancellation', signal: 'SIGTERM', targetGroup: pids[0], sent: true, identity: row.launchIdentity }];
  }
  return raw;
}
test('raw derivation ignores a fabricated clean summary and preserves input', () => {
  const raw = rawProjection(); raw.derived = { decision: 'GO' }; const before = structuredClone(raw);
  assert.equal(derive(raw).decision, 'NO-GO'); assert.deepEqual(raw, before);
});
for (const field of ['write', 'tcp', 'udp']) test(`consistent raw allowed ${field} is measured NO-GO`, () => {
  const raw = rawProjection(), attack = raw.attacks[1], row = JSON.parse(attack.files.parent);
  row[field] = { value: true }; attack.files.parent = JSON.stringify(row);
  if (field === 'write') attack.externalWrites.parent = attack.nonce;
  else { const bytes = JSON.stringify({ nonce: attack.nonce, role: 'parent', pid: attack.pid }); raw[field].push({ bytes, chunks: [Buffer.from(bytes + '\n').toString('base64')] }); }
  assert.equal(derive(raw).decision, 'NO-GO');
});
for (const [name, mutate] of [
  ['lost raw descendant', r => { r.attacks[1].files.detached = ''; }],
  ['forged denial missing positive sink', r => { r.tcp.pop(); }],
  ['foreign process identity', r => { r.attacks[1].ready.child.pid = 999; }],
  ['changed process birth at cancellation', r => { r.attacks[1].processAfterCancel.stdout = r.attacks[1].processAfterCancel.stdout.replace('01:00:00', '02:00:00'); }],
  ['failed process observer cannot mean absent', r => { r.attacks[1].processAfterCleanup.error = 'EPERM'; }],
  ['arbitrary empty status cannot mean absent', r => { r.attacks[1].processAfterCleanup.status = 2; }],
  ['lost TCP chunk', r => { r.tcp[0].chunks = []; }],
  ['lost cancel event', r => { delete r.attacks[1].cancel; }],
  ['lost actual signal action', r => { r.attacks[1].signals = []; }],
  ['missing raw command', r => { r.commands.pop(); }],
  ['fabricated summary over ENOENT', r => { const row = JSON.parse(r.attacks[1].files.parent); row.read.error = 'ENOENT'; r.attacks[1].files.parent = JSON.stringify(row); r.derived = { decision: 'GO' }; }],
  ['sensitive symlink read', r => { const row = JSON.parse(r.attacks[1].files.parent); row.symlink = { value: true }; r.attacks[1].files.parent = JSON.stringify(row); }],
  ['late sensitive read', r => { const lines = r.attacks[1].files.detached.trim().split('\n').map(JSON.parse); lines[1].read = { value: true }; r.attacks[1].files.detached = lines.map(JSON.stringify).join('\n'); }],
]) test(name, () => { const raw = rawProjection(); mutate(raw); if (['sensitive symlink read', 'late sensitive read'].includes(name)) assert.equal(derive(raw).decision, 'NO-GO'); else assert.throws(() => derive(raw)); });

test('signals require a live direct child with the original birth and group', () => {
  const args = ['-ww', '-p', '22', '-o', 'pid=,ppid=,pgid=,lstart=,command='];
  const first = { args, status: 0, stdout: '22 11 22 Sun Nov 8 01:00:00 2026 node', stderr: '' };
  assert.equal(signalIdentity(first, first, 22, 11), true);
  for (const stdout of ['22 99 22 Sun Nov 8 01:00:00 2026 node', '22 11 22 Sun Nov 8 01:00:01 2026 node', '22 11 23 Sun Nov 8 01:00:00 2026 node']) assert.equal(signalIdentity(first, { ...first, stdout }, 22, 11), false);
  assert.equal(signalIdentity(first, { args, status: 1, stdout: '', stderr: '' }, 22, 11), false);
  assert.throws(() => signalIdentity(first, { args, status: 2, stdout: '', stderr: 'observer failed' }, 22, 11));
});
