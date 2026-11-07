import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const parseProcesses = (query, pids) => {
  assert.deepEqual(query.args, ['-ww', '-p', pids.join(','), '-o', 'pid=,ppid=,pgid=,lstart=,command='], 'exact selected PID observer');
  assert.ok(!query.error && !query.signal && query.stderr === '', 'working process observer');
  assert.ok((query.status === 0 && query.stdout.trim()) || (query.status === 1 && query.stdout === ''), 'only ps no-match is absence');
  return query.stdout.trim().split('\n').filter(Boolean).map(line => {
  const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$/);
  assert.ok(match, 'retained ps identity');
  return { pid: +match[1], ppid: +match[2], pgid: +match[3], birth: match[4], command: match[5] };
  });
};

export function signalIdentity(initial, current, pid, supervisorPid) {
  const first = parseProcesses(initial, [pid]);
  const now = parseProcesses(current, [pid]);
  assert.equal(first.length, 1, 'initial live owned leader');
  const owned = row => row.pid === pid && row.ppid === supervisorPid && row.pgid === pid;
  assert.ok(owned(first[0]), 'initial direct-child group ownership');
  return now.length === 1 && owned(now[0]) && now[0].birth === first[0].birth;
}

// Raw outputs and independent supervisor observations are the inputs. Summary
// booleans supplied by the producer are never an authority for this derivation.
export function derive(raw) {
  assert.equal(sha(raw.policy), raw.policySha256, 'exact retained policy');
  assert.ok(!raw.collectorErrors?.length, 'complete loopback collector');
  for (const event of raw.tcp) assert.equal(Buffer.concat(event.chunks.map(chunk => Buffer.from(chunk, 'base64'))).toString(), event.bytes + '\n', 'actual TCP chunks form one complete frame');
  const cohort = ['syntax', 'tests', 'inspect-allow', 'inspect-block', 'pack'].map(id => {
    const compatible = mode => {
      const rows = raw.commands.filter(row => row.id === id && row.mode === mode);
      assert.equal(rows.length, 1, 'one observation for each command/mode');
      const row = rows[0]; assert.ok(row.closed >= row.started && row.pid > 0);
      if (row.timeout || row.error || row.exit.signal || row.exit.code !== (id === 'inspect-block' ? 2 : 0)) return false;
      if (id.startsWith('inspect-')) {
        const lines = row.stdout.trim().split('\n').map(line => JSON.parse(line));
        return lines.length === 1 && lines[0].action === (id === 'inspect-block' ? 'block' : 'pass');
      }
      if (id === 'tests') return /(?:# pass|ℹ pass) 41\b/.test(row.stdout) && !/(?:# fail|ℹ fail) [1-9]/.test(row.stdout);
      if (id === 'pack') {
        if (!(row.archive.bytes > 0 && /^[a-f0-9]{64}$/.test(row.archive.sha256) && Object.keys(row.archive.members || {}).length > 0)) return false;
        for (const member of Object.values(row.archive.members)) assert.ok(member.bytes >= 0 && /^[a-f0-9]{64}$/.test(member.sha256), 'retained member bytes');
        if (mode === 'strict') {
          const baseline = raw.commands.find(value => value.id === id && value.mode === 'baseline');
          if (JSON.stringify(row.archive.members) !== JSON.stringify(baseline.archive.members)) return false;
        }
        return true;
      }
      return true;
    };
    return { id, baseline: compatible('baseline'), strict: compatible('strict') };
  });
  const attack = {};
  for (const mode of ['baseline', 'strict']) {
    const matches = raw.attacks.filter(row => row.mode === mode); assert.equal(matches.length, 1);
    const row = matches[0]; attack[mode] = row;
    assert.equal(row.timeout, undefined); assert.equal(row.error, undefined);
    const pids = ['parent', 'child', 'detached'].map(role => row.ready[role]?.pid);
    assert.ok(pids.every(pid => Number.isSafeInteger(pid) && pid > 1) && new Set(pids).size === 3);
    const before = parseProcesses(row.processBefore, pids), after = parseProcesses(row.processAfterCancel, pids), cleanup = parseProcesses(row.processAfterCleanup, pids);
    const observed = {};
    for (const role of ['parent', 'child', 'detached']) {
      const ready = row.ready[role]; assert.equal(ready.nonce, row.nonce); assert.equal(ready.role, role);
      if (role === 'parent') assert.equal(ready.pid, row.pid);
      const identity = before.find(p => p.pid === ready.pid); assert.ok(identity, 'every ready process independently observed');
      assert.ok(identity.command.includes(row.nonce) && identity.command.endsWith(role === 'parent' ? row.argv.at(-1) : role), 'nonce and command role');
      assert.equal(identity.ppid, ready.ppid);
      if (role !== 'parent') assert.equal(ready.ppid, row.ready[role === 'child' ? 'parent' : 'child'].pid, 'true child/grandchild ancestry');
      assert.equal(identity.pgid === row.pid, role !== 'detached', 'actual detached group');
      const lines = row.files[role].trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
      assert.ok(lines.length > 0, 'actual effect attempt');
      for (const line of lines) {
        assert.equal(line.nonce, row.nonce); assert.equal(line.pid, ready.pid); assert.equal(line.role, role);
        for (const field of ['read', 'symlink', 'write', 'tcp', 'udp']) assert.ok(line[field], `effect role ${field}`);
        if (mode === 'baseline') {
          assert.equal(line.read.value, row.canary); assert.equal(line.symlink.value, row.canary);
          for (const field of ['write', 'tcp', 'udp']) assert.equal(line[field].value, true);
        } else for (const field of ['read', 'symlink', 'write', 'tcp', 'udp']) assert.ok(['EPERM', 'EACCES'].includes(line[field].error) || line[field].value !== undefined, 'measured effect on every attempt');
      }
      const line = lines[0];
      observed[role] = { ...line };
      for (const field of ['read', 'symlink', 'write', 'tcp', 'udp']) {
        const allowed = lines.find(value => value[field].value !== undefined);
        if (allowed) observed[role][field] = allowed[field];
      }
      for (const field of ['read', 'symlink', 'write', 'tcp', 'udp']) assert.ok(line[field], `effect role ${field}`);
      if (mode === 'baseline') {
        assert.equal(line.read.value, row.canary); assert.equal(line.symlink.value, row.canary);
        assert.equal(row.externalWrites[role], row.nonce);
        for (const kind of ['tcp', 'udp']) assert.ok(raw[kind].filter(event => { const data = JSON.parse(event.bytes); return data.nonce === row.nonce && data.role === role && data.pid === ready.pid; }).length >= lines.length, 'same-target positive sink control');
      } else {
        if (observed[role].write.value !== undefined) assert.equal(row.externalWrites[role], row.nonce, 'observed allowed write');
        else assert.deepEqual(row.externalWrites[role], { error: 'ENOENT' });
        for (const kind of ['tcp', 'udp']) {
          const events = raw[kind].filter(event => { const data = JSON.parse(event.bytes); return data.nonce === row.nonce && data.role === role && data.pid === ready.pid; });
          if (observed[role][kind].value !== undefined) assert.ok(events.length > 0, 'observed allowed egress');
          else assert.equal(events.length, 0, 'no denied sink delivery');
        }
      }
      const surviving = after.find(p => p.pid === ready.pid);
      if (surviving) {
        const stable = ({ ppid, ...rest }) => rest;
        assert.deepEqual(stable(surviving), stable(identity), 'survival retains PID/birth/command/group identity; reparenting is retained separately');
      }
      if (surviving && role === 'detached') {
        assert.ok(lines.some(line => line.time > row.cancel.time), 'retained sensitive attempts after parent cancellation');
        const heartbeats = text => text.trim().split('\n').filter(Boolean).map(value => JSON.parse(value));
        const beats = heartbeats(row.heartbeatAfter[role]);
        assert.ok(beats.length > heartbeats(row.heartbeatBefore[role]).length, 'continued work after cancellation');
        for (const beat of beats) { assert.equal(beat.nonce, row.nonce); assert.equal(beat.pid, ready.pid); }
      }
      assert.ok(!cleanup.some(p => p.pid === ready.pid), 'separate safety cleanup complete');
    }
    assert.equal(row.cancel.targetGroup, row.pid); assert.equal(row.cancel.signal, 'SIGTERM');
    const signals = row.signals.filter(event => event.reason === 'measured cancellation');
    assert.equal(signals.length, 1, 'actual cancellation action retained');
    const signal = signals[0];
    assert.equal(signal.signal, 'SIGTERM'); assert.equal(signal.targetGroup, row.pid); assert.equal(signal.sent, true);
    assert.equal(signalIdentity(row.launchIdentity, signal.identity, row.pid, row.ready.parent.ppid), true, 'owned group at cancellation');
    assert.ok(row.cancel.time >= Math.max(...Object.values(observed).map(line => line.time)) && row.cleanupTime > row.cancel.time);
    attack[mode] = { row, observed, after };
  }
  const effects = ['parent', 'child', 'detached'].map(role => {
    const baseline = {}, strict = {};
    for (const field of ['read', 'symlink', 'write', 'tcp', 'udp']) {
      baseline[field] = attack.baseline.observed[role][field].value !== undefined;
      strict[field] = attack.strict.observed[role][field].value !== undefined ? true : attack.strict.observed[role][field].error;
    }
    const row = attack.strict.row;
    const sinkBytes = ['tcp', 'udp'].flatMap(kind => raw[kind]).filter(event => { const data = JSON.parse(event.bytes); return data.nonce === row.nonce && data.role === role; }).reduce((total, event) => total + Buffer.byteLength(event.bytes), 0);
    return { role, baseline, strict, unchanged: typeof row.externalWrites[role] !== 'string', sinkBytes };
  });
  const strict = attack.strict;
  const alive = role => strict.after.some(p => p.pid === strict.row.ready[role].pid);
  const cancellation = { parentClosed: !alive('parent'), childClosed: !alive('child'), detachedSurvived: alive('detached'), identityVerified: true, cleanupComplete: true };
  const observations = { cohort, effects, cancellation };
  return { ...observations, ...evaluate(observations) };
}

// This is a decision over derived observations, not report authentication.
// run.mjs retains command output and independent effect/process observations.
export function evaluate(report) {
  const reasons = [];
  const ids = ['syntax', 'tests', 'inspect-allow', 'inspect-block', 'pack'];
  assert.deepEqual(report.cohort.map(row => row.id).sort(), ids.sort(), 'complete useful cohort');
  for (const row of report.cohort) {
    assert.equal(row.baseline, true, `invalid baseline: ${row.id}`);
    assert.equal(typeof row.strict, 'boolean');
    if (!row.strict) reasons.push(`benign breakage: ${row.id}`);
  }
  assert.deepEqual(report.effects.map(row => row.role).sort(), ['child', 'detached', 'parent']);
  for (const row of report.effects) {
    for (const effect of ['read', 'symlink', 'write', 'tcp', 'udp']) {
      assert.equal(row.baseline[effect], true, `positive control: ${row.role}/${effect}`);
      const value = row.strict[effect];
      assert.ok(value === true || ['EPERM', 'EACCES'].includes(value), `unmeasured denial: ${row.role}/${effect}`);
      if (value === true) reasons.push(`sensitive effect allowed: ${row.role}/${effect}`);
    }
    assert.equal(typeof row.unchanged, 'boolean', 'external forbidden write observation');
    assert.ok(Number.isSafeInteger(row.sinkBytes) && row.sinkBytes >= 0, 'external loopback sink observation');
    if (!row.unchanged) reasons.push(`external forbidden write: ${row.role}`);
    if (row.sinkBytes) reasons.push(`external loopback delivery: ${row.role}`);
  }
  const cancel = report.cancellation;
  assert.equal(cancel.identityVerified, true, 'independent descendant identity');
  assert.equal(cancel.cleanupComplete, true, 'all task processes closed after safety cleanup');
  for (const field of ['parentClosed', 'childClosed', 'detachedSurvived']) assert.equal(typeof cancel[field], 'boolean', `missing cancellation observation: ${field}`);
  if (!cancel.parentClosed) reasons.push('parent survived group cancellation');
  if (!cancel.childClosed) reasons.push('ordinary descendant survived group cancellation');
  if (cancel.detachedSurvived) reasons.push('detached descendant survived group cancellation');
  return { decision: reasons.length ? 'NO-GO' : 'GO', reasons };
}
