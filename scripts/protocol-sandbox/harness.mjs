import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';

export function equivalent(direct, guarded) {
  assert.notEqual(direct, undefined, 'missing direct observation');
  assert.notEqual(guarded, undefined, 'missing guarded observation');
  assert.deepEqual(guarded, direct, 'guard changed benign semantics');
}

export function assertEcho(result, expected) {
  assert.ok(!result.isError, 'echo returned a tool error');
  assert.deepEqual(result.content, [{ type: 'text', text: JSON.stringify(expected) }]);
}

export function assertUnsupported(observation, method, wireCode, clientCode) {
  assert.equal(observation.value.code, clientCode);
  const request = observation.wire.find(w => w.direction === 'to-server' && w.message.method === method)?.message;
  assert.ok(request, `missing ${method} request`);
  const response = observation.wire.find(w => w.direction === 'from-server' && w.message.id === request.id)?.message;
  assert.equal(response?.error?.code, wireCode);
}

export function record(wire, direction, message) {
  const json = JSON.stringify(message);
  assert.ok(wire.length < 256, 'wire message budget exceeded');
  wire.push({ direction, ...(json.length <= 32768 ? { message } : {
    bytes: Buffer.byteLength(json), sha256: createHash('sha256').update(json).digest('hex'), truncated: true,
  }) });
}

export function exchange(command, args, options = {}) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], detached: true, ...options });
  const wire = [];
  const pending = new Map();
  let nextId = 0;
  let stderr = '';
  let closed = false;
  let failure;
  const rejectAll = error => {
    failure = error;
    for (const p of pending.values()) { clearTimeout(p.timer); p.reject(error); }
    pending.clear();
  };
  const done = new Promise(resolve => {
    child.on('close', () => { closed = true; rejectAll(new Error('peer disconnected')); resolve(); });
    child.on('error', rejectAll);
  });
  child.stdin.on('error', rejectAll);
  child.stderr.on('data', b => { stderr = (stderr + b).slice(-32768); });
  const reader = createInterface({ input: child.stdout });
  let bytes = 0;
  child.stdout.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > 16 * 1024 * 1024) {
      rejectAll(new Error('wire byte budget exceeded'));
      reader.close(); child.stdout.destroy();
    }
  });
  reader.on('line', line => {
    try {
      assert.ok(line.length <= 11 * 1024 * 1024, 'wire frame budget exceeded');
      const message = JSON.parse(line);
      assert.ok(message && typeof message === 'object' && !Array.isArray(message), 'invalid JSON-RPC object');
      assert.equal(message.jsonrpc, '2.0', 'invalid JSON-RPC version');
      record(wire, 'from-server', message);
      if ('method' in message) return;
      assert.notEqual('result' in message, 'error' in message, 'response needs exactly one result or error');
      const p = pending.get(message.id);
      assert.ok(p, `unmatched response ${message.id}`);
      clearTimeout(p.timer); pending.delete(message.id); p.resolve(message);
    } catch (error) { rejectAll(error); }
  });
  function send(message) {
    if (failure) throw failure;
    record(wire, 'to-server', message);
    child.stdin.write(JSON.stringify(message) + '\n');
  }
  return {
    child, wire, get stderr() { return stderr; },
    send,
    request(method, params = {}, timeout = 3000) {
      const id = ++nextId;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`deadline: ${method}`)); }, timeout);
        pending.set(id, { resolve, reject, timer });
        try { send({ jsonrpc: '2.0', id, method, params }); }
        catch (e) { clearTimeout(timer); pending.delete(id); reject(e); }
      });
    },
    async close() {
      child.stdin.end();
      const pause = ms => new Promise(resolve => { const t = setTimeout(resolve, ms); done.then(() => { clearTimeout(t); resolve(); }); });
      await pause(500);
      for (const signal of ['SIGTERM', 'SIGKILL']) {
        // The guard owns a child too; tear down this test's entire process group.
        try { process.kill(-child.pid, signal); } catch (e) { if (e.code !== 'ESRCH') throw e; }
        if (!closed) await pause(1000);
      }
      reader.close();
      assert.ok(closed, 'peer did not terminate');
    },
  };
}
