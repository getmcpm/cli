import { test } from 'node:test';
import assert from 'node:assert/strict';
import { equivalent, exchange } from './harness.mjs';

test('comparison refuses changed results and missing observations', () => {
  assert.throws(() => equivalent({ content: ['a'] }, { content: ['b'] }));
  assert.throws(() => equivalent(undefined, undefined));
  equivalent({ content: ['a'] }, { content: ['a'] });
});

test('wire requests correlate out-of-order responses and ignore notifications', async () => {
  const session = exchange(process.execPath, ['-e', `
    const rl = require('node:readline').createInterface({input: process.stdin});
    const queue = [];
    rl.on('line', line => {
      queue.push(JSON.parse(line));
      if (queue.length === 2) {
        console.log(JSON.stringify({jsonrpc:'2.0',method:'notifications/message',params:{}}));
        for (const r of queue.reverse()) console.log(JSON.stringify({jsonrpc:'2.0',id:r.id,result:{value:r.id}}));
      }
    });
  `]);
  try {
    const results = await Promise.all([session.request('one'), session.request('two')]);
    assert.deepEqual(results.map(r => r.result.value), [1, 2]);
  } finally { await session.close(); }
});

test('silent and disconnected peers reject within a deadline', async () => {
  for (const code of ['setInterval(()=>{},1000)', 'process.exit(0)']) {
    const session = exchange(process.execPath, ['-e', code]);
    try { await assert.rejects(session.request('test', {}, 100)); }
    finally { await session.close(); }
    assert.equal(session.child.exitCode !== null || session.child.signalCode !== null, true);
  }
});

test('output without a newline cannot grow the reader without a bound', async () => {
  const session = exchange(process.execPath, ['-e', "process.stdout.write(Buffer.alloc(17*1024*1024, 120));setInterval(()=>{},1000)"]);
  try { await assert.rejects(session.request('test'), /wire byte budget exceeded/); }
  finally { await session.close(); }
});
