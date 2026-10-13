#!/opt/mcpm-native/node/bin/node
import assert from 'node:assert/strict';

const args = process.argv.slice(2);
assert.equal(args[0], '-y');
assert.match(args[1], /^@mcpm\/native-fixture@(1|2)\.0\.0$/);
const version = args[1].split('@').at(-1);
const marker = args.includes('--native-marker') ? args[args.indexOf('--native-marker') + 1] : '';
process.argv = [process.execPath, new URL('./peer.mjs', import.meta.url).pathname, version, marker];
await import('./peer.mjs');
