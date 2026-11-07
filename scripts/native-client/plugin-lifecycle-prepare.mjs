import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, cp, stat, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url)), root = path.resolve(here, '../..');
const [context, archive] = process.argv.slice(2);
assert.ok(context && archive, 'Usage: node plugin-lifecycle-prepare.mjs EMPTY_CONTEXT NATIVE_TGZ');
assert.equal((await readdir(context)).length, 0, 'context must be empty');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const pins = JSON.parse(await readFile(`${here}/plugin-lifecycle-pins.json`));
const lock = JSON.parse(await readFile(`${here}/package-lock.json`));
assert.equal(lock.packages[`node_modules/${pins.package}`].integrity, pins.integrity, 'existing native fixture pin drift');
assert.ok((await stat(archive)).isFile() && (await stat(archive)).size < 128 * 1024 * 1024);
const packed = await readFile(archive);
assert.equal(sha(packed), pins.archiveSha256);
assert.equal(`sha512-${createHash('sha512').update(packed).digest('base64')}`, pins.integrity);
// Exact pinned archive, bounded stdout only; never extract paths into the host filesystem.
const binary = execFileSync('tar', ['-xOzf', path.resolve(archive), 'package/claude'], { maxBuffer: pins.binaryBytes + 1, timeout: 15000 });
assert.equal(binary.length, pins.binaryBytes); assert.equal(sha(binary), pins.binarySha256);
const files = ['plugin-lifecycle.Dockerfile', 'plugin-lifecycle-run.mjs', 'plugin-lifecycle-checks.mjs', 'plugin-lifecycle-marker.mjs', 'plugin-lifecycle-pins.json'];
const inputs = { schemaVersion: 1, sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(), sourceFiles: {}, imageFiles: { '/opt/claude': pins.binarySha256 }, native: pins, nativeFixtureLockSha256: sha(await readFile(`${here}/package-lock.json`)) };
for (const name of [...files, 'plugin-lifecycle-prepare.mjs', '../dogfood-plugin-lifecycle.sh']) {
  const bytes = await readFile(`${here}/${name}`); inputs.sourceFiles[path.posix.normalize(`scripts/native-client/${name}`)] = sha(bytes);
  if (['plugin-lifecycle-run.mjs', 'plugin-lifecycle-checks.mjs', 'plugin-lifecycle-pins.json', 'plugin-lifecycle-marker.mjs'].includes(name)) inputs.imageFiles[`/probe/${name === 'plugin-lifecycle-marker.mjs' ? 'marker.mjs' : name}`] = sha(bytes);
}
await mkdir(`${context}/plugin-lifecycle-fixtures`, { recursive: true });
for (const version of ['v1', 'v2']) {
  await cp(`${here}/plugin-lifecycle-fixtures/${version}`, `${context}/plugin-lifecycle-fixtures/${version}`, { recursive: true });
  for (const name of ['.claude-plugin/plugin.json', 'hooks/hooks.json', 'skills/inert/SKILL.md']) {
    const digest = sha(await readFile(`${here}/plugin-lifecycle-fixtures/${version}/${name}`));
    inputs.sourceFiles[`scripts/native-client/plugin-lifecycle-fixtures/${version}/${name}`] = digest;
    inputs.imageFiles[`/probe/plugin-lifecycle-fixtures/${version}/${name}`] = digest;
  }
}
for (const name of files) await cp(`${here}/${name}`, `${context}/${name === 'plugin-lifecycle.Dockerfile' ? 'Dockerfile' : name}`);
await writeFile(`${context}/native`, binary, { mode: 0o600 });
await writeFile(`${context}/inputs.json`, JSON.stringify(inputs, null, 2) + '\n');
