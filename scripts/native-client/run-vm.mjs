import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdir, readdir, rm, copyFile, cp } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { checkPayload, cliArtifact, evidenceFiles, validateReport } from './checks.mjs';
import { command } from './command.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const [tart, storageArg, payloadArg, outputArg, ...flags] = process.argv.slice(2);
if (!outputArg) throw Error('Usage: node run-vm.mjs TART_BINARY TASK_VM_STORAGE PAYLOAD_DIRECTORY OUTPUT_DIRECTORY [--candidate] [--realistic-config]');
assert.ok(flags.every(f => ['--candidate', '--realistic-config'].includes(f)) && new Set(flags).size === flags.length, 'invalid runner flags');
const candidate = flags.includes('--candidate'), realistic = flags.includes('--realistic-config');
assert.ok(!realistic || candidate, 'realistic configuration tests require an explicit candidate');
assert.equal(process.platform, 'darwin'); assert.equal(process.arch, 'arm64');
const storage = path.resolve(storageArg), payload = path.resolve(payloadArg), output = path.resolve(outputArg);
await mkdir(output, { recursive: true }); assert.equal((await readdir(output)).length, 0, 'evidence directory must be empty');
await mkdir(storage, { recursive: true });
const owner = `${storage}/.mcpm-native-owner`;
try { assert.equal(await readFile(owner, 'utf8'), 'mcpm-native-client-validation\n'); }
catch (e) {
  if (e.code !== 'ENOENT') throw e;
  assert.equal((await readdir(storage)).length, 0, 'refuse existing VM storage without task ownership marker');
  await writeFile(owner, 'mcpm-native-client-validation\n', { flag: 'wx' });
}
const pins = JSON.parse(await readFile(`${here}/pins.json`));
const payloadBudget = await checkPayload(payload, candidate);
for (const [file, pin] of [['node.tar.gz', pins.node], ['vscode.zip', pins.vscode]]) {
  assert.equal(createHash('sha256').update(await readFile(`${payload}/${file}`)).digest('hex'), pin.sha256);
}
for (const file of (candidate ? ['pins.json'] : ['package.json', 'package-lock.json', 'pins.json'])) assert.equal(await readFile(`${payload}/${file}`, 'utf8'), await readFile(`${here}/${file}`, 'utf8'));
for (const [name, version] of [['@anthropic-ai/claude-code', pins.claudeCode], ['jsonc-parser', '3.3.1'], ...(!candidate ? [['@getmcpm/cli', pins.mcpm]] : [])]) {
  assert.equal(JSON.parse(await readFile(`${payload}/node_modules/${name}/package.json`)).version, version);
}
const artifact = await cliArtifact(payload, candidate);
const env = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TART_HOME: storage, TART_NO_AUTO_PRUNE: '1' };
const controller = new AbortController();
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => controller.abort(Error(signal)));
async function call(args, opts = {}) {
  const r = await command(tart, args, { env, signal: controller.signal, ...opts });
  assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr}\n${r.stdout}`); return r.stdout;
}
assert.equal((await call(['--version'])).trim(), pins.tart.version);
const stage = `${output}/stage`; await mkdir(stage);
// Whitelist public artifacts; never archive a checkout, home or host profile.
for (const file of ['package.json', 'package-lock.json', 'pins.json', 'node.tar.gz', 'vscode.zip', ...(candidate ? ['candidate.tgz'] : [])]) await copyFile(`${payload}/${file}`, `${stage}/${file}`);
await cp(`${payload}/node_modules`, `${stage}/node_modules`, { recursive: true, verbatimSymlinks: true });
for (const file of ['peer.mjs', 'launcher.mjs', 'fixture-registry.mjs', 'checks.mjs', 'gateway.mjs', 'approval.mjs', 'run-guest.mjs']) await copyFile(`${here}/${file}`, `${stage}/${file}`);
await cp(`${here}/vscode-extension`, `${stage}/vscode-extension`, { recursive: true });
await copyFile(`${repo}/src/guard/__tests__/fixtures/mcptox/warn/quoted-attack-phrase-near-non-rgi-flag.json`, `${stage}/warn.json`);
const archive = `${output}/payload.tar`;
const packed = await command('/usr/bin/tar', ['-cf', archive, '-C', stage, '.'], { signal: controller.signal }); assert.equal(packed.status, 0, packed.stderr);
const hashes = {};
for (const file of [...(await readdir(stage)).filter(f => /\.(mjs|json|tgz)$/.test(f)), 'vscode-extension/package.json', 'vscode-extension/tests.cjs']) {
  hashes[file] = createHash('sha256').update(await readFile(`${stage}/${file}`)).digest('hex');
}
const hostHashes = {};
for (const file of (await readdir(here)).filter(f => /\.(mjs|json)$/.test(f))) hostHashes[file] = createHash('sha256').update(await readFile(`${here}/${file}`)).digest('hex');
const report = { schemaVersion: 1, pins, cliArtifact: artifact, suite: realistic ? 'realistic-config' : 'baseline', hashes, hostHashes, payloadBudget, runFlags: ['--no-graphics', '--no-audio', '--no-usb-accessories', '--no-clipboard', '--net-host'], clients: [] };
await writeFile(`${output}/manifest.json`, JSON.stringify(report, null, 2));
for (const client of ['vscode', 'claude-code']) {
  const name = `mcpm-native-${client}-${randomBytes(4).toString('hex')}`;
  let running;
  if (controller.signal.aborted) break;
  let log = '';
  const row = { client, vm: name, status: 'fail' };
  try {
    await call(['clone', pins.image, name], { timeout: 1800000 });
    await call(['set', name, '--cpu', '2', '--memory', '6144', '--display', '1200x800']);
    running = spawn(tart, ['run', name, ...report.runFlags], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const logChunk = b => { log = (log + String(b)).slice(-1024 * 1024); };
    running.stdout.on('data', logChunk); running.stderr.on('data', logChunk);
    running.on('error', e => { logChunk(e.message); controller.abort(e); });
    const bootDeadline = Date.now() + 180000;
    while (true) {
      controller.signal.throwIfAborted();
      const probe = await command(tart, ['exec', name, '/usr/bin/true'], { env, timeout: 5000, signal: controller.signal });
      if (probe.status === 0) break;
      assert.ok(Date.now() < bootDeadline, 'guest agent boot deadline');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    row.vmConfig = JSON.parse(await call(['get', name, '--format', 'json']));
    await call(['exec', name, '/usr/bin/sudo', '/bin/mkdir', '-p', '/opt/mcpm-native']);
    await call(['exec', name, '/usr/bin/sudo', '/usr/sbin/chown', 'admin:staff', '/opt/mcpm-native']);
    await call(['exec', '-i', name, '/usr/bin/tar', '-xf', '-', '-C', '/opt/mcpm-native'], { timeout: 180000, input: archive });
    const provision = `set -eu
cd /opt/mcpm-native
mkdir node
tar -xf node.tar.gz -C node --strip-components 1
sudo /usr/bin/ditto -x -k vscode.zip /Applications
/usr/bin/codesign --verify --deep --strict '/Applications/Visual Studio Code.app'
printf 'set skip on lo0\\nblock drop all\\n' > native.pf
sudo /sbin/pfctl -f native.pf
sudo /sbin/pfctl -e || sudo /sbin/pfctl -s info | grep -q Enabled
/opt/mcpm-native/node/bin/node node_modules/@anthropic-ai/claude-code/install.cjs
PATH=/opt/mcpm-native/node/bin:/usr/bin:/bin node_modules/.bin/claude --version
printf 'export PATH=/opt/mcpm-native/bin:/opt/mcpm-native/node/bin:/opt/mcpm-native/node_modules/.bin:/usr/bin:/bin:/usr/sbin:/sbin\\n' > /Users/admin/.zprofile
sw_vers
id
`;
    row.provision = await call(['exec', name, '/bin/bash', '-c', provision], { timeout: 180000 });
    const result = await command(tart, ['exec', name, '/opt/mcpm-native/node/bin/node', '/opt/mcpm-native/run-guest.mjs', client, ...(candidate ? ['candidate'] : []), ...(realistic ? ['realistic'] : [])], { env, timeout: 900000, signal: controller.signal });
    await writeFile(`${output}/${client}-execution.json`, JSON.stringify({ status: result.status, signal: result.signal, error: result.error, stdout: result.stdout, stderr: result.stderr }, null, 2));
    const exporter = "const fs=require('node:fs');const d='/opt/mcpm-native/evidence';const out={};const names=fs.readdirSync(d);if(names.length>32)throw Error('Evidence file count');let total=0;for(const n of names){const stat=fs.lstatSync(d+'/'+n);if(!/^[a-z0-9.-]+\\.json$/.test(n)||!stat.isFile())throw Error('Invalid evidence file');total+=stat.size;if(stat.size>4*1024*1024||total>16*1024*1024)throw Error('Evidence budget');out[n]=JSON.parse(fs.readFileSync(d+'/'+n,'utf8'));}process.stdout.write(JSON.stringify(out));";
    const exported = JSON.parse(await call(['exec', name, '/opt/mcpm-native/node/bin/node', '-e', exporter], { maxBuffer: 16 * 1024 * 1024 }));
    const evidence = `${output}/${client}`; await mkdir(evidence);
    for (const [file, value] of evidenceFiles(exported)) {
      await writeFile(`${evidence}/${file}`, JSON.stringify(value, null, 2), { flag: 'wx' });
    }
    row.report = JSON.parse(await readFile(`${evidence}/report.json`));
    assert.equal(result.status, 0, result.stderr + result.stdout);
    validateReport(row.report, client, pins, hashes, exported, artifact);
    assert.equal(row.report.suite, report.suite); row.status = 'pass';
  } catch (e) { row.reason = e.stack; }
  finally {
    const stop = await command(tart, ['stop', name], { env, timeout: 20000, encoding: 'utf8' });
    if (running && running.exitCode === null && running.signalCode === null) await new Promise(resolve => {
      const timer = setTimeout(() => { running.kill('SIGKILL'); resolve(); }, 10000);
      running.once('close', () => { clearTimeout(timer); resolve(); });
    });
    const deleted = await command(tart, ['delete', name], { env, timeout: 20000, encoding: 'utf8' });
    row.cleanup = { stopStatus: stop.status, deleteStatus: deleted.status };
    if (deleted.status !== 0) row.status = 'fail';
    await writeFile(`${output}/${client}-vm.log`, log);
    report.clients.push(row); await writeFile(`${output}/manifest.json`, JSON.stringify(report, null, 2));
  }
}
await rm(stage, { recursive: true, force: true }); await rm(archive, { force: true });
process.exitCode = !controller.signal.aborted && report.clients.length === 2 && report.clients.every(r => r.status === 'pass') ? 0 : 1;
