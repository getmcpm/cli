import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, readdir, rm, copyFile, cp } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { evidenceFiles, validateReport } from './checks.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const [tart, storageArg, payloadArg, outputArg] = process.argv.slice(2);
if (!outputArg) throw Error('Usage: node run-vm.mjs TART_BINARY TASK_VM_STORAGE PAYLOAD_DIRECTORY OUTPUT_DIRECTORY');
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
for (const [file, pin] of [['node.tar.gz', pins.node], ['vscode.zip', pins.vscode]]) {
  assert.equal(createHash('sha256').update(await readFile(`${payload}/${file}`)).digest('hex'), pin.sha256);
}
assert.equal(await readFile(`${payload}/package-lock.json`, 'utf8'), await readFile(`${here}/package-lock.json`, 'utf8'));
for (const [name, version] of [['@getmcpm/cli', pins.mcpm], ['@anthropic-ai/claude-code', pins.claudeCode]]) {
  assert.equal(JSON.parse(await readFile(`${payload}/node_modules/${name}/package.json`)).version, version);
}
const env = { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', TART_HOME: storage, TART_NO_AUTO_PRUNE: '1' };
function call(args, opts = {}) {
  const r = spawnSync(tart, args, { encoding: 'utf8', env, timeout: 60000, maxBuffer: 8 * 1024 * 1024, ...opts });
  assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr}\n${r.stdout}`); return r.stdout;
}
assert.equal(call(['--version']).trim(), pins.tart.version);
const stage = `${output}/stage`; await mkdir(stage);
// Whitelist public artifacts; never archive a checkout, home or host profile.
for (const file of ['package.json', 'package-lock.json', 'pins.json', 'node.tar.gz', 'vscode.zip']) await copyFile(`${payload}/${file}`, `${stage}/${file}`);
await cp(`${payload}/node_modules`, `${stage}/node_modules`, { recursive: true, verbatimSymlinks: true });
for (const file of ['peer.mjs', 'launcher.mjs', 'fixture-registry.mjs', 'checks.mjs', 'gateway.mjs', 'approval.mjs', 'run-guest.mjs']) await copyFile(`${here}/${file}`, `${stage}/${file}`);
await cp(`${here}/vscode-extension`, `${stage}/vscode-extension`, { recursive: true });
await copyFile(`${repo}/src/guard/__tests__/fixtures/mcptox/warn/quoted-attack-phrase-near-non-rgi-flag.json`, `${stage}/warn.json`);
const archive = `${output}/payload.tar`;
const packed = spawnSync('/usr/bin/tar', ['-cf', archive, '-C', stage, '.'], { encoding: 'utf8', timeout: 60000 }); assert.equal(packed.status, 0, packed.stderr);
const report = { schemaVersion: 1, pins, runFlags: ['--no-graphics', '--no-audio', '--no-usb-accessories', '--no-clipboard', '--net-host'], clients: [] };
await writeFile(`${output}/manifest.json`, JSON.stringify(report, null, 2));
for (const client of ['vscode', 'claude-code']) {
  const name = `mcpm-native-${client}-${randomBytes(4).toString('hex')}`;
  let running;
  const log = [];
  const row = { client, vm: name, status: 'fail' };
  try {
    call(['clone', pins.image, name], { timeout: 1800000 });
    call(['set', name, '--cpu', '2', '--memory', '6144', '--display', '1200x800']);
    running = spawn(tart, ['run', name, ...report.runFlags], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    running.stdout.on('data', b => { log.push(String(b)); }); running.stderr.on('data', b => { log.push(String(b)); });
    const bootDeadline = Date.now() + 180000;
    while (true) {
      const probe = spawnSync(tart, ['exec', name, '/usr/bin/true'], { env, timeout: 5000, encoding: 'utf8' });
      if (probe.status === 0) break;
      assert.ok(Date.now() < bootDeadline, 'guest agent boot deadline');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    row.vmConfig = JSON.parse(call(['get', name, '--format', 'json']));
    call(['exec', name, '/usr/bin/sudo', '/bin/mkdir', '-p', '/opt/mcpm-native']);
    call(['exec', name, '/usr/bin/sudo', '/usr/sbin/chown', 'admin:staff', '/opt/mcpm-native']);
    const archiveFd = (await import('node:fs')).openSync(archive, 'r');
    try { call(['exec', '-i', name, '/usr/bin/tar', '-xf', '-', '-C', '/opt/mcpm-native'], { timeout: 180000, stdio: [archiveFd, 'pipe', 'pipe'] }); }
    finally { (await import('node:fs')).closeSync(archiveFd); }
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
    row.provision = call(['exec', name, '/bin/bash', '-c', provision], { timeout: 180000 });
    const result = spawnSync(tart, ['exec', name, '/opt/mcpm-native/node/bin/node', '/opt/mcpm-native/run-guest.mjs', client], { env, timeout: 900000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    await writeFile(`${output}/${client}-execution.json`, JSON.stringify({ status: result.status, signal: result.signal, error: result.error?.code, stdout: result.stdout, stderr: result.stderr }, null, 2));
    const exporter = "const fs=require('node:fs');const d='/opt/mcpm-native/evidence';const out={};for(const n of fs.readdirSync(d)){if(!/^[a-z0-9.-]+\\.json$/.test(n)||fs.lstatSync(d+'/'+n).isSymbolicLink())throw Error('Invalid evidence file');const s=fs.readFileSync(d+'/'+n,'utf8');if(s.length>4*1024*1024)throw Error('Evidence budget');out[n]=JSON.parse(s);}process.stdout.write(JSON.stringify(out));";
    const exported = JSON.parse(call(['exec', name, '/opt/mcpm-native/node/bin/node', '-e', exporter], { maxBuffer: 32 * 1024 * 1024 }));
    const evidence = `${output}/${client}`; await mkdir(evidence);
    for (const [file, value] of evidenceFiles(exported)) {
      await writeFile(`${evidence}/${file}`, JSON.stringify(value, null, 2), { flag: 'wx' });
    }
    row.report = JSON.parse(await readFile(`${evidence}/report.json`));
    assert.equal(result.status, 0, result.stderr + result.stdout);
    validateReport(row.report, client, client === 'vscode' ? pins.vscode.version : pins.claudeCode); row.status = 'pass';
  } catch (e) { row.reason = e.stack; }
  finally {
    const stop = spawnSync(tart, ['stop', name], { env, timeout: 20000, encoding: 'utf8' });
    if (running) await new Promise(resolve => { if (running.exitCode !== null) resolve(); else { running.once('close', resolve); setTimeout(() => { running.kill('SIGKILL'); resolve(); }, 10000).unref(); } });
    const deleted = spawnSync(tart, ['delete', name], { env, timeout: 20000, encoding: 'utf8' });
    row.cleanup = { stopStatus: stop.status, deleteStatus: deleted.status };
    if (deleted.status !== 0) row.status = 'fail';
    await writeFile(`${output}/${client}-vm.log`, log.join('').slice(-1024 * 1024));
    report.clients.push(row); await writeFile(`${output}/manifest.json`, JSON.stringify(report, null, 2));
  }
}
await rm(stage, { recursive: true, force: true }); await rm(archive, { force: true });
process.exitCode = report.clients.every(r => r.status === 'pass') ? 0 : 1;
