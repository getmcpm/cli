import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { networkInterfaces } from 'node:os';
import assert from 'node:assert/strict';
import { checkReport, fixtureFiles, nativeFiles } from './check.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const readJSON = async file => JSON.parse(await fs.readFile(file, 'utf8'));
const put = async (file, text) => { await fs.mkdir(path.dirname(file), { recursive: true }); await fs.writeFile(file, text); };
// Preparation copies only public explicit inputs; it never builds/runs Code or the candidate.
if (process.argv[2] === '--prepare') {
  const [archive, codeArchive, output] = process.argv.slice(3);
  if (!archive || !codeArchive || !output || process.argv.length !== 6) throw Error('Usage: node run.mjs --prepare CANDIDATE_TGZ VSCODE_LINUX_ARM64_TGZ FRESH_CONTEXT');
  const root = await fs.realpath(new URL('../../', import.meta.url)), context = path.resolve(output);
  await fs.mkdir(context, { mode: 0o700 });
  const codeBytes = await fs.readFile(codeArchive);
  assert.equal(sha(codeBytes), '3b6ea238a2aa9000bab0137c19f06d4e8edcb5587438a3afc9dc9739e793e934');
  const retainedArchive = `${context}/vscode-input.tgz`; await fs.writeFile(retainedArchive, codeBytes);
  const listing = spawnSync('/usr/bin/tar', ['-tzf', retainedArchive], { encoding: 'utf8', maxBuffer: 2 ** 20 }); assert.equal(listing.status, 0, listing.stderr);
  const members = listing.stdout.trim().split('\n');
  assert.ok(members.length < 10000 && members.every(name => name === 'VSCode-linux-arm64' || (name.startsWith('VSCode-linux-arm64/') && !name.split('/').includes('..'))));
  // The exact pinned public archive was inspected as regular files/directories only (no links).
  await fs.mkdir(`${context}/vscode`);
  const extraction = spawnSync('/usr/bin/tar', ['-xzf', retainedArchive, '--strip-components=1', '--no-same-owner', '-C', `${context}/vscode`], { encoding: 'utf8' }); assert.equal(extraction.status, 0, extraction.stderr);
  await fs.rm(retainedArchive);
  for (const file of ['Dockerfile', 'run.mjs', 'check.mjs', 'extension.cjs']) await fs.copyFile(`${root}/scripts/scope-vscode/${file}`, `${context}/${file}`);
  for (const file of ['package.json', 'package-lock.json']) await fs.copyFile(`${root}/scripts/protocol-sandbox/${file}`, `${context}/${file}`);
  const pkg = await readJSON(`${context}/package.json`); pkg.dependencies['@getmcpm/cli'] = 'file:./candidate.tgz';
  await fs.writeFile(`${context}/package.json`, JSON.stringify(pkg)); await fs.copyFile(archive, `${context}/candidate.tgz`);
  const filesSha256 = {};
  for (const file of (await fs.readdir(`${root}/dist`)).filter(name => name.endsWith('.js')).sort()) filesSha256[file] = sha(await fs.readFile(`${root}/dist/${file}`));
  await fs.writeFile(`${context}/candidate.json`, JSON.stringify({ version: (await readJSON(`${root}/package.json`)).version, filesSha256 }));
  const inputs = { candidateSha256: sha(await fs.readFile(`${context}/candidate.tgz`)), codeArchiveSha256: sha(codeBytes), helpers: {}, codeFiles: {} };
  for (const file of ['Dockerfile', 'run.mjs', 'check.mjs', 'extension.cjs', 'package.json', 'package-lock.json', 'candidate.json']) inputs.helpers[file] = sha(await fs.readFile(`${context}/${file}`));
  async function inventory(directory) {
    for (const name of (await fs.readdir(directory)).sort()) { const file = `${directory}/${name}`, stat = await fs.lstat(file);
      if (stat.isDirectory()) await inventory(file);
      else { assert.ok(stat.isFile() && !stat.isSymbolicLink()); inputs.codeFiles[path.relative(`${context}/vscode`, file)] = { bytes: stat.size, sha256: sha(await fs.readFile(file)), mode: stat.mode & 0o777 }; }
    }
  }
  await inventory(`${context}/vscode`); await fs.writeFile(`${context}/inputs.json`, JSON.stringify(inputs, null, 2) + '\n');
  console.log(context); process.exit(0);
}
const cli = '/app/node_modules/@getmcpm/cli/dist/index.js';
const base = '/work/scope-cli', home = `${base}/home`, project = `${base}/project`;
const report = { schemaVersion: 1, cli: [], bindings: {} };
for (const file of ['/app/candidate.tgz', '/app/candidate.json', '/app/inputs.json', '/app/package-lock.json', '/app/run.mjs', '/app/check.mjs', '/app/extension.cjs', '/opt/vscode/code', '/opt/vscode/resources/app/product.json']) report.bindings[file] = sha(await fs.readFile(file));
await fs.copyFile('/app/inputs.json', '/evidence/inputs.json');
const candidate = await readJSON('/app/candidate.json');
const actualJS = {};
for (const file of (await fs.readdir(path.dirname(cli))).filter(file => file.endsWith('.js')).sort()) actualJS[file] = sha(await fs.readFile(path.join(path.dirname(cli), file)));
assert.deepEqual(actualJS, candidate.filesSha256, 'installed packed runtime matches candidate build');
report.runtimeJS = actualJS;
report.productCommit = (await readJSON('/opt/vscode/resources/app/product.json')).commit;
const env = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: home, TMPDIR: '/work/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
await fs.mkdir(env.TMPDIR, { recursive: true });
const markerPath = `${base}/EXECUTION_MARKER`;
const entry = { command: '/usr/local/bin/node', args: ['-e', `require('fs').writeFileSync(${JSON.stringify(markerPath)},'SCOPE_SECRET_EXEC')`], env: { TOKEN: 'SCOPE_SECRET_ENV' }, url: 'https://SCOPE_SECRET.invalid', headers: { Authorization: 'SCOPE_SECRET_HEADER' } };
const vsEntry = { ...entry, env: { ...entry.env, N: 2, REMOVE: null } };
const seeded = {
  'project/.vscode/mcp.json': `\uFEFF{ // JSONC\n "servers": ${JSON.stringify({ same: vsEntry })}, }`,
  'project/.mcp.json': JSON.stringify({ mcpServers: { same: entry } }),
  'home/.config/Code/User/mcp.json': `{ // JSONC\n "servers": ${JSON.stringify({ same: vsEntry })}, }`,
  'home/.copilot/mcp-config.json': JSON.stringify({ mcpServers: { same: entry } }),
  'home/.claude.json': JSON.stringify({ mcpServers: { user: entry }, projects: { [project]: { mcpServers: { local: entry } } } }),
  'project/.github/copilot-instructions.md': 'SCOPE_SECRET_INSTRUCTIONS @/outside/private\n',
  'AGENTS.md': 'SCOPE_SECRET_ANCESTOR\n',
  'home/.copilot/copilot-instructions.md': 'SCOPE_SECRET_USER_INSTRUCTIONS\n',
  'forbidden.json': '{"servers":{"SCOPE_SECRET_TARGET":{"command":"SCOPE_SECRET_COMMAND"}}}',
};
assert.deepEqual(Object.keys(seeded).sort(), [...fixtureFiles].sort());
for (const [file, text] of Object.entries(seeded)) await put(`${base}/${file}`, text);
report.fixtureBytes = seeded;
async function snapshot(files, prefix = '') {
  const result = {};
  for (const file of files) {
    const full = prefix + file;
    const stat = await fs.lstat(full);
    const mode = stat.mode & 0o777;
    if (stat.isSymbolicLink()) { result[file] = { state: 'symlink', target: await fs.readlink(full), mode }; continue; }
    // Controller-owned synthetic denied file only: observe bytes before/after, restore denied mode before CLI.
    if (mode === 0) await fs.chmod(full, 0o600);
    try { const bytes = await fs.readFile(full); result[file] = { state: 'file', mode, bytes: bytes.length, base64: bytes.toString('base64'), sha256: sha(bytes) }; }
    finally { if (mode === 0) await fs.chmod(full, 0); }
  }
  return result;
}
async function invoke(id, root = project, options = ['--client', 'vscode', '--json']) {
  const before = await snapshot(fixtureFiles, base + '/');
  const args = [cli, 'scope', root, ...options];
  const result = spawnSync(process.execPath, args, { cwd: project, env, encoding: 'utf8', timeout: 15000, maxBuffer: 2 ** 20, killSignal: 'SIGKILL' });
  let marker;
  try { const stat = await fs.lstat(markerPath); marker = { path: markerPath, state: 'present', bytes: stat.size }; }
  catch (error) { if (error.code !== 'ENOENT') throw error; marker = { path: markerPath, state: 'missing', code: error.code }; }
  report.cli.push({ id, command: process.execPath, args, cwd: project, env, status: result.status, signal: result.signal, error: result.error?.code,
    stdout: result.stdout || '', stderr: result.stderr || '', before, after: await snapshot(fixtureFiles, base + '/'), marker, markerExists: marker.state === 'present' });
}

let xvfb;
try {
  const status = await fs.readFile('/proc/self/status', 'utf8');
  report.boundary = { uid: process.getuid(), gid: process.getgid(), capEff: status.match(/^CapEff:\s+(\S+)/m)?.[1], noNewPrivs: status.match(/^NoNewPrivs:\s+(\S+)/m)?.[1], interfaces: Object.keys(networkInterfaces()) };
  try { await fs.writeFile('/app/should-be-readonly', 'test'); report.boundary.rootWriteError = 'unexpected-success'; } catch (error) { report.boundary.rootWriteError = error.code; }
  assert.equal(report.boundary.uid, 1000); assert.equal(report.boundary.gid, 1000); assert.match(report.boundary.capEff, /^0+$/);
  assert.equal(report.boundary.noNewPrivs, '1'); assert.deepEqual(report.boundary.interfaces, ['lo']); assert.equal(report.boundary.rootWriteError, 'EROFS');
  const control = spawnSync(entry.command, entry.args, { cwd: project, env, encoding: 'utf8', timeout: 10000 });
  report.sentinelControl = { command: entry.command, args: entry.args, env, status: control.status, signal: control.signal, error: control.error?.code, stdout: control.stdout || '', stderr: control.stderr || '', markerContents: await fs.readFile(markerPath, 'utf8') };
  await fs.rm(markerPath);
  try { await fs.lstat(markerPath); throw Error('positive-control marker was not removed'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  report.sentinelControl.removed = true;
  await invoke('vscode-json');
  await invoke('vscode-human', project, ['--client', 'vscode']);
  await invoke('claude-default', project, ['--json']);
  await invoke('claude-explicit', project, ['--client', 'claude-code', '--json']);
  await put(`${project}/.vscode/mcp.json`, '{"servers":{"duplicate":{},"duplicate":{}}}');
  await invoke('vscode-malformed'); await put(`${project}/.vscode/mcp.json`, seeded['project/.vscode/mcp.json']);
  await put(`${home}/.copilot/mcp-config.json`, '{ // user portable is strict JSON\n "mcpServers":{}, }');
  await invoke('vscode-user-jsonc'); await put(`${home}/.copilot/mcp-config.json`, seeded['home/.copilot/mcp-config.json']);
  await fs.rm(`${project}/.vscode/mcp.json`); await fs.symlink(`${base}/forbidden.json`, `${project}/.vscode/mcp.json`);
  await invoke('vscode-symlink'); await fs.rm(`${project}/.vscode/mcp.json`); await put(`${project}/.vscode/mcp.json`, seeded['project/.vscode/mcp.json']);
  await fs.chmod(`${project}/.vscode/mcp.json`, 0); await invoke('vscode-denied'); await fs.chmod(`${project}/.vscode/mcp.json`, 0o600);
  await invoke('missing-root', '/work/not-present'); await invoke('empty-root', '');
  await invoke('bad-client', project, ['--client', 'unsupported', '--json']);
  await put(`${project}/.mcp.json`, '{"servers":42,"visible-neighbor":{"command":"SCOPE_SECRET_COMMAND"}}');
  await invoke('vscode-bare');

  // Separate native fixtures: no server entries, tokens, extensions or provider sessions.
  const valid = '{ // inert project JSONC\n "servers": {}, "inputs": [], }\n';
  await put(nativeFiles[0], valid); await put(nativeFiles[1], valid);
  await put(nativeFiles[2], '{"mcpServers":{}}'); await put(nativeFiles[3], '{"mcpServers":{}}');
  await put(nativeFiles[4], JSON.stringify({ 'chat.mcp.autostart': 'never', 'chat.mcp.discovery.enabled': {}, 'telemetry.telemetryLevel': 'off', 'update.mode': 'none', 'extensions.autoUpdate': 'off', 'extensions.autoCheckUpdates': false, 'extensions.ignoreRecommendations': true, 'workbench.startupEditor': 'none' }));
  await fs.mkdir('/home/node/.cache', { recursive: true }); await fs.mkdir('/work/extensions', { recursive: true });
  await put('/work/extension/package.json', JSON.stringify({ name: 'mcpm-scope-validation', publisher: 'mcpm', version: '1.0.0', engines: { vscode: '*' }, main: './extension.cjs' }));
  await fs.copyFile('/app/extension.cjs', '/work/extension/extension.cjs');
  report.nativeBefore = await snapshot(nativeFiles);
  const nativeEnv = { PATH: env.PATH, HOME: '/home/node', TMPDIR: env.TMPDIR, LANG: env.LANG, LC_ALL: env.LC_ALL, DISPLAY: ':99' };
  const xArgs = [':99', '-screen', '0', '1280x800x24', '-nolisten', 'tcp', '-ac'];
  xvfb = spawn('/usr/bin/Xvfb', xArgs, { env: nativeEnv, stdio: ['ignore', 'ignore', 'pipe'] });
  report.xvfb = { command: '/usr/bin/Xvfb', args: xArgs, pid: xvfb.pid, stderr: '' }; xvfb.stderr.on('data', bytes => { report.xvfb.stderr += bytes; });
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) { try { await fs.lstat('/tmp/.X11-unix/X99'); break; } catch { await new Promise(resolve => setTimeout(resolve, 25)); } }
  const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--extensions-dir', '/work/extensions', '--skip-welcome', '--skip-release-notes', '--disable-updates', '--disable-telemetry', '--disable-workspace-trust', '--extensionDevelopmentPath', '/work/extension', '--extensionTestsPath', '/work/extension/extension.cjs', '--wait', '/work/native-project'];
  // HOME is the actual image account's /home/node, backed only by a private tmpfs. No user-data-dir override.
  const result = spawnSync('/opt/vscode/bin/code', args, { env: nativeEnv, cwd: '/work/native-project', encoding: 'utf8', timeout: 90000, maxBuffer: 8 * 2 ** 20, killSignal: 'SIGKILL' });
  report.nativeProcess = { command: '/opt/vscode/bin/code', args, env: nativeEnv, status: result.status, signal: result.signal, error: result.error?.code, stdout: result.stdout || '', stderr: result.stderr || '' };
  report.native = await readJSON('/evidence/native.json'); report.nativeAfter = await snapshot(nativeFiles);
  assert.equal(result.status, 0, 'native process completed');
  report.result = checkReport(report);
} catch (error) { report.measurementError = { name: error.name, message: error.message }; process.exitCode = 1; }
finally {
  if (xvfb && xvfb.exitCode === null) xvfb.kill('SIGTERM');
  await fs.writeFile('/evidence/report.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report.result || report.measurementError));
}
