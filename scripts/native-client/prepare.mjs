import { readFile, writeFile, mkdir, copyFile, access, readdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw Error('Usage: node prepare.mjs PAYLOAD_DIRECTORY');
const pins = JSON.parse(await readFile(`${here}/pins.json`));
await mkdir(out, { recursive: true });
if ((await readdir(out)).length > 0 && (await readFile(`${out}/pins.json`, 'utf8')) !== (await readFile(`${here}/pins.json`, 'utf8'))) {
  throw Error('Refuse an existing directory without matching native payload pins');
}
for (const file of ['package.json', 'package-lock.json', 'pins.json']) await copyFile(`${here}/${file}`, `${out}/${file}`);
for (const [name, pin] of [['node.tar.gz', pins.node], ['vscode.zip', pins.vscode]]) {
  try { await access(`${out}/${name}`); }
  catch {
    const r = await fetch(pin.url, { signal: AbortSignal.timeout(600000) });
    if (!r.ok) throw Error(`Download failed ${r.status}: ${pin.url}`);
    await writeFile(`${out}/${name}`, Buffer.from(await r.arrayBuffer()));
  }
  if (createHash('sha256').update(await readFile(`${out}/${name}`)).digest('hex') !== pin.sha256) throw Error(`Checksum mismatch: ${name}`);
}
await mkdir(`${out}/npm-home`, { recursive: true });
await writeFile(`${out}/npm-home/npmrc`, 'registry=https://registry.npmjs.org/\n');
const result = spawnSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', out], {
  stdio: 'inherit', timeout: 600000, env: { PATH: process.env.PATH, HOME: `${out}/npm-home`, npm_config_userconfig: `${out}/npm-home/npmrc` },
});
if (result.status !== 0) throw Error('Pinned native test dependencies failed to install');
console.log(`Verified public payload ready: ${out}`);
