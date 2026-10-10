import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const launcher = fileURLToPath(new URL('../dogfood-protocol.sh', import.meta.url));

test('launcher stops a timed-out container before export and preserves failure status', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'protocol-launcher-'));
  try {
    await mkdir(`${root}/bin`);
    await symlink(process.execPath, `${root}/bin/node`);
    await writeFile(`${root}/bin/docker`, `#!/bin/sh
printf '%s\\n' "$*" >> "$DOCKER_LOG"
case "$1" in
  build) echo image ;;
  create) echo container ;;
  inspect) if [ "$3" = '{{.State.Running}}' ]; then echo "$RUNNING"; else echo '{}'; fi ;;
  image) echo '{}' ;;
  cp) printf '{"cases":[]}' > "$3/report.json" ;;
esac
`, { mode: 0o755 });
    // Exercise the real launcher without waiting 120 seconds or requiring Docker.
    await writeFile(`${root}/deadline.cjs`, `
const assert = require('node:assert/strict');
const cp = require('node:child_process');
const original = cp.spawnSync;
cp.spawnSync = (command, args, options) => {
  if (command !== 'docker' || args[0] !== 'start') return original(command, args, options);
  assert.equal(options.timeout, 120000);
  assert.equal(options.killSignal, 'SIGKILL');
  return process.env.RUNNING === 'true'
    ? { status: null, error: { code: 'ETIMEDOUT' }, signal: 'SIGKILL' }
    : { status: Number(process.env.EXIT_CODE), signal: null };
};
`);
    for (const exitCode of [0, 3, 124]) {
      const output = `${root}/evidence-${exitCode}`;
      const log = `${root}/docker-${exitCode}.log`;
      const result = spawnSync('bash', [launcher, output], { encoding: 'utf8', timeout: 10000, env: {
        ...process.env, PATH: `${root}/bin:${process.env.PATH}`, DOCKER_LOG: log,
        RUNNING: String(exitCode === 124), EXIT_CODE: String(exitCode), NODE_OPTIONS: `--require=${root}/deadline.cjs`,
      } });
      assert.equal(result.status, exitCode, result.stderr);
      const execution = JSON.parse(await readFile(`${output}/execution.json`, 'utf8'));
      assert.equal(execution.exitCode, exitCode);
      assert.equal(execution.status, exitCode ? 'fail' : 'pass');
      const calls = await readFile(log, 'utf8');
      if (exitCode === 124) assert.match(calls, /kill container\ncp container:\/evidence\/\./);
      assert.match(calls, /rm -fv container\n$/);
      const repeated = spawnSync('bash', [launcher, output], { encoding: 'utf8', timeout: 10000 });
      assert.notEqual(repeated.status, 0);
      assert.match(repeated.stderr, /Evidence directory must be empty/);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
