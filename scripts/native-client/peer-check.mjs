import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

for (const version of ['2025-06-18', '2025-11-25', 'unsupported']) {
  test(`native peer negotiates ${version}`, () => {
    const work = mkdtempSync(path.join(os.tmpdir(), 'native-peer-check-'));
    try {
      const result = spawnSync(process.execPath, [fileURLToPath(new URL('./peer.mjs', import.meta.url)), '1.0.0'], {
        env: { MCPM_NATIVE_WORK: work }, encoding: 'utf8', timeout: 5000,
        input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: version } }) + '\n',
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).result.protocolVersion, version === 'unsupported' ? '2025-11-25' : version);
    } finally { rmSync(work, { recursive: true, force: true }); }
  });
}
