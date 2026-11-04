// Record the native-facing wire, including guard output, without changing frames.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { appendFileSync } from 'node:fs';
const [work, home, mode] = process.argv.slice(2);
if (!work || !home || !['direct', 'guarded'].includes(mode)) throw Error('Invalid doctor recorder arguments');
const cli = new URL('./node_modules/@getmcpm/cli/dist/index.js', import.meta.url).pathname;
const serve = [cli, 'serve'];
const args = mode === 'guarded' ? [cli, 'guard', 'run', '--inner', '--server-name', 'native-doctor', '--', process.execPath, ...serve] : serve;
const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH, HOME: home, TMPDIR: '/tmp' }, stdio: ['pipe', 'pipe', 'inherit'] });
let bytes = 0;
function forward(input, output, direction) {
  const lines = createInterface({ input });
  lines.on('line', line => {
    bytes += Buffer.byteLength(line);
    if (bytes > 2 * 1024 * 1024) { child.kill('SIGKILL'); throw Error('Doctor wire budget exceeded'); }
    appendFileSync(`${work}/wire.jsonl`, JSON.stringify({ pid: child.pid, direction, message: JSON.parse(line) }) + '\n');
    output.write(line + '\n');
  });
  return lines;
}
const input = forward(process.stdin, child.stdin, 'to-server');
input.on('close', () => child.stdin.end());
forward(child.stdout, process.stdout, 'from-server');
child.on('error', error => { console.error(error); process.exitCode = 1; });
child.on('close', code => { input.close(); process.stdin.destroy(); process.exitCode = code ?? 1; });
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
