import { execFile } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

// Async commands let interruption reach the VM cleanup while a guest is busy.
export async function command(file, args, { input, ...options } = {}) {
  const pending = promisify(execFile)(file, args, { encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024, killSignal: 'SIGKILL', ...options });
  try {
    const transfer = input ? pipeline(createReadStream(input), pending.child.stdin) : pending.child.stdin.end();
    const [result] = await Promise.all([pending, transfer]);
    return { status: 0, ...result };
  } catch (error) {
    pending.child.kill('SIGKILL');
    return { status: Number.isInteger(error.code) ? error.code : null, signal: error.signal, error: error.code, stdout: error.stdout || '', stderr: error.stderr || error.message };
  }
}
