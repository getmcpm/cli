// Synthetic effects only. Every process has its own finite self-exit timer.
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import net from 'node:net';
import dgram from 'node:dgram';
const [root, nonce, tcpPort, udpPort, role = 'parent'] = process.argv.slice(2);
const scratch = `${root}/scratch/${nonce}`;
const prefix = `${scratch}/${role}`;
setTimeout(() => process.exit(0), 8000);

async function effects() {
  const row = { role, nonce, pid: process.pid, ppid: process.ppid, time: Date.now() };
  for (const [name, operation] of [
    ['read', () => createHash('sha256').update(fs.readFileSync(`${root}/forbidden/canary`)).digest('hex')],
    ['symlink', () => createHash('sha256').update(fs.readFileSync(`${scratch}/escape`)).digest('hex')],
    ['write', () => { fs.writeFileSync(`${root}/forbidden/${role}-output`, nonce); return true; }],
  ]) { try { row[name] = { value: operation() }; } catch (error) { row[name] = { error: error.code }; } }
  for (const kind of ['tcp', 'udp']) row[kind] = await new Promise(resolve => {
    let socket, finished = false;
    const finish = value => { if (finished) return; finished = true; clearTimeout(timer); if (kind === 'tcp') socket?.destroy(); else try { socket?.close(); } catch {} resolve(value); };
    const timer = setTimeout(() => finish({ error: 'TIMEOUT' }), 1000);
    const message = JSON.stringify({ nonce, role, pid: process.pid });
    if (kind === 'tcp') {
      socket = net.createConnection({ host: '127.0.0.1', port: Number(tcpPort) });
      socket.on('error', e => finish({ error: e.code }));
      socket.on('connect', () => socket.write(message + '\n'));
      socket.on('data', () => finish({ value: true }));
    } else {
      socket = dgram.createSocket('udp4'); socket.on('error', e => finish({ error: e.code }));
      socket.on('message', () => finish({ value: true }));
      socket.send(message, Number(udpPort), '127.0.0.1', e => { if (e) finish({ error: e.code }); });
    }
  });
  fs.appendFileSync(`${prefix}.ndjson`, JSON.stringify(row) + '\n');
  return row;
}

await effects();
if (role !== 'detached') {
  const childRole = role === 'parent' ? 'child' : 'detached';
    const fd = fs.openSync(`${scratch}/${childRole}.stderr`, 'a');
    const child = spawn(process.execPath, [import.meta.filename, root, nonce, tcpPort, udpPort, childRole], {
      env: process.env, cwd: scratch, detached: childRole === 'detached', stdio: ['ignore', fd, fd],
    });
    fs.closeSync(fd);
    fs.writeFileSync(`${scratch}/${childRole}.spawn.json`, JSON.stringify({ pid: child.pid, parentPid: process.pid, nonce, role: childRole }));
}
fs.writeFileSync(`${prefix}.ready`, JSON.stringify({ pid: process.pid, ppid: process.ppid, nonce, role }));
setInterval(() => fs.appendFileSync(`${prefix}.heartbeat`, JSON.stringify({ nonce, pid: process.pid, time: Date.now() }) + '\n'), 100);
while (true) { await new Promise(resolve => setTimeout(resolve, 250)); await effects(); }
