import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';
import { TerminalScreen } from './terminal.mjs';

export function terminalChoices(screen) {
  const choices = [];
  for (const line of screen.split('\n')) {
    const m = /^\s*[❯›>●]?\s*(\d+)\.\s*(.+)/.exec(line);
    if (m) choices.push({ key: m[1], label: m[2].trim() });
    else if (choices.length && /^\s{3,}\S/.test(line)) choices.at(-1).label += ' ' + line.trim();
  }
  return choices;
}

function unnumberedChoice(screen, predicate) {
  const rows = screen.split('\n').map(line => /^\s*([❯›>●]?)\s*((?:Yes|No)\b.*)$/.exec(line)).filter(Boolean);
  const selected = rows.findIndex(r => r[1]), target = rows.findIndex(r => predicate(r[2]));
  if (selected < 0 || target < 0) return;
  return { key: (target > selected ? '\x1b[B' : '\x1b[A').repeat(Math.abs(target - selected)), label: rows[target][2] };
}

export function claudeStartup(screen, root) {
  if (screen.includes('Accessing workspace:') && screen.includes(root) && screen.includes('Quick safety check:') && /No, (exit|continue without these permissions)/.test(screen))
    return unnumberedChoice(screen, label => label === 'Yes, I trust this folder');
  if (screen.includes('Detected a custom API key in your environment') && screen.includes('ANTHROPIC_API_KEY:') && screen.includes('Do you want to use this API key?') && screen.includes('No (recommended)'))
    return unnumberedChoice(screen, label => label === 'Yes');
}

export function claudeConsent(screen, request) {
  const headers = [...screen.matchAll(/^\s*(?:Bash command|Tool use|Read file|Edit file|Write file|[^\n]* Tool:)\s*$/gm)];
  if (!headers.length) return;
  screen = screen.slice(headers.at(-1).index);
  if (!screen.includes('io.github.getmcpm/native-fixture') || !screen.includes(request.text)) return;
  if (!screen.includes('Do you want to proceed?')) return;
  const choices = terminalChoices(screen);
  if (!/\bNo\b/.test(screen) || !/\bYes\b/.test(screen)) return;
  const { action, tool } = request.consent;
  if (!screen.includes('native-fixture — ' + tool) && !screen.includes('native-fixture - ' + tool)) return;
  if (action === 'persisted') throw Error('persisted exact-tool permission prompted again');
  if (action === 'cancel') return { key: '\x1b', label: 'Escape' };
  const matches = label => action === 'always' ? label.startsWith("Yes, and don't ask again for ") && label.includes('native-fixture') && label.includes(tool + ' commands')
    : action === 'deny' ? /^No(?:$|\s)/.test(label) : /^Yes(?:$|\s*\()/.test(label);
  return choices.find(c => matches(c.label)) ?? unnumberedChoice(screen, matches);
}

export async function interactiveClaude(command, args, env, root, work, request, model) {
  assert.match(env.ANTHROPIC_BASE_URL, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(env.ANTHROPIC_API_KEY, 'synthetic-native-fixture-key');
  const child = spawn('/usr/bin/expect', ['-f', fileURLToPath(new URL('./pty.tcl', import.meta.url)), '--', command, ...args],
  { env, cwd: root, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const screen = new TerminalScreen(), decoder = new StringDecoder('utf8'), decisions = [], startup = [];
  let stdout = '', stderr = '', failure, exiting = false, timedOut = false, lastScreen = '';
  const stop = signal => {
    const pid = /native-fixture PTY verified pid=(\d+)/.exec(stdout)?.[1];
    if (pid) { try { process.kill(-Number(pid), signal); } catch {} }
    try { process.kill(-child.pid, signal); } catch {}
  };
  const absorb = b => {
    try { const text = decoder.write(b); stdout += text; assert.ok(Buffer.byteLength(stdout) <= 1024 * 1024, 'terminal output budget exceeded'); screen.feed(text); }
    catch (e) { failure = e.stack; stop('SIGKILL'); }
  };
  child.stdout.on('data', absorb); child.stderr.on('data', b => { stderr = (stderr + b).slice(-1024 * 1024); });
  child.stdin.on('error', e => { if (!exiting) failure = e.stack; });
  const timeout = setTimeout(() => { timedOut = true; stop('SIGKILL'); }, 90000);
  let polling = false;
  const poll = setInterval(async () => {
    if (polling || exiting || failure) return; polling = true;
    try {
      const text = screen.text;
      if (text === lastScreen) return; lastScreen = text;
      const setup = claudeStartup(text, root);
      if (setup && !startup.some(s => s.label === setup.label)) {
        assert.ok(!/sign.?in|oauth|browser.*login/i.test(text));
        startup.push({ ...setup, screen: text }); child.stdin.write(setup.key + '\r'); return;
      }
      const expectedDecisions = request.case === 'one-shot' ? 2 : request.consent.action === 'persisted' ? 0 : 1;
      if (decisions.length < expectedDecisions || request.consent.action === 'persisted') {
        const current = { ...request, text: request.case === 'one-shot' ? `${request.text}-${decisions.length + 1}` : request.text };
        const decision = claudeConsent(text, current);
        if (decision) {
          const raw = await readFile(`${work}/wire.jsonl`, 'utf8').catch(e => { if (e.code !== 'ENOENT') throw e; return ''; });
          const calls = raw.split('\n').filter(Boolean).map(s => JSON.parse(s)).filter(w => w.direction === 'to-server' && w.message.method === 'tools/call' && w.message.params.arguments?.text === current.text);
          assert.equal(calls.length, 0, 'Claude dispatched before permission');
          decisions.push({ ...decision, ...request.consent, text: current.text, screen: text, callsBeforeDecision: calls.length });
          child.stdin.write(decision.key + (decision.key === '\x1b' ? '' : '\r')); return;
        }
      }
      const finished = text.includes('Synthetic gateway observed the native tool result.') && model.results.length === (['block', 'one-shot'].includes(request.case) ? 2 : 1);
      const refused = decisions.length > 0 && ['deny', 'cancel'].includes(request.consent.action) &&
        /Interrupted|rejected|denied|What should Claude do instead/i.test(text) && /^\s*❯\s*$/m.test(text) && !claudeConsent(text, request);
      if (finished || refused) { exiting = true; child.stdin.write('/exit\r'); }
    } catch (e) { failure = e.stack; stop('SIGKILL'); }
    finally { polling = false; }
  }, 100);
  try {
    const result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (status, signal) => resolve({ status, signal })); });
    return { ...result, stdout, stderr, timedOut, exiting, failure, decisions, startup, screen: screen.text,
      ptyVerified: stdout.includes('native-fixture PTY verified') };
  } finally { clearInterval(poll); clearTimeout(timeout); child.stdin.destroy(); }
}
