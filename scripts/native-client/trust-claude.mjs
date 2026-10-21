import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';
import { serverName } from './fixture-registry.mjs';
import { claudeConsent, claudeStartup, terminalChoices } from './consent-claude.mjs';
import { TerminalScreen } from './terminal.mjs';

function choose(screen, predicate) {
  const numbered = terminalChoices(screen);
  const match = numbered.find(choice => predicate(choice.label));
  if (match) return match;
  const rows = screen.split('\n').map(line => /^\s*([❯›>●]?)\s*((?:Use|Continue|Yes|No)\b.*)$/.exec(line)).filter(Boolean);
  const selected = rows.findIndex(row => row[1]), target = rows.findIndex(row => predicate(row[2]));
  if (selected < 0 || target < 0) return;
  return { key: target === selected ? '' : target > selected ? '\x1b[B' : '\x1b[A', label: rows[target][2], selected: rows[selected][2] };
}

export function claudeProjectTrust(screen, request, root) {
  const startup = claudeStartup(screen, root);
  if (startup && screen.includes('Detected a custom API key in your environment')) return { ...startup, phase: 'api-key' };
  if (startup) {
    if (request.trust.workspace === 'persisted') throw Error('persisted workspace trust prompted again');
    if (request.trust.workspace === 'allow') return { ...startup, phase: 'workspace' };
    return { ...choose(screen, label => /^No, (?:exit|continue without these permissions)/.test(label)), phase: 'workspace' };
  }
  if (!screen.includes('New MCP server found in this project:') || !screen.includes(serverName)) return;
  if (request.trust.server === 'persisted') throw Error('persisted MCP server trust prompted again');
  const decision = request.trust.server === 'deny'
    ? choose(screen, label => label === 'Continue without using this MCP server')
    : choose(screen, label => label === 'Use this MCP server');
  return decision && { ...decision, phase: 'server' };
}

export async function interactiveClaudeTrust(command, env, root, cwd, work, request, model) {
  assert.match(env.ANTHROPIC_BASE_URL, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(env.ANTHROPIC_API_KEY, 'synthetic-native-fixture-key');
  const child = spawn('/usr/bin/expect', ['-f', fileURLToPath(new URL('./pty.tcl', import.meta.url)), '--', command, '--permission-mode', 'default'],
    { env, cwd, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const screen = new TerminalScreen(), decoder = new StringDecoder('utf8');
  const trustDecisions = [], startupDecisions = [], toolDecisions = [];
  let stdout = '', stderr = '', failure, exiting = false, closing = false, timedOut = false, lastScreen = '', stableSince = Date.now(), navigating, submission;
  const stop = signal => {
    const pid = /native-fixture PTY verified pid=(\d+)/.exec(stdout)?.[1];
    if (pid) { try { process.kill(-Number(pid), signal); } catch {} }
    try { process.kill(-child.pid, signal); } catch {}
  };
  const absorb = bytes => {
    try { const text = decoder.write(bytes); stdout += text; assert.ok(Buffer.byteLength(stdout) <= 1024 * 1024, 'terminal output budget exceeded'); screen.feed(text); }
    catch (error) { failure = error.stack; stop('SIGKILL'); }
  };
  child.stdout.on('data', absorb); child.stderr.on('data', bytes => { stderr = (stderr + bytes).slice(-1024 * 1024); });
  child.stdin.on('error', error => { if (!exiting) failure = error.stack; });
  const timeout = setTimeout(() => { timedOut = true; stop('SIGKILL'); }, 90000);
  let polling = false;
  const poll = setInterval(async () => {
    if (polling || exiting || failure) return; polling = true;
    try {
      const text = screen.text;
      if (text !== lastScreen) { lastScreen = text; stableSince = Date.now(); return; }
      if (Date.now() - stableSince < 300) return;
      const trust = claudeProjectTrust(text, request, cwd);
      if (trust?.phase === 'api-key' && !startupDecisions.length) {
        if (trust.key.startsWith('\x1b[')) { if (navigating !== trust.selected) { navigating = trust.selected; child.stdin.write(trust.key); } return; }
        navigating = undefined; startupDecisions.push({ ...trust, screen: text }); child.stdin.write('\r'); return;
      }
      if (trust && !trustDecisions.some(decision => decision.phase === trust.phase)) {
        if (trust.key.startsWith('\x1b[')) { if (navigating !== trust.selected) { navigating = trust.selected; child.stdin.write(trust.key); } return; }
        navigating = undefined;
        trustDecisions.push({ ...trust, screen: text }); child.stdin.write(trust.key + '\r'); return;
      }
      if (request.trust.workspace === 'deny') return;
      if (closing) { if (/^\s*❯\s*\/exit\b/m.test(text)) { exiting = true; child.stdin.write('\r'); } return; }
      const denied = trustDecisions.some(decision => decision.phase === 'server' && request.trust.server === 'deny');
      if (denied) {
        if (/^\s*❯\s*$/m.test(text)) { closing = true; child.stdin.write('/exit'); }
        return;
      }
      if (!submission) {
        const raw = await readFile(`${work}/wire.jsonl`, 'utf8').catch(error => { if (error.code !== 'ENOENT') throw error; return ''; });
        const wire = raw.split('\n').filter(Boolean).map(line => JSON.parse(line));
        const listing = wire.find(entry => entry.direction === 'to-server' && entry.message.method === 'tools/list');
        const complete = listing && wire.find(entry => entry.direction === 'from-server' && entry.pid === listing.pid && entry.message.id === listing.message.id && entry.message.result?.tools?.some(tool => tool.name === 'echo'));
        if (!complete || !/^\s*❯\s*$/m.test(text)) return;
        const prompt = `Run the native fixture ${request.case} check with text ${request.text}.`;
        submission = { prompt, toolsListId: listing.message.id, peerPid: listing.pid, screen: text };
        child.stdin.write(prompt); return;
      }
      if (!submission.confirmed) {
        if (!text.includes(submission.prompt)) return;
        submission.confirmed = true; child.stdin.write('\r'); return;
      }
      if (!toolDecisions.length) {
        const consent = claudeConsent(text, { ...request, consent: { action: 'allow', tool: 'echo' } });
        if (consent) {
          if (consent.key.startsWith('\x1b[')) { if (navigating !== consent.selected) { navigating = consent.selected; child.stdin.write(consent.key); } return; }
          navigating = undefined; toolDecisions.push({ ...consent, screen: text }); child.stdin.write(consent.key + '\r'); return;
        }
      }
      if (text.includes('Synthetic gateway observed the native tool result.') && model.results.length === 1) { closing = true; child.stdin.write('/exit'); }
    } catch (error) { failure = error.stack; stop('SIGKILL'); }
    finally { polling = false; }
  }, 100);
  try {
    const result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (status, signal) => resolve({ status, signal })); });
    return { ...result, command, args: ['--permission-mode', 'default'], cwd, stdout, stderr, timedOut, exiting, failure, trustDecisions, toolDecisions, submission, screen: screen.text,
      ptyVerified: stdout.includes('native-fixture PTY verified'), startupDecisions };
  } finally { clearInterval(poll); clearTimeout(timeout); child.stdin.destroy(); }
}
