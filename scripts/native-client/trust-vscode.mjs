import { appendFile, readFile } from 'node:fs/promises';

const accountPrompt = /sign.?in|account|oauth|authentication/i;

export function vscodeTrustButton(dialog, intent, workspace) {
  if (accountPrompt.test(dialog.text)) return;
  if (/Enable global auto approve\?/.test(dialog.text)) return dialog.buttons.find(button => button === 'Enable');
  if (/Do you trust the authors of the files in this (?:folder|workspace)\?/i.test(dialog.text)) {
    if (intent.workspace === 'persisted') throw Error('persisted workspace trust prompted again');
    return dialog.buttons.find(button => intent.workspace === 'allow'
      ? /trust (?:folder|workspace)|yes, i trust/i.test(button)
      : /restricted mode|don't trust|^Cancel$/i.test(button));
  }
  if (dialog.text.includes('native-fixture') && /trust and run|updated.*trust and run/is.test(dialog.text)) {
    if (intent.server === 'persisted') throw Error('persisted MCP server trust prompted again');
    return dialog.buttons.find(button => intent.server === 'allow' ? button === 'Trust' : button === 'Do not trust');
  }
  if ((dialog.text.includes(workspace) || /trust the authors|workspace trust|restricted mode/i.test(dialog.text)) && /trust/i.test(dialog.text)) throw Error('unrecognized fixture workspace trust prompt');
}

export async function vscodeTrustDialogs(port, work, log, signal) {
  const seen = new Set();
  while (!signal.aborted) {
    let ws;
    try {
      const intent = JSON.parse(await readFile(`${work}/trust-intent.json`, 'utf8').catch(error => {
        if (error.code === 'ENOENT') return 'null'; throw error;
      }));
      const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
      const page = pages.find(candidate => candidate.type === 'page' && candidate.url?.startsWith('vscode-file:'));
      if (page && intent) ws = new WebSocket(page.webSocketDebuggerUrl);
      if (!ws) throw Error('fixture page or trust intent not ready');
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(Error('UI connection deadline')), 1000);
        ws.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
        ws.addEventListener('error', event => { clearTimeout(timer); reject(event); }, { once: true });
      });
      const evaluate = expression => new Promise((resolve, reject) => {
        const id = Math.floor(Math.random() * 1000000);
        const timer = setTimeout(() => reject(Error('UI evaluation deadline')), 2000);
        const listener = event => {
          const result = JSON.parse(event.data); if (result.id !== id) return;
          clearTimeout(timer); ws.removeEventListener('message', listener); resolve(result.result?.result?.value);
        };
        ws.addEventListener('message', listener);
        ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }));
      });
      const dialogs = await evaluate("Array.from(new Set(document.querySelectorAll('.monaco-dialog-box,[role=dialog]'))).map(d=>({text:d.innerText,buttons:Array.from(d.querySelectorAll('.monaco-button,button')).map(b=>b.innerText)}))");
      for (const dialog of dialogs || []) {
        const snapshot = JSON.stringify(dialog);
        if (!seen.has(snapshot)) { seen.add(snapshot); await appendFile(`${work}/trust-ui.jsonl`, snapshot + '\n'); }
        const button = vscodeTrustButton(dialog, intent, intent.workspacePath);
        if (!button) continue;
        const clicked = await evaluate(`(()=>{const d=Array.from(new Set(document.querySelectorAll('.monaco-dialog-box,[role=dialog]'))).find(d=>d.innerText===${JSON.stringify(dialog.text)});const b=d&&Array.from(d.querySelectorAll('.monaco-button,button')).find(b=>b.innerText===${JSON.stringify(button)});if(b&&b.getAttribute('aria-disabled')!=='true'){b.click();return true;}return false;})()`);
        if (clicked) {
          const phase = /authors of the files/.test(dialog.text) ? 'workspace' : /Enable global auto approve\?/.test(dialog.text) ? 'tool-policy' : 'server';
          const decision = { phase, text: dialog.text, buttons: dialog.buttons, button };
          log.push(decision); await appendFile(`${work}/trust-ack.jsonl`, JSON.stringify(decision) + '\n');
        }
      }
    } catch (error) {
      if (signal.aborted) return;
      if (/persisted .* prompted again|unrecognized fixture workspace trust prompt/.test(String(error))) throw error;
    } finally { ws?.close(); }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}
