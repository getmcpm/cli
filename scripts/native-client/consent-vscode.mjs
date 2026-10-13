import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';

export function consentButton(dialog, intent) {
  if (/sign.?in|account|oauth|authentication|global auto approve/i.test(dialog.text)) return;
  if (!dialog.text.includes('native-fixture: Synthetic compatibility fixture.') ||
      !new RegExp('^Run `?' + intent.tool + '`?(?:\\n|$)').test(dialog.text)) return;
  if (intent.action === 'allow') return dialog.buttons.find(b => /^(Yes|Allow|Continue)$/.test(b));
  if (['deny', 'cancel'].includes(intent.action)) return dialog.buttons.find(b => b === 'Cancel');
}

export async function consentDialogs(work, log, signal) {
  const handled = new Set(), grants = new Map();
  while (!signal.aborted) {
    let ws;
    try {
      const intent = JSON.parse(await readFile(`${work}/consent-intent.json`, 'utf8'));
      if (handled.has(intent.text)) { await new Promise(r => setTimeout(r, 100)); continue; }
      const pages = await (await fetch('http://127.0.0.1:9222/json/list', { signal: AbortSignal.timeout(1000) })).json();
      const page = pages.find(p => p.type === 'page' && p.url?.startsWith('vscode-file:'));
      if (!page) continue;
      ws = new WebSocket(page.webSocketDebuggerUrl);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(Error('consent UI connection deadline')), 1000);
        ws.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
        ws.addEventListener('error', e => { clearTimeout(timer); reject(e); }, { once: true });
      });
      let serial = 0;
      const evaluate = expression => new Promise((resolve, reject) => {
        const id = ++serial, timer = setTimeout(() => { ws.removeEventListener('message', listener); reject(Error('consent UI evaluation deadline')); }, 2000);
        const listener = e => { const r = JSON.parse(e.data); if (r.id !== id) return; clearTimeout(timer); ws.removeEventListener('message', listener); if (r.result?.exceptionDetails) reject(Error('consent UI evaluation failed')); else resolve(r.result?.result?.value); };
        ws.addEventListener('message', listener); ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }));
      });
      const dialogs = await evaluate("Array.from(document.querySelectorAll('.monaco-dialog-box')).map(d=>({text:d.innerText,buttons:Array.from(d.querySelectorAll('.monaco-button')).map(b=>b.innerText)}))");
      for (const dialog of dialogs || []) {
        const button = consentButton(dialog, intent); if (!button) continue;
        const wire = await readFile(`${work}/wire.jsonl`, 'utf8').catch(e => { if (e.code !== 'ENOENT') throw e; return ''; });
        const calls = wire.split('\n').filter(Boolean).map(s => JSON.parse(s)).filter(w => w.direction === 'to-server' && w.message.method === 'tools/call' && w.message.params.arguments?.text === intent.text);
        assert.equal(calls.length, 0, 'tool dispatched before consent');
        if (intent.action === 'cancel') {
          for (const type of ['keyDown', 'keyUp']) ws.send(JSON.stringify({ id: ++serial, method: 'Input.dispatchKeyEvent', params: { type, key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 } }));
        } else {
          assert.equal(await evaluate(`(()=>{const d=Array.from(document.querySelectorAll('.monaco-dialog-box')).find(d=>d.innerText===${JSON.stringify(dialog.text)});const b=d&&Array.from(d.querySelectorAll('.monaco-button')).find(b=>b.innerText===${JSON.stringify(button)});if(!b||b.getAttribute('aria-disabled')==='true')return false;b.click();return true;})()`), true);
        }
        log.push({ ...intent, dialog, button: intent.action === 'cancel' ? 'Escape' : button, callsBeforeDecision: calls.length }); handled.add(intent.text);
      }
      if (intent.action === 'always') {
        const selected = await evaluate(`(()=>{
          const w=Array.from(document.querySelectorAll('.quick-input-widget')).find(w=>w.offsetWidth>0&&w.querySelector('input')?.placeholder==='Configure global tool approvals');if(!w)return;
          const rows=Array.from(w.querySelectorAll('.monaco-list-row')), start=rows.findIndex(r=>r.getAttribute('aria-level')==='1'&&r.innerText.includes('native-fixture'));if(start<0)return;
          const end=rows.findIndex((r,i)=>i>start&&r.getAttribute('aria-level')==='1');
          const row=rows.slice(start+1,end<0?undefined:end).find(r=>r.getAttribute('aria-level')==='2'&&r.innerText.trim().split('\\n')[0]===${JSON.stringify(intent.tool)});
          if(!row){rows[start].querySelector('.monaco-tl-twistie')?.click();return;}
          const c=row.querySelector('[role="checkbox"]');if(!c)return;const checked=c.getAttribute('aria-checked');
          if(checked==='false'){c.click();return {state:'clicked',text:w.innerText,tool:row.innerText,checked};}
          if(checked==='true')return {state:'checked',text:w.innerText,tool:row.innerText,checked};
        })()`);
        if (selected?.state === 'clicked') grants.set(intent.text, selected);
        if (selected?.state === 'checked' && grants.has(intent.text)) {
          log.push({ ...intent, selection: { before: grants.get(intent.text), after: selected } }); handled.add(intent.text);
          await writeFile(`${work}/consent-ack.json`, JSON.stringify(intent));
        }
      }
    } catch (e) {
      if (signal.aborted) return;
      if (e.code !== 'ENOENT' && !/fetch failed|deadline|ECONNREFUSED/.test(e.message)) { log.push({ error: e.stack }); throw e; }
    } finally { ws?.close(); }
    await new Promise(r => setTimeout(r, 100));
  }
}
