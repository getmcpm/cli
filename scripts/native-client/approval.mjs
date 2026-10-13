export const fixtureInputPrompt = 'native-fixture synthetic input';
export const fixtureInputValue = 'synthetic input "quoted" \\ path';
export function fixtureInput(widget) {
  return !/sign.?in|account|oauth|authentication/i.test(widget.text) && widget.text.includes(fixtureInputPrompt) && widget.value === fixtureInputValue;
}

export function fixtureApproval(dialog) {
  if (/sign.?in|account|oauth|authentication/i.test(dialog.text)) return undefined;
  if (!/Enable global auto approve\?/.test(dialog.text) && !/native-fixtur/.test(dialog.text)) return undefined;
  return dialog.buttons.find(b => /^(Enable|Allow)$/.test(b));
}

// Click the normal consent UI only for the known synthetic fixture in the VM.
// Never mutate VS Code's approval database or accept sign-in/account dialogs.
export async function approveFixtureDialogs(port, log, signal) {
  while (!signal.aborted) {
    let ws;
    try {
      const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(1000) })).json();
      const page = pages.find(p => p.type === 'page' && p.url?.startsWith('vscode-file:'));
      if (page) {
        ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(Error('UI connection deadline')), 1000);
          ws.addEventListener('open', () => { clearTimeout(t); resolve(); }, { once: true });
          ws.addEventListener('error', e => { clearTimeout(t); reject(e); }, { once: true });
        });
        const evaluate = expression => new Promise((resolve, reject) => {
          const id = Math.floor(Math.random() * 1000000);
          const timer = setTimeout(() => reject(Error('UI evaluation deadline')), 2000);
          const listener = e => { const r = JSON.parse(e.data); if (r.id !== id) return; clearTimeout(timer); ws.removeEventListener('message', listener); resolve(r.result?.result?.value); };
          ws.addEventListener('message', listener); ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, returnByValue: true } }));
        });
        const dialogs = await evaluate("Array.from(document.querySelectorAll('.monaco-dialog-box')).map(d=>({text:d.innerText,buttons:Array.from(d.querySelectorAll('.monaco-button')).map(b=>b.innerText)}))");
        for (const dialog of dialogs || []) {
          const button = fixtureApproval(dialog);
          if (!button) continue;
          const clicked = await evaluate(`(()=>{const d=Array.from(document.querySelectorAll('.monaco-dialog-box')).find(d=>d.innerText===${JSON.stringify(dialog.text)});const b=d&&Array.from(d.querySelectorAll('.monaco-button')).find(b=>b.innerText===${JSON.stringify(button)});if(b&&b.getAttribute('aria-disabled')!=='true'){b.click();return true;}return false;})()`);
          if (clicked) log.push({ text: dialog.text, button });
        }
        const widgets = await evaluate("Array.from(document.querySelectorAll('.quick-input-widget')).filter(w=>w.offsetWidth>0).map(w=>({text:w.innerText,value:w.querySelector('input')?.value}))");
        if ((widgets || []).some(fixtureInput)) {
          for (const type of ['keyDown', 'keyUp']) ws.send(JSON.stringify({ id: Math.floor(Math.random() * 1000000), method: 'Input.dispatchKeyEvent', params: { type, key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 } }));
          log.push({ inputPrompt: fixtureInputPrompt, value: fixtureInputValue });
        }
      }
    } catch (e) { if (signal.aborted) return; }
    finally { ws?.close(); }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}
