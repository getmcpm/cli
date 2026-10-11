const vscode = require('vscode');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.dirname(__dirname);
exports.activate = () => {
  void exports.run().catch(e => console.error('Native smoke failed:', e.message)).finally(() => vscode.commands.executeCommand('workbench.action.quit'));
};
exports.run = async () => {
  const request = JSON.parse(fs.readFileSync(path.join(root, 'work/request.json')));
  const receipt = { client: 'vscode', version: vscode.version, case: request.case, status: 'fail', results: [] };
  const timer = setTimeout(() => { throw Error('native VS Code deadline exceeded'); }, 45000);
  try {
    await vscode.commands.executeCommand('workbench.mcp.openUserMcpJson');
    receipt.configPath = vscode.window.activeTextEditor?.document.uri.fsPath;
    assert.equal(receipt.configPath, '/Users/admin/Library/Application Support/Code/User/mcp.json');
    const listing = vscode.commands.executeCommand('workbench.mcp.listServer');
    await new Promise(resolve => setTimeout(resolve, 300));
    await vscode.commands.executeCommand('workbench.action.closeQuickOpen');
    await listing;
    let startupError;
    try {
      const startup = vscode.commands.executeCommand('workbench.mcp.startServer', '*', { autoTrustChanges: true, waitForLiveTools: true });
      if (request.case === 'drift') void startup.catch(e => { receipt.driftError = e.message; });
      else await startup;
    }
    catch (e) { startupError = e.message; if (request.case !== 'drift') throw e; }
    let tools = vscode.lm.tools;
    for (let i = 0; i < 20 && !tools.some(t => /(?:^|_)echo$/.test(t.name)) && !['absent', 'drift'].includes(request.case); i++) {
      await vscode.commands.executeCommand('workbench.mcp.startServer', '*', { autoTrustChanges: true, waitForLiveTools: true });
      await new Promise(resolve => setTimeout(resolve, 250)); tools = vscode.lm.tools;
    }
    receipt.tools = tools.map(t => t.name);
    if (request.case === 'drift') {
      receipt.startupError = startupError;
      for (let i = 0; i < 40; i++) {
        void vscode.commands.executeCommand('workbench.mcp.startServer', '*', { autoTrustChanges: true, waitForLiveTools: false })
          .then(undefined, e => { receipt.driftError = e.message; });
        const wireFile = path.join(root, 'work/wire.jsonl');
        const eventsFile = '/Users/admin/.mcpm/guard-events.jsonl';
        if (fs.existsSync(wireFile) && fs.readFileSync(wireFile, 'utf8').includes('"method":"tools/list"') &&
          fs.existsSync(eventsFile) && fs.readFileSync(eventsFile, 'utf8').includes('"signature_id":"schema-drift"')) { receipt.status = 'pass'; return; }
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      throw Error('native schema-drift block was not observed');
    }
    if (request.case === 'absent') {
      assert.ok(!tools.some(t => /(?:^|_)echo$/.test(t.name))); receipt.status = 'pass'; return;
    }
    const tool = name => {
      const match = tools.filter(t => t.name.endsWith('_' + name) || t.name === name);
      assert.equal(match.length, 1, `expected one native ${name} tool, got ${JSON.stringify(receipt.tools)}`);
      return match[0].name;
    };
    const invoke = (name, token) => vscode.lm.invokeTool(tool(name), { toolInvocationToken: undefined, input: { text: request.text } }, token);
    if (request.case === 'cancel') {
      const c = new vscode.CancellationTokenSource();
      const t = setTimeout(() => c.cancel(), 500);
      try { await assert.rejects(invoke('slow', c.token)); } finally { clearTimeout(t); c.dispose(); }
      receipt.results.push(await invoke('echo'));
    } else if (request.case === 'restart') {
      const stateFile = path.join(root, 'work/reload.json');
      if (!fs.existsSync(stateFile)) {
        const first = await invoke('echo');
        fs.writeFileSync(stateFile, JSON.stringify({ text: request.text, first }));
        await vscode.commands.executeCommand('workbench.action.reloadWindow');
        await new Promise(() => {}); // The replacement extension host completes this case.
      } else {
        const state = JSON.parse(fs.readFileSync(stateFile)); assert.equal(state.text, request.text);
        receipt.results.push(state.first, await invoke('echo')); receipt.restartAction = 'workbench.action.reloadWindow';
      }
    } else if (request.case === 'block') {
      let result;
      try { result = await invoke('attack'); }
      catch (e) { receipt.blockError = e.message; }
      if (result) receipt.results.push(result);
      assert.match(receipt.blockError || JSON.stringify(result), /BLOCKED by mcpm-guard/);
      receipt.results.push(await invoke('echo'));
    } else receipt.results.push(await invoke(request.case === 'warn' ? 'warn' : request.case === 'attack' ? 'attack' : 'echo'));
    receipt.status = 'pass';
  } catch (e) { receipt.error = e.stack; throw e; }
  finally {
    clearTimeout(timer);
    fs.writeFileSync(path.join(root, 'work/receipt.json'), JSON.stringify(receipt, null, 2));
  }
};
