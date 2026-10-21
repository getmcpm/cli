const vscode = require('vscode');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.dirname(__dirname);
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const wire = () => {
  const file = path.join(root, 'work/wire.jsonl');
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
};
const acknowledgements = () => {
  const file = path.join(root, 'work/trust-ack.jsonl');
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
};
async function runTrust(request, receipt) {
  const expectedWorkspaceDecision = request.trust.workspace === 'persisted' ? 0 : 1;
  if (request.trust.workspace !== 'persisted') receipt.workspaceTrustResult = await vscode.workspace.requestWorkspaceTrust();
  for (let i = 0; i < 100 && acknowledgements().filter(row => row.phase === 'workspace').length < expectedWorkspaceDecision; i++) await wait(100);
  assert.equal(acknowledgements().filter(row => row.phase === 'workspace').length, expectedWorkspaceDecision, 'missing or unexpected workspace trust decision');
  receipt.workspaceTrusted = vscode.workspace.isTrusted;
  receipt.workspace = vscode.workspace.workspaceFolders?.map(folder => folder.uri.fsPath) ?? [];
  if (request.trust.workspace === 'deny') {
    assert.equal(receipt.workspaceTrusted, false); await wait(1000);
    assert.equal(wire().length, 0, 'untrusted workspace started the project server');
    assert.ok(!vscode.lm.tools.some(tool => /(?:^|_)echo$/.test(tool.name)));
    receipt.status = 'pass'; return;
  }
  assert.equal(receipt.workspaceTrusted, true, 'workspace trust was not granted or persisted');
  await wait(2000);
  let startupError;
  try { await vscode.commands.executeCommand('workbench.mcp.startServer', '*', { autoTrustChanges: false, waitForLiveTools: true }); }
  catch (error) { startupError = error.message; }
  receipt.startupError = startupError;
  const expectedServerDecision = request.trust.server === 'persisted' ? 0 : 1;
  for (let i = 0; i < 100 && acknowledgements().filter(row => row.phase === 'server').length < expectedServerDecision; i++) await wait(100);
  assert.equal(acknowledgements().filter(row => row.phase === 'server').length, expectedServerDecision, 'missing or unexpected server trust decision');
  if (request.trust.server === 'deny') {
    await wait(500); assert.equal(wire().length, 0, 'distrusted server process started');
    receipt.cachedTools = vscode.lm.tools.map(tool => tool.name);
    receipt.status = 'pass'; return;
  }
  let tools = vscode.lm.tools;
  for (let i = 0; i < 30 && !tools.some(tool => /(?:^|_)echo$/.test(tool.name)); i++) {
    await vscode.commands.executeCommand('workbench.mcp.startServer', '*', { autoTrustChanges: false, waitForLiveTools: true });
    await wait(250); tools = vscode.lm.tools;
  }
  const matches = tools.filter(tool => tool.name.endsWith('_echo') || tool.name === 'echo');
  assert.equal(matches.length, 1, `expected trusted native echo tool, got ${JSON.stringify(tools.map(tool => tool.name))}`);
  const invocation = vscode.lm.invokeTool(matches[0].name, { toolInvocationToken: undefined, input: { text: request.text } });
  if (request.case === 'trust-server-allow') {
    for (let i = 0; i < 100 && !acknowledgements().some(row => row.phase === 'tool-policy'); i++) await wait(100);
    assert.equal(acknowledgements().filter(row => row.phase === 'tool-policy').length, 1, 'missing tool-policy setup decision');
  }
  receipt.results.push(await invocation);
  receipt.tools = tools.map(tool => tool.name); receipt.status = 'pass';
}
exports.activate = () => {
  void exports.run().catch(e => console.error('Native smoke failed:', e.message)).finally(() => vscode.commands.executeCommand('workbench.action.quit'));
};
exports.run = async () => {
  const request = JSON.parse(fs.readFileSync(path.join(root, 'work/request.json')));
  const receipt = { client: 'vscode', version: vscode.version, case: request.case, status: 'fail', results: [] };
  const timer = setTimeout(() => { throw Error('native VS Code deadline exceeded'); }, 45000);
  try {
    if (request.trust) { await runTrust(request, receipt); return; }
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
    const invoke = (name, token, text = request.text) => vscode.lm.invokeTool(tool(name), { toolInvocationToken: undefined, input: { text } }, token);
    if (request.consent) {
      const intentFile = path.join(root, 'work/consent-intent.json');
      const intent = { ...request.consent, text: request.text };
      if (request.case === 'one-shot') {
        for (let i = 1; i <= 2; i++) {
          const text = `${request.text}-${i}`;
          fs.writeFileSync(intentFile, JSON.stringify({ ...intent, text }));
          receipt.results.push(await invoke('echo', undefined, text));
        }
      } else {
      fs.writeFileSync(intentFile, JSON.stringify(intent));
      if (intent.action === 'always') {
        await vscode.commands.executeCommand('workbench.action.chat.editToolApproval', 'profile');
        const ackFile = path.join(root, 'work/consent-ack.json');
        let ack;
        for (let i = 0; i < 100; i++) {
          if (fs.existsSync(ackFile)) { ack = JSON.parse(fs.readFileSync(ackFile)); if (ack.text === request.text) break; }
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        assert.deepEqual(ack, intent, 'fixture profile grant was not made through the UI');
        await vscode.commands.executeCommand('workbench.action.closeQuickOpen');
        fs.writeFileSync(intentFile, JSON.stringify({ ...intent, action: 'persisted' }));
      }
      let result, error;
      try { result = await invoke(intent.tool); } catch (e) { error = e.message; }
      if (['deny', 'cancel'].includes(intent.action)) {
        assert.ok(error, 'refused invocation must reject'); receipt.refusal = error;
      } else if (request.case === 'block') {
        assert.match(error || JSON.stringify(result), /BLOCKED by mcpm-guard/);
        receipt.blockError = error; if (result) receipt.results.push(result);
        fs.writeFileSync(intentFile, JSON.stringify({ action: 'persisted', tool: 'echo', text: request.text }));
        receipt.results.push(await invoke('echo'));
      } else { assert.equal(error, undefined, error); receipt.results.push(result); }
      }
    } else if (request.case === 'cancel') {
      const wireFile = path.join(root, 'work/wire.jsonl');
      const readWire = () => fs.existsSync(wireFile) ? fs.readFileSync(wireFile, 'utf8').split('\n').slice(0, -1).map(line => JSON.parse(line)) : [];
      const offset = readWire().length;
      const c = new vscode.CancellationTokenSource();
      try {
        // Observe rejection immediately, including when startup fails before the wire call.
        const rejected = invoke('slow', c.token).then(() => false, () => true);
        let call;
        for (let i = 0; i < 100; i++) {
          call = readWire().slice(offset).find(w => w.direction === 'to-server' && w.message.method === 'tools/call' &&
            w.message.params?.name === 'slow' && w.message.params.arguments?.text === request.text);
          if (call) break;
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        assert.ok(call, 'native slow call did not reach the peer before cancellation deadline');
        receipt.cancelledRequestId = call.message.id;
        c.cancel();
        assert.equal(await rejected, true, 'native slow invocation must reject after cancellation');
      } finally { c.cancel(); c.dispose(); }
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
