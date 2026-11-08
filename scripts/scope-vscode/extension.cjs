const vscode = require('vscode');
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const sha = text => crypto.createHash('sha256').update(text).digest('hex');
const waitFor = async (read, predicate) => {
  const deadline = Date.now() + 15000;
  do { const value = read(); if (predicate(value)) return value; await new Promise(resolve => setTimeout(resolve, 100)); } while (Date.now() < deadline);
  throw Error('native syntax observation deadline exceeded');
};
exports.run = async () => {
  const receipt = { status: 'fail', version: vscode.version, commands: [], transitions: [], diagnosticEvents: [] };
  let subscription;
  try {
    receipt.commands.push('workbench.mcp.openUserMcpJson');
    await vscode.commands.executeCommand(receipt.commands[0]);
    receipt.configPath = vscode.window.activeTextEditor?.document.uri.fsPath;
    assert.equal(receipt.configPath, '/home/node/.config/Code/User/mcp.json');
    await vscode.extensions.getExtension('vscode.json-language-features')?.activate();
    const document = await vscode.workspace.openTextDocument('/work/native-project/.vscode/mcp.json');
    const editor = await vscode.window.showTextDocument(document);
    receipt.projectPath = document.uri.fsPath; receipt.languageId = document.languageId;
    assert.equal(document.languageId, 'jsonc');
    const original = document.getText(); receipt.originalText = original; receipt.originalSha256 = sha(original); receipt.initialVersion = document.version;
    const diagnostics = () => vscode.languages.getDiagnostics(document.uri).map(row => ({ severity: row.severity, message: row.message, start: row.range.start, end: row.range.end }));
    subscription = vscode.languages.onDidChangeDiagnostics(event => {
      if (event.uris.some(uri => uri.toString() === document.uri.toString())) receipt.diagnosticEvents.push({ path: document.uri.fsPath, version: document.version, sha256: sha(document.getText()), diagnostics: diagnostics() });
    });
    const replace = async text => {
      assert.equal(await editor.edit(builder => builder.replace(new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), text)), true);
      receipt.transitions.push({ version: document.version, text: document.getText(), sha256: sha(document.getText()) });
    };
    receipt.initialDiagnosticsKind = 'snapshot'; receipt.initialDiagnostics = diagnostics();
    // In-memory malformed control, then restore identical inert bytes. No server exists in either document.
    await replace('{"servers":');
    const invalid = await waitFor(() => receipt.diagnosticEvents.find(event => event.version === document.version && event.sha256 === sha(document.getText()) && event.diagnostics.some(row => row.severity === vscode.DiagnosticSeverity.Error)), Boolean);
    receipt.invalidDiagnostics = invalid.diagnostics;
    await replace(original);
    const restored = await waitFor(() => receipt.diagnosticEvents.find(event => event.version === document.version && event.sha256 === sha(document.getText()) && !event.diagnostics.some(row => row.severity === vscode.DiagnosticSeverity.Error)), Boolean);
    receipt.restoredDiagnostics = restored.diagnostics;
    receipt.restoredSha256 = sha(document.getText());
    assert.equal(receipt.restoredSha256, receipt.originalSha256);
    if (document.isDirty) assert.equal(await document.save(), true);
    receipt.status = 'pass';
  } catch (error) { receipt.error = error.message; throw error; }
  finally { subscription?.dispose(); fs.writeFileSync('/evidence/native.json', JSON.stringify(receipt, null, 2) + '\n'); }
};
