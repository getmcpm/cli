import { afterEach, describe, expect, it, vi } from "vitest";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import * as fs from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { buildScopeModel, buildVSCodeScopeModel, renderScope, registerScopeCommand } from "../../commands/scope.js";
import { Command } from "commander";
import os from "node:os";

vi.mock("node:fs/promises", async importOriginal => ({
  ...await importOriginal<typeof import("node:fs/promises")>(),
}));

const roots: string[] = [];
async function fixture() {
  const base = await realpath(await mkdtemp(path.join(tmpdir(), "mcpm-vscode-scope-")));
  roots.push(base);
  const home = path.join(base, "home"), project = path.join(base, "workspace", "project");
  const profile = path.join(home, ".config", "Code", "User");
  for (const dir of [profile, project, path.join(project, ".vscode"), path.join(home, ".copilot")]) await mkdir(dir, { recursive: true });
  return { base, home, project, profile, deps: { home, platform: "linux" as const },
    projectVS: path.join(project, ".vscode", "mcp.json"), projectPortable: path.join(project, ".mcp.json"),
    userVS: path.join(profile, "mcp.json"), userPortable: path.join(home, ".copilot", "mcp-config.json") };
}
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });

describe("VS Code fixed scope inventory", () => {
  it("retains four format/origin identities and duplicates without a winner or values", async () => {
    const f = await fixture();
    const entry = { command: "DO_NOT_EXECUTE", args: ["SECRET_ARGS"], env: { TOKEN: "SECRET_ENV" }, url: "https://SECRET_URL", headers: { Authorization: "SECRET_HEADER" } };
    for (const file of [f.projectVS, f.userVS]) await writeFile(file, JSON.stringify({ servers: { same: entry } }));
    for (const file of [f.projectPortable, f.userPortable]) await writeFile(file, JSON.stringify({ mcpServers: { same: entry } }));
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.client).toBe("vscode"); expect(model.schemaVersion).toBe(1);
    expect(model.inventoryComplete).toBe(true);
    expect(model.sources.map(source => [source.origin, source.format])).toEqual([
      ["vscode-project", "vscode"], ["copilot-project", "copilot-portable"],
      ["vscode-user", "vscode"], ["copilot-user", "copilot-portable"],
    ]);
    expect(model.servers).toHaveLength(4);
    expect(model.servers.every(server => server.sameNameIn.length === 3 && server.effective === "unknown")).toBe(true);
    expect(model.servers.every(server => !("possibleShadowedBy" in server))).toBe(true);
    for (const output of [JSON.stringify(model), renderScope(model)]) expect(output).not.toMatch(/SECRET_|DO_NOT_EXECUTE/);
    expect(model.loaded).toBe("unknown"); expect(model.enforced).toBe("unknown");
    expect(model.coverage.join(" ")).toMatch(/forward/i);
  });

  it("accepts VS Code JSONC/BOM and valid numeric/null env while keeping wrapper identity unknown", async () => {
    const f = await fixture();
    const bytes = '\uFEFF{ // comment\r\n "servers": {"mültibyte": {"command":"mcpm","args":["guard","run"],"env":{"N":2,"REMOVE":null}},}, }';
    await writeFile(f.projectVS, bytes);
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[0].state).toBe("present");
    expect(model.servers[0]).toMatchObject({ name: "mültibyte", declaration: "object", guardForm: "unknown" });
    expect(await readFile(f.projectVS, "utf8")).toBe(bytes);
  });

  it.each([
    'null', '[]', '{"servers":null}', '{"servers":[]}',
    '{"servers":{"x":null}}', '{"servers":{"x":{"args":"SECRET_BAD"}}}',
    '{"servers":{"x":{"env":{"BAD":true}}}}',
    '{"servers":{"x":{},"x":{}}}', '{"servers":{},"servers":{}}',
    '{"servers":{"x":{"env":{"same":"one","same":"two"}}}}',
    '{"mcpServers":{"wrong":{"command":"SECRET_WRONG"}}}',
  ])("keeps invalid/wrong-format source incomplete without suppressing a valid other source: %s", async raw => {
    const f = await fixture(); await writeFile(f.projectVS, raw);
    await writeFile(f.projectPortable, '{"mcpServers":{"intact":{}}}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[0].state).toBe("malformed"); expect(model.inventoryComplete).toBe(false);
    expect(model.servers.some(server => server.name === "intact" && server.origin === "copilot-project")).toBe(true);
    expect(JSON.stringify(model)).not.toMatch(/SECRET_/);
  });

  it("rejects the VS Code root in a portable file and preserves prototype-like server names", async () => {
    const f = await fixture();
    await writeFile(f.projectPortable, '{"servers":{"wrong":{}}}');
    await writeFile(f.projectVS, '{"servers":{"__proto__":{},"constructor":{},"toString":{}}}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[1].state).toBe("malformed");
    expect(model.servers.map(server => server.name)).toEqual(["__proto__", "constructor", "toString", "servers"]);
    expect(model.servers.at(-1)?.declaration).toBe("malformed");
  });

  it("does not let a malformed bare server named servers hide a legitimate neighboring declaration", async () => {
    const f = await fixture();
    await writeFile(f.projectPortable, '{"servers":42,"visible-neighbor":{"command":"DO_NOT_EXECUTE"}}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[1]).toMatchObject({ state: "malformed", container: "bare" });
    expect(model.servers.map(row => [row.name, row.declaration])).toEqual([["servers", "malformed"], ["visible-neighbor", "object"]]);
    expect(JSON.stringify(model)).not.toContain("DO_NOT_EXECUTE");
  });

  it.each(["servers", "mcpServers"])("preserves prototype-like names and rejects nested duplicates in %s", async key => {
    const f = await fixture(), file = key === "servers" ? f.projectVS : f.projectPortable;
    await writeFile(file, `{ // JSONC\n "${key}": {"__proto__":{},"constructor":{},"toString":{}}, }`);
    expect((await buildVSCodeScopeModel(f.project, f.deps)).servers.map(row => row.name)).toEqual(["__proto__", "constructor", "toString"]);
    await writeFile(file, `{ "${key}": {"x":{"env":{"TOKEN":"SECRET_ONE","TOKEN":"SECRET_TWO"}}} }`);
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources.find(row => row.path === file)?.state).toBe("malformed");
    expect(JSON.stringify(model)).not.toMatch(/SECRET_/);
  });

  it("distinguishes JSONC/bare project portable input from strict wrapped user portable input", async () => {
    const f = await fixture();
    await writeFile(f.projectPortable, '{ // project JSONC/bare map\n "legacy":{"command":"node"}, "servers":{"command":"node"}, }');
    await writeFile(f.userPortable, '{ // not user JSON\n "mcpServers":{"user":{}}, }');
    let model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[1]).toMatchObject({ state: "present", container: "bare" });
    expect(model.servers.map(row => row.name)).toEqual(["legacy", "servers"]);
    expect(model.sources[3].state).toBe("malformed");
    await writeFile(f.projectPortable, '{"mcpServers":{"command":"node"}}');
    model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[1]).toMatchObject({ state: "malformed", container: "mcpServers" });
    expect(model.servers.find(row => row.name === "command")?.declaration).toBe("malformed");
  });

  it("marks mixed wrappers incomplete and retains interpretable declarations", async () => {
    const f = await fixture();
    await writeFile(f.projectVS, '{"servers":{"visible":{}},"mcpServers":{"contrary":{}}}');
    await writeFile(f.projectPortable, '{"mcpServers":{"portable":{}},"servers":{"contrary":{}}}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources.slice(0, 2).every(row => row.state === "malformed")).toBe(true);
    expect(model.servers.map(row => row.name)).toEqual(["visible", "portable"]);
    expect(model.inventoryComplete).toBe(false);
    expect(model.sources.slice(0, 2).every(row => row.uninterpretedRootFields === true)).toBe(true);
  });

  it("marks extra wrapped root fields as uninterpreted without printing their keys/values", async () => {
    const f = await fixture();
    await writeFile(f.projectPortable, '{"mcpServers":{"known":{}},"SECRET_ROOT":{"command":"SECRET_VALUE"}}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.sources[1]).toMatchObject({ state: "present", container: "mcpServers", uninterpretedRootFields: true });
    expect(model.servers.map(row => row.name)).toEqual(["known"]);
    expect(JSON.stringify(model)).not.toMatch(/SECRET_/);
  });

  it("retains supported but uninterpreted fields instead of declaring complete native validity", async () => {
    const f = await fixture();
    await writeFile(f.projectVS, '{"servers":{"stdio":{"command":"node","envFile":"SECRET_FILE","dev":{"watch":"SECRET_WATCH"}},"remote":{"type":"sse","url":"https://SECRET_URL","oauth":{"clientId":"SECRET_ID"}}},"inputs":[{"id":"SECRET_INPUT","type":"promptString"}]}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.servers.map(server => server.declaration)).toEqual(["object", "object"]);
    expect(model.servers[0].guardForm).toBe("unknown");
    expect(JSON.stringify(model)).not.toMatch(/SECRET_/);
    expect(model.coverage.join(" ")).toMatch(/schema|validat/i);
  });

  it("only inspects fixed instruction metadata and does not follow referenced/custom/nested sources", async () => {
    const f = await fixture();
    await mkdir(path.join(f.project, ".github", "instructions"), { recursive: true });
    await writeFile(path.join(f.project, ".github", "copilot-instructions.md"), "SECRET_BODY @/outside/private");
    await writeFile(path.join(f.project, ".github", "instructions", "nested.instructions.md"), "SECRET_RECURSIVE");
    await writeFile(path.join(f.home, ".copilot", "copilot-instructions.md"), "SECRET_USER_BODY");
    await writeFile(path.join(f.base, "workspace", "AGENTS.md"), "SECRET_ANCESTOR");
    await writeFile(path.join(f.project, "other.code-workspace"), '{"mcp":{"servers":{"DO_NOT_READ":{}}},"folders":[{"path":"/SECRET_FOLDER"}]}');
    const model = await buildVSCodeScopeModel(f.project, f.deps);
    expect(model.instructions.find(row => row.path === path.join(f.home, ".copilot", "copilot-instructions.md"))?.state).toBe("present");
    expect(model.instructions.find(row => row.path === path.join(f.base, "workspace", "AGENTS.md"))?.scope).toBe("ancestor");
    expect(model.instructions.some(row => row.path.includes("nested.instructions"))).toBe(false);
    expect(model.instructions.every(row => row.applicability === "unknown")).toBe(true);
    expect(model.coverage.join(" ")).toMatch(/profile/i);
    expect(JSON.stringify(model)).not.toMatch(/SECRET_|DO_NOT_READ/);
  });

  it("preserves strict Claude parsing and its unchanged model when VS Code is not selected", async () => {
    const f = await fixture();
    await writeFile(f.projectPortable, '{ // not strict JSON\n "mcpServers":{}, }');
    const claude = await buildScopeModel(f.project, { home: f.home, managedDirectory: path.join(f.base, "managed") });
    expect(claude.client).toBe("claude-code"); expect(claude.sources.find(row => row.scope === "project")?.state).toBe("malformed");
    expect(claude.sources.every(row => !("format" in row) && !("origin" in row))).toBe(true);
    expect(renderScope(claude).startsWith("Claude Code scope inventory:")).toBe(true);
  });

  it("refuses an unsupported client selector before inventory reads", async () => {
    const program = new Command().exitOverride().configureOutput({ writeErr: () => {} }); registerScopeCommand(program);
    const spy = vi.spyOn(fs, "realpath");
    await expect(program.parseAsync(["node", "mcpm", "scope", "/SECRET_ROOT", "--client", "unsupported"])).rejects.toThrow();
    expect(spy).not.toHaveBeenCalled();
  });

  it("runs the actual registered VS Code CLI path with synthetic HOME and no config/script execution", async () => {
    const f = await fixture(), marker = path.join(f.base, "EXECUTION_MARKER");
    const command = { command: "node", args: ["-e", `require('fs').writeFileSync(${JSON.stringify(marker)},'executed')`] };
    await writeFile(f.projectVS, JSON.stringify({ servers: { sentinel: command } }));
    vi.spyOn(os, "homedir").mockReturnValue(f.home);
    const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const program = new Command().exitOverride(); registerScopeCommand(program);
    await program.parseAsync(["node", "mcpm", "scope", f.project, "--client", "vscode", "--json"]);
    const model = JSON.parse(output.mock.calls.map(call => call[0]).join(""));
    expect(model.client).toBe("vscode"); expect(model.servers[0].name).toBe("sentinel");
    await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(output.mock.calls.map(call => call[0]).join("")).not.toContain("EXECUTION_MARKER");
  });

  it("rejects empty/missing/non-directory VS Code roots before probing sources", async () => {
    const f = await fixture();
    expect((await buildVSCodeScopeModel("", f.deps)).root).toEqual({ path: "", state: "not-directory" });
    expect((await buildVSCodeScopeModel(path.join(f.base, "absent"), f.deps)).sources).toEqual([]);
    await writeFile(path.join(f.base, "file"), "");
    expect((await buildVSCodeScopeModel(path.join(f.base, "file"), f.deps)).root.state).toBe("not-directory");
    const alias = path.join(f.base, "alias"); await symlink(f.project, alias);
    expect((await buildVSCodeScopeModel(alias, f.deps)).root.path).toBe(f.project);
  });

  it("rejects invalid UTF-8 and bounds config reads", async () => {
    const f = await fixture(); await writeFile(f.projectVS, Buffer.from([0xff]));
    expect((await buildVSCodeScopeModel(f.project, f.deps)).sources[0].state).toBe("malformed");
    await writeFile(f.projectVS, " ".repeat(1024 * 1024 + 1));
    expect((await buildVSCodeScopeModel(f.project, f.deps)).sources[0].state).toBe("too-large");
  });

  it("skips intermediate/final symlinks, denied paths and non-files", async () => {
    const f = await fixture(); await rm(path.join(f.project, ".vscode"), { recursive: true });
    await symlink(f.home, path.join(f.project, ".vscode"));
    await symlink(path.join(f.base, "missing"), f.projectPortable);
    await writeFile(f.userVS, '{}'); await chmod(f.userVS, 0);
    await mkdir(f.userPortable);
    try { const model = await buildVSCodeScopeModel(f.project, f.deps);
      expect(model.sources.map(row => row.state)).toEqual(["symlink-skipped", "symlink-skipped", "unreadable", "not-file"]);
      expect(model.inventoryComplete).toBe(false);
    } finally { await chmod(f.userVS, 0o600); }
  });
});
