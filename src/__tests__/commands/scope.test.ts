import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm, realpath, chmod } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { wrapEntry } from "../../guard/wrap.js";
import { buildScopeModel, renderScope } from "../../commands/scope.js";

vi.mock("node:fs/promises", async importOriginal => ({
  ...await importOriginal<typeof import("node:fs/promises")>(),
}));

const roots: string[] = [];
async function fixture() {
  const base = await realpath(await mkdtemp(path.join(tmpdir(), "mcpm-scope-test-")));
  roots.push(base);
  const home = path.join(base, "home");
  const project = path.join(base, "workspace", "project");
  const managed = path.join(base, "managed");
  await Promise.all([home, project, managed].map(p => mkdir(p, { recursive: true })));
  return { base, home, project, managed, deps: { home, managedDirectory: managed } };
}
afterEach(async () => { await Promise.all(roots.splice(0).map(p => rm(p, { recursive: true, force: true }))); });

describe("scope inventory", () => {
  it("reports duplicate declarations, document order only, and no values or instruction contents", async () => {
    const f = await fixture();
    const entry = { command: "DO_NOT_EXECUTE", args: ["SECRET_ARG"], env: { TOKEN: "SECRET_ENV", REF: "${SECRET_PLACEHOLDER}" }, url: "https://SECRET_URL", headers: { Authorization: "SECRET_HEADER" } };
    const global = JSON.stringify({ mcpServers: { same: entry }, projects: { [f.project]: { mcpServers: { same: entry } } } });
    await writeFile(path.join(f.home, ".claude.json"), global);
    await writeFile(path.join(f.project, ".mcp.json"), JSON.stringify({ mcpServers: { same: entry } }));
    await writeFile(path.join(f.project, "CLAUDE.md"), "SECRET_INSTRUCTION @/outside/secret");
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.root.state).toBe("directory");
    expect(model.servers.map(s => s.scope)).toEqual(["local", "project", "user"]);
    expect(model.servers.map(s => s.possibleShadowedBy)).toEqual([[], ["local"], ["local", "project"]]);
    expect(model.servers.every(s => s.effective === "unknown")).toBe(true);
    expect(model.instructions.find(i => i.path === path.join(f.project, "CLAUDE.md"))?.state).toBe("present");
    for (const output of [JSON.stringify(model), renderScope(model)]) expect(output).not.toMatch(/SECRET_|DO_NOT_EXECUTE/);
    expect(await readFile(path.join(f.home, ".claude.json"), "utf8")).toBe(global);
  });

  it.each(["null", "[]", '{"mcpServers":null}', '{"mcpServers":[]}', '{"mcpServers":{"x":null}}', '{"mcpServers":{"x":{"args":"SECRET_BAD_ARGS"}}}', '{"mcpServers":{"x":{},"x":{}}}'])
  ("does not turn malformed JSON containers into a healthy empty inventory: %s", async raw => {
    const f = await fixture();
    await writeFile(path.join(f.project, ".mcp.json"), raw);
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.sources.find(s => s.scope === "project")?.state).toBe("malformed");
    expect(model.inventoryComplete).toBe(false);
  });

  it.each(['{"projects":null}', '{"projects":[]}', '{"projects":{"ROOT":null}}', '{"projects":{"ROOT":{"mcpServers":null}}}'])
  ("keeps malformed local scope unknown: %s", async raw => {
    const f = await fixture();
    await writeFile(path.join(f.home, ".claude.json"), raw.replace("ROOT", f.project));
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.sources.find(s => s.scope === "local")?.state).toBe("malformed");
  });

  it("treats prototype-like names as own declarations when comparing scopes", async () => {
    const f = await fixture();
    const raw = '{"mcpServers":{"__proto__":{},"constructor":{},"toString":{}}}';
    await writeFile(path.join(f.project, ".mcp.json"), raw);
    await writeFile(path.join(f.home, ".claude.json"), raw);
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.servers.filter(s => s.scope === "project").map(s => s.name)).toEqual(["__proto__", "constructor", "toString"]);
    expect(model.servers.filter(s => s.scope === "user").map(s => s.possibleShadowedBy)).toEqual([["project"], ["project"], ["project"]]);
  });

  it("reports competing canonical and explicit project keys without merging them", async () => {
    const f = await fixture();
    const alias = path.join(f.base, "alias");
    await symlink(f.project, alias);
    await writeFile(path.join(f.home, ".claude.json"), JSON.stringify({ projects: {
      [f.project]: { mcpServers: { canonical: {} } }, [alias]: { mcpServers: { alias: {} } },
    } }));
    const model = await buildScopeModel(alias, f.deps);
    expect(model.root.path).toBe(f.project);
    expect(model.sources.find(s => s.scope === "local")?.state).toBe("malformed");
    expect(model.servers).toEqual([]);
    expect(model.inventoryComplete).toBe(false);
  });

  it("rejects an empty root instead of silently inspecting the working directory", async () => {
    const f = await fixture();
    const probe = vi.spyOn(fs, "realpath");
    try {
      const model = await buildScopeModel("", f.deps);
      expect(model.root).toEqual({ path: "", state: "not-directory" });
      expect(model.inventoryComplete).toBe(false);
      expect(model.sources).toEqual([]);
      expect(probe).not.toHaveBeenCalled();
    } finally { probe.mockRestore(); }
  });

  it("reports missing and non-directory explicit roots without probing configs", async () => {
    const f = await fixture();
    expect((await buildScopeModel(path.join(f.base, "missing"), f.deps)).root.state).toBe("missing");
    await writeFile(path.join(f.base, "file"), "");
    expect((await buildScopeModel(path.join(f.base, "file"), f.deps)).root.state).toBe("not-directory");
  });

  it("does not follow final, dangling or intermediate symlinks", async () => {
    const f = await fixture();
    await writeFile(path.join(f.base, "secret.json"), '{"mcpServers":{"SECRET_SERVER":{"command":"x"}}}');
    await symlink(path.join(f.base, "secret.json"), path.join(f.project, ".mcp.json"));
    await symlink(path.join(f.base, "missing"), path.join(f.project, "CLAUDE.md"));
    await symlink(f.base, path.join(f.project, ".claude"));
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.sources.find(s => s.scope === "project")?.state).toBe("symlink-skipped");
    expect(model.instructions.find(i => i.path === path.join(f.project, "CLAUDE.md"))?.state).toBe("symlink-skipped");
    expect(model.instructions.find(i => i.path === path.join(f.project, ".claude", "CLAUDE.md"))?.state).toBe("symlink-skipped");
    expect(JSON.stringify(model)).not.toContain("SECRET_SERVER");
  });

  it("distinguishes denied config and instruction metadata from missing", async () => {
    const f = await fixture();
    const config = path.join(f.project, ".mcp.json");
    const instruction = path.join(f.project, "CLAUDE.md");
    await writeFile(config, '{"mcpServers":{"denied":{"command":"x"}}}');
    await writeFile(instruction, "SECRET_DENIED_INSTRUCTION");
    await Promise.all([config, instruction].map(p => chmod(p, 0)));
    try {
      const model = await buildScopeModel(f.project, f.deps);
      expect(model.sources.find(s => s.scope === "project")?.state).toBe("unreadable");
      expect(model.instructions.find(i => i.path === instruction)?.state).toBe("unreadable");
      expect(model.inventoryComplete).toBe(false);
      expect(JSON.stringify(model)).not.toContain("SECRET_DENIED_INSTRUCTION");
    } finally { await Promise.all([config, instruction].map(p => chmod(p, 0o600))); }
  });

  it("rejects invalid UTF-8 rather than silently replacing server names", async () => {
    const f = await fixture();
    await writeFile(path.join(f.project, ".mcp.json"), Buffer.concat([
      Buffer.from('{"mcpServers":{"'), Buffer.from([0xff]), Buffer.from('":{}}}'),
    ]));
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.sources.find(s => s.scope === "project")?.state).toBe("malformed");
    expect(model.inventoryComplete).toBe(false);
    expect(model.servers).toEqual([]);
  });

  it("opens nonblocking so a file replaced by a FIFO cannot stall inventory", async () => {
    const f = await fixture();
    const config = path.join(f.project, ".mcp.json");
    await writeFile(config, "{}");
    const realOpen = fs.open;
    const spy = vi.spyOn(fs, "open").mockImplementation(async (file, flags, mode) => {
      if (file === config) {
        // Simulate the special-file race without leaving a blocked OS read in the test runner.
        expect(Number(flags) & constants.O_NONBLOCK).not.toBe(0);
        return { stat: async () => ({ isFile: () => false }), close: async () => {} } as Awaited<ReturnType<typeof fs.open>>;
      }
      return realOpen(file, flags, mode);
    });
    try {
      const model = await buildScopeModel(f.project, f.deps);
      expect(model.sources.find(s => s.scope === "project")?.state).toBe("not-file");
      expect(model.inventoryComplete).toBe(false);
    } finally { spy.mockRestore(); }
  });

  it("bounds config reads and rejects oversized input", async () => {
    const f = await fixture();
    await writeFile(path.join(f.project, ".mcp.json"), " ".repeat(1024 * 1024 + 1));
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.sources.find(s => s.scope === "project")?.state).toBe("too-large");
    expect(model.inventoryComplete).toBe(false);
  });

  it("includes fixed ancestor candidates through filesystem root, without recursive discovery", async () => {
    const f = await fixture();
    const ancestor = path.join(f.base, "workspace", "CLAUDE.md");
    await writeFile(ancestor, "ignored");
    await mkdir(path.join(f.project, "nested"));
    await writeFile(path.join(f.project, "nested", "CLAUDE.md"), "ignored");
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.instructions.find(i => i.path === ancestor)?.state).toBe("present");
    expect(model.instructions.some(i => i.path === path.parse(f.project).root + "CLAUDE.md")).toBe(true);
    expect(model.instructions.some(i => i.path.includes("nested"))).toBe(false);
  });

  it("recognizes the filesystem-free mcpm form without claiming protection", async () => {
    const f = await fixture();
    const wrapped = wrapEntry("wrapped", { command: "SECRET_INNER", args: ["SECRET_ARG"] }, { mcpmBinary: "mcpm" });
    await writeFile(path.join(f.project, ".mcp.json"), JSON.stringify({ mcpServers: { wrapped, ambiguous: { command: "mcpm", args: ["guard", "run", "--inner"] } } }));
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.servers.map(s => s.guardForm)).toEqual(["recognized", "ambiguous"]);
    expect(model.enforced).toBe("unknown");
    expect(JSON.stringify(model)).not.toMatch(/SECRET_/);
  });

  it("never probes configured node scripts or emits parser and OS error messages", async () => {
    const f = await fixture();
    await writeFile(path.join(f.project, ".mcp.json"), JSON.stringify({ mcpServers: { node: { command: "node", args: ["/SECRET_SCRIPT/dist/index.js", "guard", "run", "--inner"] } } }));
    const model = await buildScopeModel(f.project, f.deps);
    expect(model.servers[0].guardForm).toBe("unknown");
    expect(JSON.stringify(model)).not.toContain("SECRET_SCRIPT");
  });
});
