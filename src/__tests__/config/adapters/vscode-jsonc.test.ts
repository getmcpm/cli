import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { VSCodeAdapter } from "../../../config/adapters/vscode.js";
import { getAdapter } from "../../../config/adapters/factory.js";

const original = `// User-owned VS Code configuration.
{
  "inputs": [
    { "id": "native-fixture-input", "type": "promptString", "default": "synthetic", },
  ],
  "servers": {
    // Keep this other server and its comment.
    "other": { "command": "other", "env": { "URL": "https://example.test/a//b" }, },
    "fixture": { "command": "old", "env": { "TOKEN": "\${input:native-fixture-input}" }, },
  },
  "custom": { "enabled": true, }, // Keep this trailing comment.
}
`;

describe("VS Code JSONC configuration", () => {
  const adapter = new VSCodeAdapter();
  let directory: string;
  let file: string;

  beforeEach(async () => {
    directory = await mkdtemp(path.join(tmpdir(), "mcpm-vscode-jsonc-"));
    file = path.join(directory, "mcp.json");
    await writeFile(file, original);
  });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });

  it("reads comments/trailing commas without interpreting strings or variables", async () => {
    const entries = await adapter.read(file);
    expect(entries.fixture.env).toEqual({ TOKEN: "${input:native-fixture-input}" });
    expect(entries.other.env).toEqual({ URL: "https://example.test/a//b" });
  });

  it("preserves unrelated bytes, input declarations and the original backup through the lifecycle", async () => {
    await adapter.addServer(file, "new", { command: "new" });
    await adapter.replaceServer(file, "fixture", { command: "updated", env: { TOKEN: "${input:native-fixture-input}" } });
    await adapter.setServerDisabled(file, "fixture", true);
    expect((await adapter.read(file)).fixture.disabled).toBe(true);
    await adapter.setServerDisabled(file, "fixture", false);
    await adapter.removeServer(file, "new");
    const text = await readFile(file, "utf8");
    expect(text).toContain('// User-owned VS Code configuration.');
    expect(text).toContain('"other": { "command": "other", "env": { "URL": "https://example.test/a//b" }, },');
    expect(text).toContain('{ "id": "native-fixture-input", "type": "promptString", "default": "synthetic", },');
    expect(text).toContain('"custom": { "enabled": true, }, // Keep this trailing comment.');
    expect((await adapter.read(file)).fixture).toEqual({ command: "updated", env: { TOKEN: "${input:native-fixture-input}" } });
    expect(await readFile(file + ".bak", "utf8")).toBe(original);
    expect(await readdir(directory)).toEqual(expect.arrayContaining(["mcp.json", "mcp.json.bak"]));
    expect(await readdir(directory)).not.toContain("mcp.json.tmp");
  });

  it("retains an own __proto__ server instead of altering the result prototype", async () => {
    await writeFile(file, '{ /* JSONC */ "servers": { "__proto__": {"command":"safe"}, }, }');
    const entries = await adapter.read(file);
    expect(Object.prototype.hasOwnProperty.call(entries, "__proto__")).toBe(true);
    expect(entries.__proto__).toEqual({ command: "safe" });
    expect(Object.getPrototypeOf(entries)).toBe(null);
    expect(Object.prototype).not.toHaveProperty("command");
  });

  it.each(["__proto__", "constructor", "toString"])("removes an own %s server without consulting the object prototype", async (name) => {
    const text = `{ /* keep */ "servers": { ${JSON.stringify(name)}: {"command":"safe"}, "other": {"command":"other"} } }`;
    await writeFile(file, text);
    await adapter.removeServer(file, name);
    expect(await adapter.read(file)).toEqual({ other: { command: "other" } });
    expect(await readFile(file, "utf8")).toContain("/* keep */");
    expect(await readFile(file + ".bak", "utf8")).toBe(text);
  });

  it.each([
    '{ "servers": { "fixture": {"command":"x"}, /* keep sibling */ "other": {"command":"y"} } }',
    '{ "servers": { "other": {"command":"y"}, /* keep sibling */ "fixture": {"command":"x"}, } }',
  ])("removing a server preserves neighboring comments: %s", async (text) => {
    await writeFile(file, text);
    await adapter.removeServer(file, "fixture");
    expect(await readFile(file, "utf8")).toContain('/* keep sibling */');
    expect(await adapter.read(file)).toEqual({ other: { command: "y" } });
  });

  it.each([
    '{ "servers": {}, "servers": {} }',
    '{ "servers": {"fixture":{"command":"x"},"fixture":{"command":"y"}} }',
  ])("refuses ambiguous duplicate server paths before writing: %s", async (text) => {
    await writeFile(file, text);
    await expect(adapter.addServer(file, "new", { command: "new" })).rejects.toThrow();
    expect(await readFile(file, "utf8")).toBe(text);
    expect(await readdir(directory)).toEqual(["mcp.json"]);
  });

  it("can add a server to a comments-only file without discarding the comments", async () => {
    await writeFile(file, '// Keep this note.\n');
    await adapter.addServer(file, "new", { command: "new" });
    expect(await readFile(file, "utf8")).toContain('// Keep this note.');
    expect(await adapter.read(file)).toEqual({ new: { command: "new" } });
  });

  it.each([
    '{"servers": {} "custom": true}',
    '{"servers": {}, /* unfinished',
    '{"servers": {"fixture": {"command": undefined}}}',
  ])("refuses malformed JSONC without writes or backups: %s", async (text) => {
    await writeFile(file, text);
    await expect(adapter.addServer(file, "new", { command: "new" })).rejects.toThrow();
    expect(await readFile(file, "utf8")).toBe(text);
    expect(await readdir(directory)).toEqual(["mcp.json"]);
  });

  it.each(["claude-code", "claude-desktop", "cursor", "windsurf", "gemini-cli"] as const)(
    "%s retains its existing strict JSON behavior", async (client) => {
      await expect(getAdapter(client).read(file)).rejects.toThrow();
      expect(await readFile(file, "utf8")).toBe(original);
    },
  );
});
