import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { GeminiCliAdapter } from "../../../config/adapters/gemini-cli.js";
import { CursorAdapter } from "../../../config/adapters/cursor.js";
import { handleToggleServer } from "../../../commands/toggle.js";

const folders: string[] = [];
const original = { command: "npx", args: ["-y", "fixture@1"], env: { FIXTURE: "synthetic" }, custom: { retained: true } };
async function seed(extra: Record<string, unknown> = {}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cursor-disabled-"));
  folders.push(dir);
  const file = path.join(dir, "mcp.json");
  await writeFile(file, JSON.stringify({ preferences: { retained: true }, mcp: { excluded: ["native-disabled"], allowed: ["fixture"] }, mcpServers: { fixture: original, retained: { command: "node" } }, ...extra }));
  return file;
}
const raw = async (file: string) => JSON.parse(await readFile(file, "utf8"));
afterEach(async () => { await Promise.all(folders.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });

describe.each([new CursorAdapter(), new GeminiCliAdapter()])("$clientId effective disabled storage", (adapter) => {
  it.each([null, [], "invalid", 42, { mcpServers: null }, { mcpServers: [] }, { mcpServers: "invalid" }].map(value => ({ value })))("refuses malformed roots or active maps without rewriting them: $value", async ({ value }) => {
    const file = await seed();
    await writeFile(file, JSON.stringify(value));
    const before = await readFile(file, "utf8");
    await expect(adapter.addServer(file, "fixture", original, { force: true })).rejects.toThrow(/configuration|server/i);
    expect(await readFile(file, "utf8")).toBe(before);
  });

  it("parks/restores an entry atomically, retaining unknown fields, siblings and original backup", async () => {
    const file = await seed();
    const before = await readFile(file, "utf8");
    await adapter.setServerDisabled(file, "fixture", true);
    const disabled = await raw(file);
    expect(disabled.mcpServers).not.toHaveProperty("fixture");
    expect(disabled._mcpmDisabledServers.fixture).toEqual(original);
    expect((await adapter.read(file)).fixture).toEqual({ ...original, disabled: true });
    await adapter.setServerDisabled(file, "fixture", false);
    expect(await raw(file)).toEqual(JSON.parse(before));
    expect(await readFile(file + ".bak", "utf8")).toBe(before);
  });

  it("rerunning disable repairs the legacy ineffective flag through the real toggle handler", async () => {
    const file = await seed({ mcpServers: { fixture: { ...original, disabled: true } } });
    expect((await adapter.read(file)).fixture.disabled).toBeUndefined();
    await handleToggleServer("fixture", true, { client: adapter.clientId }, {
      detectClients: async () => [adapter.clientId], getAdapter: () => adapter,
      getConfigPath: () => file, output: () => {},
    });
    expect((await raw(file)).mcpServers).not.toHaveProperty("fixture");
  });

  it("preserves unrelated legacy flags and malformed fields through target mutations", async () => {
    const siblings = {
      legacyTrue: { ...original, disabled: true },
      legacyFalse: { ...original, disabled: false },
      malformed: { ...original, args: "invalid", disabled: true },
      ["__proto__"]: { ...original, disabled: true },
    };
    const parked = { retainedParked: { ...original, disabled: false } };
    const file = await seed({ mcpServers: { fixture: original, ...siblings }, _mcpmDisabledServers: parked });
    for (const mutate of [
      () => adapter.setServerDisabled(file, "fixture", true),
      () => adapter.addServer(file, "fixture", { command: "updated" }, { force: true }),
      () => adapter.replaceServer(file, "fixture", { command: "replacement" }),
      () => adapter.setServerDisabled(file, "fixture", false),
      () => adapter.removeServer(file, "fixture"),
    ]) {
      await mutate();
      const physical = await raw(file);
      const { fixture: _fixture, ...remaining } = physical.mcpServers;
      expect(remaining).toEqual(siblings);
      expect(physical._mcpmDisabledServers.retainedParked).toEqual(parked.retainedParked);
    }
  });

  it("keeps force-install/update and guard replacement parked until explicit enable", async () => {
    const file = await seed();
    await adapter.setServerDisabled(file, "fixture", true);
    await expect(adapter.addServer(file, "fixture", original)).rejects.toThrow(/already exists/);
    await adapter.addServer(file, "fixture", { command: "updated", args: ["v2"] }, { force: true });
    await adapter.replaceServer(file, "fixture", { command: "mcpm", args: ["guard", "run", "--inner"] });
    expect((await raw(file)).mcpServers).not.toHaveProperty("fixture");
    expect((await adapter.read(file)).fixture).toEqual({ command: "mcpm", args: ["guard", "run", "--inner"], disabled: true });
    await adapter.setServerDisabled(file, "fixture", false);
    expect((await raw(file)).mcpServers.fixture.command).toBe("mcpm");
  });

  it("removes a parked entry without resurrecting it or changing unrelated entries", async () => {
    const file = await seed();
    await adapter.setServerDisabled(file, "fixture", true);
    await adapter.removeServer(file, "fixture");
    expect(await adapter.read(file)).toEqual({ retained: { command: "node" } });
    expect((await raw(file))._mcpmDisabledServers).toBeUndefined();
  });

  it.each([null, [], "invalid", { fixture: "invalid" }, { fixture: original }].map(parked => ({ parked })))("refuses malformed or conflicting parked state: $parked", async ({ parked }) => {
    const file = await seed({ _mcpmDisabledServers: parked });
    const before = await readFile(file, "utf8");
    await expect(adapter.setServerDisabled(file, "fixture", true)).rejects.toThrow(/configuration|server/i);
    expect(await readFile(file, "utf8")).toBe(before);
  });

  it("preserves own __proto__ server names across disable and enable", async () => {
    const file = await seed({ mcpServers: { ["__proto__"]: original } });
    await adapter.setServerDisabled(file, "__proto__", true);
    expect(Object.hasOwn((await raw(file))._mcpmDisabledServers, "__proto__")).toBe(true);
    await adapter.setServerDisabled(file, "__proto__", false);
    expect(Object.hasOwn((await raw(file)).mcpServers, "__proto__")).toBe(true);
  });
});
