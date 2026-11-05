import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { getAdapter } from "../../../config/adapters/factory.js";
import { CLIENT_IDS } from "../../../config/paths.js";

const folders: string[] = [];
afterEach(async () => {
  await Promise.all(folders.splice(0).map(dir => rm(dir, { recursive: true, force: true })));
});

describe.each(CLIENT_IDS)("%s configuration containers", (clientId) => {
  const adapter = getAdapter(clientId);
  const rootKey = clientId === "vscode" ? "servers" : "mcpServers";
  it.each([null, [], "invalid", 42, false].map(value => ({ value })))("rejects invalid roots and server maps before reads or writes: $value", async ({ value }) => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-containers-"));
    folders.push(dir);
    const file = path.join(dir, "config.json");
    for (const config of [value, { [rootKey]: value, preference: "retained" }]) {
      const original = JSON.stringify(config);
      await writeFile(file, original);
      for (const operation of [
        () => adapter.read(file),
        () => adapter.addServer(file, "fixture", { command: "node" }, { force: true }),
        () => adapter.replaceServer(file, "fixture", { command: "node" }),
        () => adapter.setServerDisabled(file, "fixture", true),
        () => adapter.removeServer(file, "fixture"),
      ]) {
        await expect(operation()).rejects.toThrow(/configuration|server/i);
        expect(await readFile(file, "utf8")).toBe(original);
        expect(await readdir(dir)).toEqual(["config.json"]);
      }
    }
  });
});
