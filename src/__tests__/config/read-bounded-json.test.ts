import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { mkdtemp, realpath, rm, writeFile, open, symlink, chmod } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readConfig } from "../../config/read-bounded-json.js";

vi.mock("node:fs/promises", async importOriginal => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, open: vi.fn(actual.open) };
});
let dir: string;
let file: string;
beforeEach(async () => { dir = await mkdtemp(path.join(await realpath(os.tmpdir()), "mcpm-json-read-")); file = path.join(dir, "policy.json"); });
afterEach(async () => { vi.mocked(open).mockClear(); await rm(dir, { recursive: true, force: true }); });
it("classifies absent, unreadable, oversized and symlink files without returning values", async () => {
  expect((await readConfig(file)).state).toBe("missing");
  await writeFile(file, "{}"); await chmod(file, 0);
  expect((await readConfig(file)).state).toBe("unreadable");
  await chmod(file, 0o600); await writeFile(file, " ".repeat(1024 * 1024 + 1));
  expect((await readConfig(file)).state).toBe("too-large");
  const link = path.join(dir, "link.json"); await symlink(file, link);
  expect((await readConfig(link)).state).toBe("symlink-skipped");
});
it("limits empty initialization to the opted-in current-config read without weakening JSON validation", async () => {
  await writeFile(file, " \t\r\n");
  expect(await readConfig(file)).toEqual({ state: "malformed" });
  expect(await readConfig(file, { allowEmpty: true })).toEqual({ state: "present", value: {} });
  await writeFile(file, Buffer.from([0xff]));
  expect(await readConfig(file, { allowEmpty: true })).toEqual({ state: "malformed" });
  await writeFile(file, '{"mcpServers":{},"mcpServers":{}}');
  expect(await readConfig(file, { allowEmpty: true })).toEqual({ state: "malformed" });
  await writeFile(file, " ".repeat(1024 * 1024 + 1));
  expect(await readConfig(file, { allowEmpty: true })).toEqual({ state: "too-large" });
});
it("rejects changes during a read rather than returning a clean snapshot", async () => {
  await writeFile(file, "{}");
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  vi.mocked(open).mockImplementationOnce(async (...args: Parameters<typeof open>) => {
    const handle = await actual.open(...args);
    let changed = false;
    return new Proxy(handle, {
      get(target, key) {
        if (key === "read") return async (...readArgs: Parameters<FileHandle["read"]>) => {
          const result = await target.read(...readArgs);
          if (!changed) { changed = true; await writeFile(file, "{} "); }
          return result;
        };
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  });
  expect(await readConfig(file)).toEqual({ state: "unreadable" });
});
