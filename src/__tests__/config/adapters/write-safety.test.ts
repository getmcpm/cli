/**
 * Real-filesystem safety tests for BaseAdapter.writeAtomic.
 *
 * Unlike the per-adapter suites (which mock fs/promises), these exercise the
 * ACTUAL OS file semantics in a throwaway temp dir, proving:
 *
 *   #25 — the .bak preserves the raw original bytes and is written exactly
 *         once (never clobbered by later operations).
 *   #26 — a pre-placed symlink at <config>.tmp / <config>.bak / <config>
 *         cannot redirect mcpm's write onto the link target.
 *
 * No fs/promises mock here — this file relies on the real filesystem.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm, lstat } from "fs/promises";
import os from "os";
import path from "path";
import { ClaudeDesktopAdapter } from "../../../config/adapters/claude-desktop.js";

const adapter = new ClaudeDesktopAdapter();

let dir: string;
let configPath: string;
let secretPath: string;

const SECRET = "DO_NOT_OVERWRITE_ME\n";

beforeEach(async () => {
  dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-write-safety-"));
  configPath = path.join(dir, "claude_desktop_config.json");
  secretPath = path.join(dir, "secret.rc");
  await writeFile(secretPath, SECRET, "utf-8");
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("writeAtomic — #25 raw-bytes, write-once backup", () => {
  it("backs up the RAW original bytes verbatim", async () => {
    // Custom formatting + a key order that JSON.stringify would not reproduce.
    const rawOriginal = '{\n    "mcpServers": {\n        "old": { "command": "uvx", "args": ["x"] }\n    },\n    "z_last": true\n}\n';
    await writeFile(configPath, rawOriginal, "utf-8");

    await adapter.addServer(configPath, "new", { command: "npx", args: [] });

    const bak = await readFile(`${configPath}.bak`, "utf-8");
    expect(bak).toBe(rawOriginal);
  });

  it("never overwrites an existing .bak across multiple operations", async () => {
    const firstOriginal = JSON.stringify({ mcpServers: { a: { command: "npx", args: [] } } });
    await writeFile(configPath, firstOriginal, "utf-8");

    // First op creates the .bak from the pristine pre-mcpm state.
    await adapter.addServer(configPath, "b", { command: "npx", args: [] });
    const bakAfterFirst = await readFile(`${configPath}.bak`, "utf-8");
    expect(bakAfterFirst).toBe(firstOriginal);

    // Second op must NOT clobber that pristine backup.
    await adapter.addServer(configPath, "c", { command: "npx", args: [] });
    const bakAfterSecond = await readFile(`${configPath}.bak`, "utf-8");
    expect(bakAfterSecond).toBe(firstOriginal);
  });
});

describe("writeAtomic — #26 symlink cannot redirect the write", () => {
  it("does not write through a pre-placed .tmp symlink", async () => {
    await writeFile(configPath, JSON.stringify({ mcpServers: {} }), "utf-8");
    // Attacker pre-creates <config>.tmp as a symlink to a sensitive file.
    await symlink(secretPath, `${configPath}.tmp`);

    await adapter.addServer(configPath, "srv", { command: "npx", args: [] });

    // The secret target is untouched — the write was not redirected.
    expect(await readFile(secretPath, "utf-8")).toBe(SECRET);
    // The config was still updated correctly (a real, non-symlink file).
    const written = JSON.parse(await readFile(configPath, "utf-8"));
    expect(written.mcpServers.srv).toEqual({ command: "npx", args: [] });
  });

  it("does not write through a pre-placed .bak symlink", async () => {
    await writeFile(configPath, JSON.stringify({ mcpServers: { old: { command: "uvx", args: [] } } }), "utf-8");
    // Attacker pre-creates <config>.bak as a symlink to a sensitive file.
    await symlink(secretPath, `${configPath}.bak`);

    await adapter.addServer(configPath, "srv", { command: "npx", args: [] });

    // The secret target is untouched — the backup did not follow the symlink.
    expect(await readFile(secretPath, "utf-8")).toBe(SECRET);
    // The .bak path is still the attacker's symlink (we refused to write it),
    // and the config itself was updated.
    expect((await lstat(`${configPath}.bak`)).isSymbolicLink()).toBe(true);
    const written = JSON.parse(await readFile(configPath, "utf-8"));
    expect(written.mcpServers.srv).toBeDefined();
  });

  it("refuses to write when the config path itself is a symlink", async () => {
    // <config> is a symlink to the sensitive file.
    await symlink(secretPath, configPath);

    await expect(
      adapter.addServer(configPath, "srv", { command: "npx", args: [] })
    ).rejects.toThrow(/symlink/i);

    // The secret target is untouched.
    expect(await readFile(secretPath, "utf-8")).toBe(SECRET);
  });
});
