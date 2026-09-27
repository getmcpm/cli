/**
 * Fix 4: `mcpm guard cleanup` must not silently print "nothing to prune" when
 * pins.json is tampered. readPins returns an empty file (no throw) for the
 * genuine "no pins yet" case, so any thrown error is a PinsIntegrityError or an
 * I/O error — those must surface a visible warning and abort, not be swallowed
 * to null.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { _resetCachedStorePath } from "../../store/index.js";
import { emptyPinsFile, readPins, updatePins, upsertToolPin } from "../pins.js";
import { fileSha } from "../store-integrity.js";

let tmpHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-guard-cleanup-test-"));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
  _resetCachedStorePath();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  _resetCachedStorePath();
  rmSync(tmpHome, { recursive: true, force: true });
  vi.resetModules();
  vi.doUnmock("../pins.js");
});

describe("runCleanupCommand on a tampered pins file", () => {
  test("surfaces the PinsIntegrityError and refuses to prune (not 'nothing to prune')", async () => {
    vi.resetModules();
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return {
        ...actual,
        readPins: async () => {
          throw new actual.PinsIntegrityError("pins.json integrity check failed");
        },
      };
    });

    const { runCleanupCommand } = await import("../cli.js");
    const out: string[] = [];
    await runCleanupCommand({ apply: false, write: (s) => out.push(s) });

    const text = out.join("");
    expect(text).toContain("integrity check failed");
    expect(text).toContain("Refusing to prune");
    // The old buggy behavior printed this on a tampered file — it must NOT now.
    expect(text).not.toContain("nothing to prune");
  });
});

// #232: the actual prune now goes through updatePins (a locked
// read-modify-write) instead of a bare readPins()-then-writePins() pair, so it
// re-derives the orphan set fresh at commit time rather than reusing the
// (possibly stale) set the dry-run report above was built from.
describe("runCleanupCommand --yes (apply)", () => {
  test("prunes every orphan pin against a real filesystem, no client configs installed", async () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "orphan-a", "tool", {
      current_hash: "sha256:" + "a".repeat(64),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
    });
    pins = upsertToolPin(pins, "orphan-b", "tool", {
      current_hash: "sha256:" + "b".repeat(64),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
    });
    await updatePins(() => pins);

    const { runCleanupCommand } = await import("../cli.js");
    const out: string[] = [];
    await runCleanupCommand({ apply: true, write: (s) => out.push(s) });

    const text = out.join("");
    expect(text).toContain("Pruned 2 orphan pin entries");
    const after = await readPins();
    expect(after.servers).toEqual({});
  });

  test("the prune applies to pins.json as it is at commit time, not to the earlier report read", async () => {
    // `live` is installed (Claude Code's user config), so its pins must survive.
    writeFileSync(path.join(tmpHome, ".claude.json"), JSON.stringify({ mcpServers: { live: { command: "node", args: ["s.js"] } } }));
    const entry = (c: string) => ({
      current_hash: "sha256:" + c.repeat(64),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "first-session" as const,
      signature_list_version: "v0.5.0",
    });
    await updatePins(() => upsertToolPin(emptyPinsFile(), "orphan-a", "tool", entry("a")));

    const { runCleanupCommand } = await import("../cli.js");
    let raced = false;
    await runCleanupCommand({
      apply: true,
      write: (s) => {
        // A guard session for `live` commits its first pin between the report
        // and the prune (synchronously, so it has fully landed first).
        if (raced || !s.includes("orphan pin entr")) return;
        raced = true;
        const file = path.join(tmpHome, ".mcpm", "pins.json");
        const content = `${JSON.stringify(upsertToolPin(JSON.parse(readFileSync(file, "utf-8")), "live", "tool", entry("b")), null, 2)}\n`;
        writeFileSync(file, content);
        writeFileSync(`${file}.integrity`, fileSha(content));
      },
    });

    expect(raced).toBe(true);
    const after = await readPins();
    expect(Object.keys(after.servers)).toEqual(["live"]);
  });

  test("a tamper detected only at commit time (not at the earlier report read) aborts without pruning", async () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "orphan-a", "tool", {
      current_hash: "sha256:" + "a".repeat(64),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
    });
    await updatePins(() => pins);

    vi.resetModules();
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return {
        ...actual,
        // The dry-run-style report read still succeeds (mirrors a real
        // integrity mismatch that only appears once the file changes again
        // between the report and the commit).
        updatePins: async (): Promise<never> => {
          throw new actual.PinsIntegrityError("pins.json integrity check failed");
        },
      };
    });

    const { runCleanupCommand } = await import("../cli.js");
    const out: string[] = [];
    await runCleanupCommand({ apply: true, write: (s) => out.push(s) });

    const text = out.join("");
    expect(text).toContain("cannot prune");
    expect(text).toContain("integrity check failed");
    expect(text).not.toContain("Pruned");
  });
});
