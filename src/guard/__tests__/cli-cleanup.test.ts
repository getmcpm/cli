/**
 * Fix 4: `mcpm guard cleanup` must not silently print "nothing to prune" when
 * pins.json is tampered. readPins returns an empty file (no throw) for the
 * genuine "no pins yet" case, so any thrown error is a PinsIntegrityError or an
 * I/O error — those must surface a visible warning and abort, not be swallowed
 * to null.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
    const code = await runCleanupCommand({ apply: false, write: (s) => out.push(s) });

    const text = out.join("");
    expect(text).toContain("integrity check failed");
    expect(text).toContain("Refusing to prune");
    expect(code).toBe(1);
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
    const code = await runCleanupCommand({ apply: true, write: (s) => out.push(s) });

    const text = out.join("");
    expect(text).toContain("cannot prune");
    expect(text).toContain("integrity check failed");
    expect(text).not.toContain("Pruned");
    expect(code).toBe(1);
  });
});

// #118: `cleanup` derived its "installed" set from `status.clients[*].servers`
// and never looked at a client's read error. A client whose config could not be
// parsed contributed ZERO names, so every server it held read as an orphan and
// `--yes` erased those servers' rug-pull baselines (the next launch is then
// trusted afresh as a first session). Real adapters on real files throughout:
// a mocked read() would return a state the real one cannot produce.
describe("runCleanupCommand when a client config cannot be read (#118)", () => {
  const entry = (c: string) => ({
    current_hash: "sha256:" + c.repeat(64),
    previous_hashes: [],
    captured_at: "x",
    captured_via: "first-session" as const,
    signature_list_version: "v0.5.0",
  });
  const pinsFile = () => path.join(tmpHome, ".mcpm", "pins.json");
  const snapshot = () => ({
    pins: readFileSync(pinsFile(), "utf-8"),
    sidecar: readFileSync(`${pinsFile()}.integrity`, "utf-8"),
  });
  async function seedPins(...names: string[]): Promise<void> {
    let pins = emptyPinsFile();
    names.forEach((n, i) => {
      pins = upsertToolPin(pins, n, "tool", entry("abcdef"[i % 6]!));
    });
    await updatePins(() => pins);
  }
  const writeClaudeCode = (mcpServers: Record<string, unknown>): void =>
    writeFileSync(path.join(tmpHome, ".claude.json"), JSON.stringify({ mcpServers }));
  function writeGeminiSettings(raw: string): void {
    mkdirSync(path.join(tmpHome, ".gemini"), { recursive: true });
    writeFileSync(path.join(tmpHome, ".gemini", "settings.json"), raw);
  }
  // A trailing comma: what a hand-edit of Gemini's settings.json commonly leaves.
  const BROKEN_GEMINI = '{"mcpServers":{"server-b":{"command":"node"},}}';
  async function cleanup(apply: boolean): Promise<{ text: string; code: number }> {
    const { runCleanupCommand } = await import("../cli.js");
    const out: string[] = [];
    const code = await runCleanupCommand({ apply, write: (s) => out.push(s) });
    return { text: out.join(""), code };
  }

  test("dry run refuses, names the client, and lists no orphans (exit 1)", async () => {
    writeClaudeCode({ "server-a": { command: "node", args: ["a.js"] } });
    writeGeminiSettings(BROKEN_GEMINI);
    await seedPins("server-a", "server-b");
    const before = snapshot();

    const { text, code } = await cleanup(false);

    expect(text).toContain("cannot determine");
    expect(text).toContain("gemini-cli");
    expect(text).toContain("Refusing to prune");
    // The bug: server-b was listed as an orphan, then pruned by --yes.
    expect(text).not.toContain("server-b");
    expect(text).not.toContain("orphan pin entr");
    expect(text).not.toContain("nothing to prune");
    expect(code).toBe(1);
    expect(snapshot()).toEqual(before);
  });

  test("--yes prunes nothing: pins.json and its sidecar are byte-identical, exit 1", async () => {
    writeClaudeCode({ "server-a": { command: "node", args: ["a.js"] } });
    writeGeminiSettings(BROKEN_GEMINI);
    await seedPins("server-a", "server-b");
    const before = snapshot();

    const { text, code } = await cleanup(true);

    expect(text).toContain("gemini-cli");
    expect(text).not.toContain("Pruned");
    expect(code).toBe(1);
    expect(snapshot()).toEqual(before);
    expect(Object.keys((await readPins()).servers).sort()).toEqual(["server-a", "server-b"]);
  });

  test("a client that is simply not installed does not block cleanup", async () => {
    // Only Claude Code has a config; the other five clients do not exist.
    writeClaudeCode({ "server-a": { command: "node", args: ["a.js"] } });
    await seedPins("server-a", "server-b");

    const { text, code } = await cleanup(true);

    expect(text).toContain("Pruned 1 orphan pin entry");
    expect(code).toBe(0);
    expect(Object.keys((await readPins()).servers)).toEqual(["server-a"]);
  });

  test("a readable config on every client still reports and prunes a genuine orphan", async () => {
    writeClaudeCode({ "server-a": { command: "node", args: ["a.js"] } });
    writeGeminiSettings('{"mcpServers":{"server-b":{"command":"node"}}}');
    await seedPins("server-a", "server-b", "server-gone");

    const dry = await cleanup(false);
    expect(dry.text).toContain("1 orphan pin entry found");
    expect(dry.text).toContain("server-gone");
    expect(dry.code).toBe(0);

    const applied = await cleanup(true);
    expect(applied.text).toContain("Pruned 1 orphan pin entry");
    expect(applied.code).toBe(0);
    expect(Object.keys((await readPins()).servers).sort()).toEqual(["server-a", "server-b"]);
  });

  test("a malformed entry is still an installed server: its pin is not an orphan", async () => {
    // `args` as a string instead of an array: read() drops it into onSkip, so it
    // is absent from the validated map, but the server still launches.
    writeClaudeCode({
      "server-a": { command: "node", args: ["a.js"] },
      "server-b": { command: "npx", args: "-y pkg" },
    });
    await seedPins("server-a", "server-b");
    const before = snapshot();

    const dry = await cleanup(false);
    expect(dry.text).toContain("nothing to prune");
    expect(dry.text).not.toContain("server-b");

    const applied = await cleanup(true);
    expect(applied.text).not.toContain("Pruned");
    expect(applied.code).toBe(0);
    expect(snapshot()).toEqual(before);
  });

  test("terminal escapes in the parse error are stripped from the refusal", async () => {
    // Node's JSON.parse SyntaxError embeds a snippet of the file, and the file
    // is user-controlled text that reaches the terminal here.
    writeGeminiSettings('{"mcpServers": \u001b]0;evil\u0007}');
    await seedPins("server-b");

    const { text, code } = await cleanup(false);

    expect(code).toBe(1);
    expect(text).toContain("gemini-cli");
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u0007");
  });
});
