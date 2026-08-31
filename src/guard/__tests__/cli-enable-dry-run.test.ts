/**
 * #23 follow-up (adversarial review): `guard enable --dry-run` reports a
 * malformed config entry (excludes it from "would wrap" candidates, matching
 * the real enable path which routes it to `skipped` — never `transforms`),
 * instead of silently omitting it and under-reporting vs. what a real
 * `enable` run would show. printEnableDryRun previously had no direct test.
 *
 * Real HOME + real cursor config (same pattern as cli-confine.test.ts).
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { _resetCachedStorePath } from "../../store/index.js";
import { getConfigPath } from "../../config/paths.js";
import { runEnableCommand } from "../cli.js";

let tmpHome: string;
let originalHome: string | undefined;

const cursorConfig = () => getConfigPath("cursor");

function writeCursor(servers: Record<string, unknown>): void {
  const p = cursorConfig();
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify({ mcpServers: servers }, null, 2), { mode: 0o600 });
}

const collect = () => {
  const out: string[] = [];
  return { write: (s: string) => void out.push(s), text: () => out.join("") };
};

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-enable-dry-run-cli-"));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
  _resetCachedStorePath();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  _resetCachedStorePath();
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("runEnableCommand --dry-run — malformed entry (#23)", () => {
  test("excludes a malformed entry from 'would wrap', but still surfaces it (not silently dropped)", async () => {
    writeCursor({
      good: { command: "node", args: ["a.js"] },
      // Hand-edited/IDE-mangled: args should be string[].
      broken: { command: "node", args: "not-an-array" },
    });
    const io = collect();

    await runEnableCommand({ dryRun: true, write: io.write });

    const text = io.text();
    expect(text).toContain("would wrap 1 server");
    expect(text).toContain("+ good");
    expect(text).not.toContain("+ broken");
    expect(text).toContain("MALFORMED");
    expect(text).toContain("broken");
  });

  test("with only a malformed entry: 0 would-wrap candidates, still reported as malformed", async () => {
    writeCursor({ broken: { command: "node", args: "not-an-array" } });
    const io = collect();

    await runEnableCommand({ dryRun: true, write: io.write });

    const text = io.text();
    expect(text).toContain("would wrap 0 server");
    expect(text).toContain("MALFORMED");
    expect(text).toContain("broken");
  });
});
