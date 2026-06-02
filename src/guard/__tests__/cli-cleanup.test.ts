/**
 * Fix 4: `mcpm guard cleanup` must not silently print "nothing to prune" when
 * pins.json is tampered. readPins returns an empty file (no throw) for the
 * genuine "no pins yet" case, so any thrown error is a PinsIntegrityError or an
 * I/O error — those must surface a visible warning and abort, not be swallowed
 * to null.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { _resetCachedStorePath } from "../../store/index.js";

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
