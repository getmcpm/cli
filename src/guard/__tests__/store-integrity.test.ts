/**
 * Direct unit tests for the shared store-integrity helpers (PR2 extraction from
 * pins.ts + policy.ts). The behavior is also covered transitively by the
 * pins/policy suites; these assert the extracted module in isolation, including
 * the new `label` that names the store in the symlink-refusal message.
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileSha, assertNotSymlink, writeFileAtomic } from "../store-integrity.js";

describe("store-integrity", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "mcpm-store-int-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  describe("fileSha", () => {
    test("is the sha256:<hex> of the content and is deterministic", () => {
      const a = fileSha("hello");
      expect(a).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(fileSha("hello")).toBe(a);
      expect(fileSha("hellp")).not.toBe(a);
    });
  });

  describe("assertNotSymlink", () => {
    test("resolves for a missing path (ENOENT — nothing to traverse)", async () => {
      await expect(assertNotSymlink(path.join(dir, "nope"), "pins")).resolves.toBeUndefined();
    });

    test("resolves for a regular file", async () => {
      const f = path.join(dir, "regular");
      writeFileSync(f, "x");
      await expect(assertNotSymlink(f, "pins")).resolves.toBeUndefined();
    });

    test("throws for a symlinked target, naming the store via label", async () => {
      const target = path.join(dir, "linked");
      symlinkSync(path.join(dir, "outside"), target);
      await expect(assertNotSymlink(target, "confine")).rejects.toThrow(
        /Refusing to write confine through a symlink/,
      );
    });
  });

  describe("writeFileAtomic", () => {
    test("writes content with 0600 and no leftover .tmp", async () => {
      const f = path.join(dir, "out.txt");
      await writeFileAtomic(f, "payload", "policy");
      expect(readFileSync(f, "utf-8")).toBe("payload");
      expect(existsSync(`${f}.tmp`)).toBe(false);
    });

    test("refuses to write through a symlinked target", async () => {
      const outside = path.join(dir, "outside-target");
      writeFileSync(outside, "stale");
      const link = path.join(dir, "victim");
      symlinkSync(outside, link);
      await expect(writeFileAtomic(link, "new", "pins")).rejects.toThrow(/symlink/);
      // The symlink target was NOT followed/overwritten.
      expect(readFileSync(outside, "utf-8")).toBe("stale");
    });

    test("clears a stale .tmp (which may be a pre-placed symlink) before writing", async () => {
      const f = path.join(dir, "out2.txt");
      // Pre-place a stale .tmp as a symlink to an outside file.
      const outside = path.join(dir, "stale-outside");
      writeFileSync(outside, "do-not-touch");
      symlinkSync(outside, `${f}.tmp`);
      await writeFileAtomic(f, "fresh", "pins");
      expect(readFileSync(f, "utf-8")).toBe("fresh");
      // The pre-placed symlink's target must be untouched (unlink removed the link).
      expect(readFileSync(outside, "utf-8")).toBe("do-not-touch");
    });
  });
});
