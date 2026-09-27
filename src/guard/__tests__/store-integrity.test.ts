/**
 * Direct unit tests for the shared store-integrity helpers (PR2 extraction from
 * pins.ts + policy.ts). The behavior is also covered transitively by the
 * pins/policy suites; these assert the extracted module in isolation, including
 * the new `label` that names the store in the symlink-refusal message.
 */

import { describe, expect, test, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync, readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileSha, assertNotSymlink, writeFileAtomic, touchIfAbsent } from "../store-integrity.js";

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

  // #232: the create-if-absent seed for pins.json.
  describe("touchIfAbsent", () => {
    test("creates the file with its full content at 0600 and leaves no temp file", async () => {
      const f = path.join(dir, "pins.json");
      await touchIfAbsent(f, "{}\n");
      expect(readFileSync(f, "utf-8")).toBe("{}\n");
      expect(statSync(f).mode & 0o777).toBe(0o600);
      expect(readdirSync(dir)).toEqual(["pins.json"]);
    });

    test("never replaces an existing file (or follows a symlink there)", async () => {
      const f = path.join(dir, "pins.json");
      writeFileSync(f, "committed");
      await touchIfAbsent(f, "placeholder");
      expect(readFileSync(f, "utf-8")).toBe("committed");
      const outside = path.join(dir, "outside");
      symlinkSync(outside, path.join(dir, "dangling"));
      await touchIfAbsent(path.join(dir, "dangling"), "placeholder");
      expect(existsSync(outside)).toBe(false);
    });

    test("still creates the file on a volume without hard links (exFAT: link() is ENOTSUP)", async () => {
      vi.resetModules();
      vi.doMock("node:fs/promises", async (importOriginal) => ({
        ...(await importOriginal<typeof import("node:fs/promises")>()),
        link: async () => {
          throw Object.assign(new Error("operation not supported"), { code: "ENOTSUP" });
        },
      }));
      try {
        const { touchIfAbsent: touchNoLinks } = await import("../store-integrity.js");
        const f = path.join(dir, "pins.json");
        await touchNoLinks(f, "{}\n");
        expect(readFileSync(f, "utf-8")).toBe("{}\n");
        await touchNoLinks(f, "second");
        expect(readFileSync(f, "utf-8")).toBe("{}\n");
        expect(readdirSync(dir)).toEqual(["pins.json"]);
      } finally {
        vi.doUnmock("node:fs/promises");
        vi.resetModules();
      }
    });
  });
});
