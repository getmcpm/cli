/**
 * Real-filesystem tests for the hardened store writer (src/store/atomic.ts)
 * and the writeJson path that uses it (src/store/index.ts).
 *
 * Unlike the per-module store suites (which mock fs/promises or the store
 * index), these exercise the ACTUAL OS file semantics in a throwaway temp dir,
 * proving:
 *
 *   - writeJson refuses a symlinked destination and a pre-placed symlinked
 *     `.tmp` (the write is not redirected onto the link target).
 *   - a normal write round-trips and is atomic (.tmp + rename, no leftover tmp).
 *   - withStoreLock acquires and releases a proper-lockfile lock around the
 *     read-modify-write, and sequential locked writes do not lose prior keys.
 *
 * The store directory is redirected to a temp dir by mocking os.homedir and
 * resetting getStorePath's per-process cache, so the real writeJson /
 * withStoreLock code paths run end-to-end without touching the user's ~/.mcpm.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, writeFile, symlink, rm, lstat, mkdir } from "fs/promises";
import os from "os";
import path from "path";
import lockfile from "proper-lockfile";
import { writeJson, readJson, _resetCachedStorePath } from "../../store/index.js";
import { withStoreLock } from "../../store/atomic.js";
import { setSecret, getSecret, listSecretKeys } from "../../store/keychain.js";

const realHomedir = os.homedir;
let home: string;
let storeDir: string;

const SECRET = "DO_NOT_OVERWRITE_ME\n";

beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), "mcpm-store-atomic-"));
  storeDir = path.join(home, ".mcpm");
  await mkdir(storeDir, { recursive: true, mode: 0o700 });
  // Redirect ~/.mcpm to the temp home and clear the cached path so the next
  // getStorePath() resolves to it.
  vi.spyOn(os, "homedir").mockReturnValue(home);
  _resetCachedStorePath();
});

afterEach(async () => {
  vi.restoreAllMocks();
  _resetCachedStorePath();
  await rm(home, { recursive: true, force: true });
  // Sanity: nothing should have been written to the real store directory by
  // these tests. (If it was, restoreAllMocks already put homedir back.)
  void realHomedir;
});

describe("writeJson — symlink safety (#26 parity)", () => {
  it("round-trips a normal write atomically and leaves no .tmp behind", async () => {
    await writeJson("data.json", { a: 1, b: ["x", "y"] });

    expect(await readJson("data.json")).toEqual({ a: 1, b: ["x", "y"] });

    // The temp sibling was renamed away, not left on disk.
    await expect(lstat(path.join(storeDir, "data.json.tmp"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    // The destination is a real file, not a symlink.
    expect((await lstat(path.join(storeDir, "data.json"))).isSymbolicLink()).toBe(false);
  });

  it("refuses to write through a pre-placed .tmp symlink (no redirect)", async () => {
    const secretPath = path.join(home, "secret.rc");
    await writeFile(secretPath, SECRET, "utf-8");
    // Attacker pre-creates <file>.tmp as a symlink to a sensitive file.
    await symlink(secretPath, path.join(storeDir, "secrets.enc.json.tmp"));

    // The exclusive "wx" open refuses the pre-placed symlink (EEXIST). After
    // unlinking the stale link the write lands on a fresh, unfollowed inode.
    await writeJson("secrets.enc.json", { "srv/KEY": "ciphertext" });

    // The secret target is untouched — the write was not redirected.
    expect(await readFile(secretPath, "utf-8")).toBe(SECRET);
    const written = JSON.parse(await readFile(path.join(storeDir, "secrets.enc.json"), "utf-8"));
    expect(written).toEqual({ "srv/KEY": "ciphertext" });
  });

  it("refuses to write when the destination itself is a symlink", async () => {
    const secretPath = path.join(home, "secret.rc");
    await writeFile(secretPath, SECRET, "utf-8");
    // <file> is a symlink to the sensitive file.
    await symlink(secretPath, path.join(storeDir, "secrets.enc.json"));

    await expect(
      writeJson("secrets.enc.json", { "srv/KEY": "ciphertext" })
    ).rejects.toThrow(/symlink/i);

    // The secret target is untouched.
    expect(await readFile(secretPath, "utf-8")).toBe(SECRET);
  });
});

describe("withStoreLock — locking around read-modify-write", () => {
  // proper-lockfile creates a sibling "<lockfile>.lock" directory while held.
  const lockDirPath = () => path.join(storeDir, ".store.lock.lock");

  it("acquires and releases a proper-lockfile lock around the callback", async () => {
    const lockSpy = vi.spyOn(lockfile, "lock");

    let heldDuringCallback = false;
    await withStoreLock(async () => {
      // Inside the critical section the lock dir exists.
      heldDuringCallback = (await lstat(lockDirPath())).isDirectory();
    });

    expect(heldDuringCallback).toBe(true);
    expect(lockSpy).toHaveBeenCalledTimes(1);
    // The release callback returned by lock() was invoked, so the lock dir is
    // gone after the critical section.
    await expect(lstat(lockDirPath())).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("releases the lock even when the callback throws", async () => {
    await expect(
      withStoreLock(async () => {
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");
    // Lock released despite the throw — the lock dir is gone.
    await expect(lstat(lockDirPath())).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("sequential locked secret writes do not lose prior keys", async () => {
    // Exercises the real keychain RMW (setSecret) under the real lock against
    // the temp store. A lost update would drop an earlier key.
    await setSecret("srv", "A", "valueA");
    await setSecret("srv", "B", "valueB");
    await setSecret("srv", "C", "valueC");

    const keys = (await listSecretKeys("srv")).sort();
    expect(keys).toEqual(["A", "B", "C"]);
    expect(await getSecret("srv", "A")).toBe("valueA");
    expect(await getSecret("srv", "C")).toBe("valueC");
  });
});
