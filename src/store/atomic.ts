/**
 * Symlink-safe atomic writes + locked read-modify-write for the mcpm store.
 *
 * The store writer holds the most sensitive data in mcpm — the encrypted secret
 * store (secrets.enc.json) plus servers.json and aliases.json. This module gives
 * every store writer the same hardening the config adapters (#26) and guard pins
 * already have:
 *
 *   - Symlink refusal: an attacker who pre-places `<file>` or `<file>.tmp` as a
 *     symlink to a sensitive target cannot redirect mcpm's write onto the link
 *     target. We lstat the destination before writing, write the `.tmp`
 *     EXCLUSIVELY (flag "wx" = O_CREAT|O_EXCL, which fails EEXIST through a
 *     pre-placed symlink), and re-lstat the destination before the rename.
 *
 *   - Serialized read-modify-write: every RMW (set/merge/delete a secret, add/
 *     remove an installed server, set/remove an alias) is run under a
 *     proper-lockfile lock so two concurrent processes cannot lost-update each
 *     other. Without it, a dropped secret leaves a `mcpm:keychain:` placeholder
 *     in a client config with no backing value, and guard throws "Secret not
 *     found" at launch.
 *
 * Mirrors the idioms in src/config/adapters/base.ts and src/guard/pins.ts.
 */

import { writeFile, rename, lstat, unlink } from "fs/promises";
import path from "path";
import lockfile from "proper-lockfile";
import { getStorePath } from "./index.js";

// Dedicated lock file. Locking a single, always-present file (rather than each
// data file, which may not exist yet and is replaced via rename) gives a stable
// lock target for every store RMW. proper-lockfile requires the target to exist
// before locking, so we touch it first.
const LOCK_FILENAME = ".store.lock";

const LOCK_OPTS = {
  retries: { retries: 10, minTimeout: 20, maxTimeout: 400 },
  stale: 5_000,
} as const;

function isEnoent(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as NodeJS.ErrnoException).code === "ENOENT"
  );
}

/**
 * Throw if `targetPath` is a symlink. A missing path (ENOENT) is fine — there
 * is nothing to traverse. lstat does not follow the final component, so this
 * detects a symlinked destination/.tmp before any write or rename follows it
 * onto an attacker-chosen target. Mirrors base.ts `assertNotSymlink` (#26).
 */
async function assertNotSymlink(targetPath: string): Promise<void> {
  let st: Awaited<ReturnType<typeof lstat>>;
  try {
    st = await lstat(targetPath);
  } catch (err) {
    if (isEnoent(err)) return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`Refusing to write store file through a symlink: ${targetPath}`);
  }
}

/**
 * Write `content` to `filePath` atomically and symlink-safely.
 *
 * #26 hardening:
 *   1. lstat the destination — refuse if it is a symlink.
 *   2. unlink any stale `.tmp`. This removes the LINK ITSELF, not its target:
 *      a pre-placed `.tmp` symlink is deleted (leaving its target untouched),
 *      and a leftover real `.tmp` from a crashed run — which would otherwise
 *      cause a false EEXIST on the exclusive open — is cleared.
 *   3. write the `.tmp` EXCLUSIVELY (flag "wx" = O_CREAT|O_EXCL). The unlink in
 *      step 2 already removed any symlink, so this open creates a fresh inode;
 *      "wx" is the BACKSTOP that still fails EEXIST (rather than following a
 *      link) if the narrow unlink→open window is re-raced by an attacker.
 *   4. re-lstat the destination — refuse if it became a symlink — then rename.
 */
export async function writeFileAtomic(
  filePath: string,
  content: string
): Promise<void> {
  await assertNotSymlink(filePath);

  const tmpPath = `${filePath}.tmp`;
  try {
    await unlink(tmpPath);
  } catch (err) {
    if (!isEnoent(err)) throw err;
  }

  await writeFile(tmpPath, content, {
    encoding: "utf-8",
    mode: 0o600,
    flag: "wx",
  });

  // Defense-in-depth, not the primary TOCTOU guard: POSIX rename(2) atomically
  // REPLACES the destination and does NOT follow a symlink at that path, so even
  // a destination swapped for a symlink after the first lstat is overwritten,
  // not traversed. This re-lstat simply refuses that case early so we never
  // leave a dangling link in the store dir.
  await assertNotSymlink(filePath);
  await rename(tmpPath, filePath);
}

// ---------------------------------------------------------------------------
// Locked read-modify-write
// ---------------------------------------------------------------------------

async function lockPath(): Promise<string> {
  return path.join(await getStorePath(), LOCK_FILENAME);
}

/**
 * Run a read-modify-write under an exclusive cross-process lock.
 *
 * Serializes all store mutations against each other (security review F2 idiom,
 * as in guard/pins.ts) so two concurrent mcpm processes — e.g. a `serve`-mode
 * MCP tool handler racing a CLI invocation — cannot lost-update the same file.
 * `fn` does the read-merge-write; it runs exactly once, while holding the lock.
 */
export async function withStoreLock<T>(fn: () => Promise<T>): Promise<T> {
  const lp = await lockPath();

  // Refuse a pre-placed `.store.lock` symlink. proper-lockfile realpath-resolves
  // its target, so a symlink would relocate the lock to a different directory —
  // silently breaking mutual exclusion (two processes would lock different
  // paths and both "succeed"). Same lstat guard writeFileAtomic uses.
  await assertNotSymlink(lp);

  // proper-lockfile requires the lock target to exist; touch it once.
  try {
    await writeFile(lp, "", { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }

  const release = await lockfile.lock(lp, LOCK_OPTS);
  try {
    return await fn();
  } finally {
    await release();
  }
}
