/**
 * Shared filesystem-integrity primitives for the guard stores under ~/.mcpm
 * (pins.json, guard-policy.yaml, and the F1 guard-confine.yaml).
 *
 * These three helpers were byte-for-byte duplicated in pins.ts and policy.ts
 * (each carrying a "#26 replicated from config/adapters/base.ts" note). A third
 * copy for the confine store would triple a SECURITY primitive — the
 * symlink-safe atomic write — onto which a future hardening fix could land in
 * one copy and silently miss the others. Extracted here so every guard store
 * shares one implementation. Behavior is identical to the prior copies; the only
 * change is `assertNotSymlink`/`writeFileAtomic` take a `label` so the
 * symlink-refusal message still names the store ("pins" / "policy" / "confine").
 *
 * Issue #19: the SHA-256 sidecar is UNKEYED — integrity (tamper-evidence), NOT
 * authenticity. A same-user/postinstall process can recompute it to match a
 * malicious edit, so it is not anti-malware. A keyed MAC needs a secret the
 * writable store lacks (#15).
 */

import { createHash, randomUUID } from "node:crypto";
import { link, lstat, rename, unlink, writeFile } from "node:fs/promises";

/** `sha256:<hex>` integrity checksum over file content. UNKEYED (see #19). */
export function fileSha(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

/**
 * Throw if `targetPath` is a symlink. lstat does not follow the final component,
 * so this detects a symlinked target before a write follows it onto an
 * attacker-chosen path. A missing path (ENOENT) is fine — nothing to traverse.
 * `label` names the store in the error message (e.g. "pins", "policy").
 */
export async function assertNotSymlink(targetPath: string, label: string): Promise<void> {
  let st: Awaited<ReturnType<typeof lstat>>;
  try {
    st = await lstat(targetPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`Refusing to write ${label} through a symlink: ${targetPath}`);
  }
}

/**
 * Write `data` atomically to `target`: refuse symlinks, clear any stale `.tmp`
 * (which may itself be a pre-placed symlink — unlinking removes only the link),
 * then create the `.tmp` EXCLUSIVELY (wx) so it is a fresh, unfollowed inode,
 * and rename into place. Mirrors base.ts/writeAtomic. `label` flows to the
 * symlink-refusal message.
 */
export async function writeFileAtomic(target: string, data: string, label: string): Promise<void> {
  await assertNotSymlink(target, label);
  const tmp = `${target}.tmp`;
  try {
    await unlink(tmp);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  await writeFile(tmp, data, { encoding: "utf-8", mode: 0o600, flag: "wx" });
  await rename(tmp, target);
}

/**
 * #232: create `target` with `placeholderContent` ONLY IF it does not already
 * exist — atomically from a CONCURRENT READER's point of view.
 *
 * A plain `writeFile(target, content, {flag:"wx"})` (the pre-#232 "touch if
 * absent" idiom, still fine for a SINGLE writer) is two separate syscalls: the
 * `open(O_CREAT|O_EXCL)` makes `target` exist at 0 bytes, and the following
 * `write()` fills it in afterward. A reader that opens `target` in the gap
 * between those two — plain, unlocked `readPins()` at another guard session's
 * startup — sees a torn, empty file and fails closed with "Unexpected end of
 * JSON input". Harmless with one writer (the gap is vanishingly unlikely to be
 * hit); measured to fire under real contention once `updatePins` gave EVERY
 * guard session's first pins.json touch a peer to race against (an IDE
 * launching N servers at once, each pinning tools AND a handshake) — see
 * storm.mjs / CHANGELOG.
 *
 * Fix: write the FULL content to a private temp file first (so it is complete
 * before anything can observe it under the real name), then `link()` it into
 * place. `link()` is a single atomic syscall — a reader either sees no file or
 * the fully-written one, never a partial one — and unlike `rename()` it fails
 * with EEXIST if `target` already exists, so a slower racer can never clobber
 * whatever a faster one (a real writer, not just another toucher) already
 * committed there. Deliberately NOT `writeFileAtomic`: that always REPLACES
 * `target`, which is correct for an intentional overwrite but wrong for a
 * touch, whose entire point is "only if nothing is there yet".
 *
 * A volume without hard links (exFAT/FAT, some SMB mounts) fails the `link()`
 * with ENOTSUP/EPERM even though nothing is there — measured on exFAT, where
 * every call threw and no pin was ever persisted. There we fall back to the
 * plain exclusive create: correct, just without the torn-read protection.
 */
export async function touchIfAbsent(target: string, placeholderContent: string): Promise<void> {
  const tmp = `${target}.touch-${process.pid}-${randomUUID()}`;
  const create = { encoding: "utf-8", mode: 0o600, flag: "wx" } as const;
  try {
    await writeFile(tmp, placeholderContent, create);
    try {
      await link(tmp, target);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") return;
      await writeFile(target, placeholderContent, create);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  } finally {
    await unlink(tmp).catch(() => undefined);
  }
}
