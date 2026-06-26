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

import { createHash } from "node:crypto";
import { lstat, rename, unlink, writeFile } from "node:fs/promises";

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
