/**
 * Local JSON file store for mcpm.
 *
 * All data is persisted under ~/.mcpm/ as JSON files.
 * All writes are atomic: data is written to a .tmp file first, then renamed.
 */

import { readFile, writeFile, rename, mkdir } from "fs/promises";
import os from "os";
import path from "path";

// ---------------------------------------------------------------------------
// Store path
// ---------------------------------------------------------------------------

// Module-level cache so mkdir is only called once per process lifetime.
// getStorePath() is called on every readJson/writeJson — this avoids redundant
// async syscalls when the directory already exists.
let _cachedStorePath: string | null = null;

/**
 * Returns the absolute path to the mcpm store directory (~/.mcpm).
 * Creates the directory if it does not already exist.
 *
 * Cached per-process: mkdir is only called once. Subsequent calls return the
 * cached path synchronously-via-resolved-promise.
 */
export async function getStorePath(): Promise<string> {
  if (_cachedStorePath !== null) {
    return _cachedStorePath;
  }
  const storePath = path.join(os.homedir(), ".mcpm");
  // { recursive: true } means mkdir will not throw if the directory already
  // exists. Any other error (e.g. EACCES) is caught and silently ignored so
  // that read operations still work even if we cannot create the directory.
  try {
    await mkdir(storePath, { recursive: true });
  } catch {
    // Ignore — directory may already exist or we may not need to write.
  }
  _cachedStorePath = storePath;
  return storePath;
}

/**
 * Reset the cached store path. Only for use in tests.
 * @internal
 */
export function _resetCachedStorePath(): void {
  _cachedStorePath = null;
}

// ---------------------------------------------------------------------------
// readJson / writeJson
// ---------------------------------------------------------------------------

/**
 * Read and parse a JSON file from the store directory.
 *
 * @param filename - Relative filename inside ~/.mcpm/ (e.g. "servers.json").
 * @returns Parsed value, or null if the file does not exist (ENOENT).
 * @throws For malformed JSON or permission errors.
 */
export async function readJson<T>(filename: string): Promise<T | null> {
  const storePath = await getStorePath();
  const resolved = path.resolve(storePath, filename);
  const storeResolved = path.resolve(storePath);
  if (!resolved.startsWith(storeResolved + path.sep)) {
    throw new Error(`Path traversal attempt blocked: "${filename}"`);
  }
  const filePath = resolved;

  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }

  return JSON.parse(raw) as T;
}

/**
 * Write data as JSON to a file in the store directory, atomically.
 *
 * @param filename - Relative filename inside ~/.mcpm/.
 * @param data     - Serialisable value to persist.
 */
export async function writeJson(
  filename: string,
  data: unknown
): Promise<void> {
  const storePath = await getStorePath();
  const resolved = path.resolve(storePath, filename);
  const storeResolved = path.resolve(storePath);
  if (!resolved.startsWith(storeResolved + path.sep)) {
    throw new Error(`Path traversal attempt blocked: "${filename}"`);
  }
  const filePath = resolved;
  const tmpPath = `${filePath}.tmp`;

  await writeFile(tmpPath, JSON.stringify(data, null, 2), "utf-8");
  await rename(tmpPath, filePath);
}
