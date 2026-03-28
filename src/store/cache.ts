/**
 * Registry response cache stored under ~/.mcpm/cache/.
 *
 * Cache entries are stored as { data, timestamp } objects.
 * TTL is checked on read; stale entries return null.
 */

import { readJson, writeJson } from "./index.js";

/** Default cache TTL: 1 hour in milliseconds. */
export const DEFAULT_CACHE_TTL_MS = 3_600_000;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

/**
 * Converts a cache key into a safe relative filename under cache/.
 * Colons and slashes are replaced so the string is a valid filename.
 */
function keyToFilename(key: string): string {
  const safe = key.replace(/[:/\\]/g, "_");
  return `cache/${safe}.json`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the cached value for `key` if it exists and has not expired.
 * Returns null if the entry is missing, expired, malformed, or unreadable.
 *
 * @param key   - Cache key string (e.g. "search:filesystem").
 * @param ttlMs - Time-to-live in milliseconds. Defaults to 1 hour.
 */
export async function getCachedResponse<T>(
  key: string,
  ttlMs: number = DEFAULT_CACHE_TTL_MS
): Promise<T | null> {
  try {
    const entry = await readJson<CacheEntry<T>>(keyToFilename(key));
    if (entry === null) return null;

    // Guard against malformed entries missing a timestamp.
    if (typeof entry.timestamp !== "number") return null;

    const age = Date.now() - entry.timestamp;
    if (age >= ttlMs) return null;

    return entry.data;
  } catch {
    // Treat any read/parse error as a cache miss.
    return null;
  }
}

/**
 * Stores `data` in the cache under `key` with the current timestamp.
 * Does not mutate the data passed in.
 *
 * @param key  - Cache key string.
 * @param data - Value to cache (must be JSON-serialisable).
 */
export async function setCachedResponse(
  key: string,
  data: unknown
): Promise<void> {
  const entry: CacheEntry<unknown> = {
    data,
    timestamp: Date.now(),
  };
  await writeJson(keyToFilename(key), entry);
}
