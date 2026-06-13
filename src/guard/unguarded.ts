/**
 * Unguarded-consent store for mcpm-guard (H9 — fail-closed posture).
 *
 * URL/HTTP-transport server entries have no `command`, so the stdio MITM relay
 * cannot wrap them — they run with ZERO runtime inspection. H9 converts the
 * old silent skip into an explicit, informed-consent DENY-BY-DEFAULT: such a
 * server is refused unless the user opts in (`--allow-unguarded` /
 * `policy.allowUrlServers`). This store records the SET of server names the
 * user has consented to run unguarded, so we can:
 *
 *   1. warn ONCE at allow-time, then suppress on subsequent runs UNLESS the
 *      unguarded set CHANGES (re-warning every run trains rubber-stamping —
 *      SECURITY-HARDENING.md §5 H9 critique fix), and
 *   2. let `mcpm guard enable` recognise a previously-consented server.
 *
 * Asymmetry (documented): ADDITIONS re-warn (a new unguarded server is new
 * risk); REMOVALS silently update the store (dropping a server only reduces
 * risk). See {@link isNewUnguarded}.
 *
 * Storage: ~/.mcpm/guard-unguarded.json — { servers: string[] } (sorted,
 * deduped). Routed through the store's hardened atomic writer (symlink-safe,
 * 0o600), the same discipline as pins.json. This is consent state, NOT an
 * integrity-protected control surface — an attacker who can write it could
 * equally write the IDE config it gates, so an integrity sidecar would add no
 * real asymmetry here (mirrors the issue #19 reasoning for pins).
 */

import { z } from "zod";
import { readJson, writeJson } from "../store/index.js";

export const UNGUARDED_FILENAME = "guard-unguarded.json";

const UnguardedStoreSchema = z.object({
  servers: z.array(z.string()),
});

// ---------------------------------------------------------------------------
// Pure set helpers
// ---------------------------------------------------------------------------

/** Sort + dedupe a list of server names (deterministic store/marker order). */
function normalize(names: readonly string[]): string[] {
  return [...new Set(names)].sort();
}

/**
 * True iff `current` contains at least one name NOT in `previous` (an
 * ADDITION). A pure subset (or equal set) returns false, so removals do NOT
 * trigger a re-warn — only newly-consented unguarded servers do.
 */
export function isNewUnguarded(
  current: readonly string[],
  previous: readonly string[],
): boolean {
  const prev = new Set(previous);
  return current.some((name) => !prev.has(name));
}

/** Union of two name lists, sorted + deduped. */
export function mergeUnguarded(
  a: readonly string[],
  b: readonly string[],
): string[] {
  return normalize([...a, ...b]);
}

// ---------------------------------------------------------------------------
// Store I/O
// ---------------------------------------------------------------------------

/**
 * Read the consented-unguarded server-name set. Returns an empty array when
 * the store does not exist (first run) or is structurally invalid (treated as
 * "no consent recorded" — fail closed: an unreadable store must not be read as
 * blanket consent).
 */
export async function readUnguardedConsent(): Promise<string[]> {
  const raw = await readJson<unknown>(UNGUARDED_FILENAME).catch(() => null);
  if (raw === null) return [];
  const parsed = UnguardedStoreSchema.safeParse(raw);
  if (!parsed.success) return [];
  return normalize(parsed.data.servers);
}

/** Write the consented-unguarded set (sorted + deduped) atomically. */
export async function writeUnguardedConsent(servers: readonly string[]): Promise<void> {
  await writeJson(UNGUARDED_FILENAME, { servers: normalize(servers) });
}
