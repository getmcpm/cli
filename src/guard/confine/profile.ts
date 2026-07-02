/**
 * Platform-neutral confinement profile for F1 `mcpm guard --confine`.
 *
 * A ConfineProfile is the RENDERED (materialized-absolute-paths) description of
 * one server's OS-sandbox policy. It is deliberately platform-neutral so it is
 * 100% unit-testable on the ubuntu-only CI; the OS backend (backend-macos.ts)
 * renders it to Seatbelt SBPL at spawn time.
 *
 * v1 ships the "standard" tier only (read-denylist of secret dirs, a write
 * allowlist that denies all of $HOME except caches/scratch, and an all-or-none
 * egress switch). The "strict" tier (read-allowlist + host-granular net) is
 * deferred and intentionally NOT a schema member yet.
 *
 * The profile is stored RENDERED (not as a symbolic "standard tier" reference)
 * so its content hash — the value bound into the wrap marker — stays stable
 * across mcpm upgrades that might change how a tier renders. If it were symbolic,
 * a re-render on upgrade would mismatch the marker and brick every enrolled
 * server (spawn decision-table row 3). See hashConfineProfile.
 */

import { createHash } from "node:crypto";
import { z } from "zod";

export const CONFINE_FORMAT_VERSION = 1;

/** v1 = "standard" only; "strict" is reserved/deferred (see module header). */
export const ConfineTierSchema = z.enum(["standard"]);
export type ConfineTier = z.infer<typeof ConfineTierSchema>;

/**
 * Egress posture. v1 is all-or-none — Seatbelt host-granular filtering is
 * unreliable, so per-host allowlists are deferred to the strict tier.
 */
export const ConfineNetSchema = z.enum(["all", "none"]);
export type ConfineNet = z.infer<typeof ConfineNetSchema>;

export const ConfineProfileSchema = z
  .object({
    tier: ConfineTierSchema,
    /**
     * When true, a server whose backend is unavailable (or whose marker is
     * stripped / store is gone) FAILS CLOSED at spawn instead of the hybrid
     * default (warn + run unconfined). Replicated into the wrap marker as the
     * bare `--confine-required` flag so it survives whole-store deletion.
     */
    require_confine: z.boolean(),
    /** Absolute secret dirs the child may not READ (allow-all-except-these). */
    read_deny: z.array(z.string()),
    /** Absolute dirs the child MAY write (deny-all-except-these). */
    write_allow: z.array(z.string()),
    net: ConfineNetSchema,
    /** Absolute per-server scratch dir (the child's only $HOME-adjacent write root). */
    scratch_dir: z.string(),
    /** ISO 8601 timestamp the profile was derived. */
    captured_at: z.string(),
  })
  .strict();
export type ConfineProfile = z.infer<typeof ConfineProfileSchema>;

export const ConfineStoreSchema = z
  .object({
    format_version: z.number(),
    /** server name → its rendered profile. */
    servers: z.record(z.string(), ConfineProfileSchema),
  })
  .strict();
export type ConfineStore = z.infer<typeof ConfineStoreSchema>;

export function emptyConfineStore(): ConfineStore {
  return { format_version: CONFINE_FORMAT_VERSION, servers: {} };
}

/**
 * Recursively sort object keys so the hash is independent of key order — a YAML
 * round-trip (store read) may reorder keys, but the marker's content hash was
 * computed at enable time; both must agree. Arrays keep their order (derive
 * emits read_deny/write_allow already sorted, so they are canonical too).
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.keys(obj)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = canonicalize(obj[k]);
        return acc;
      }, {});
  }
  return value;
}

/**
 * Content hash of a profile — the value bound into the wrap marker
 * (`--confine-profile-hash`). A CONTENT hash (not an opaque id) is what makes
 * the marker↔store binding load-bearing: a same-user attacker who rewrites the
 * stored profile body (issue #19 — the sidecar is unkeyed) changes this hash, so
 * the spawn-time recompute no longer matches the marker and the run fails closed.
 *
 * Hashes ONLY the enforcement-policy fields — `captured_at` is provenance
 * metadata, not policy, and is DELIBERATELY excluded. If it were hashed, two
 * derivations of the same policy at different times would hash differently, so a
 * multi-client partial-enable + retry (which re-derives an already-enrolled
 * server with a fresh timestamp) would mint a new hash that no longer matches the
 * already-wrapped clients' markers → spawn decision-table row 3 (fail-closed
 * ALWAYS) would brick a working server with a bogus tamper alarm.
 */
export function hashConfineProfile(profile: ConfineProfile): string {
  const { captured_at: _capturedAt, ...policy } = profile;
  return createHash("sha256").update(JSON.stringify(canonicalize(policy))).digest("hex");
}
