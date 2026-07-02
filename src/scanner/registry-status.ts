/**
 * Registry lifecycle-status assessment (E9a).
 *
 * The official MCP registry marks each server with a lifecycle status —
 * `active` | `deprecated` | `deleted` (see the registry `RegistryExtensions`
 * type). This module turns that raw string into an enforcement decision.
 *
 * FAIL-SAFE, by design (the inverse of the guard/pins fail-CLOSED posture):
 * registry status is an availability signal, not an integrity one. We act ONLY
 * on the two explicitly-known bad values. An absent, `active`, or unrecognized
 * status yields no action — a new benign status the registry adds later must
 * never start blocking installs. The hard control is elsewhere (integrity pins,
 * trust score); this is a cheap "the registry itself pulled this listing" gate.
 *
 * Pure: no network, no filesystem, no clock.
 */

import type { Finding } from "./tier1.js";
import type { ServerEntry } from "../registry/types.js";
import { OFFICIAL_META_KEY } from "../utils/format-trust.js";

/** Removed/withdrawn from the registry — BLOCK install/up, WARN in audit. */
const STATUS_DELETED = "deleted";
/** Superseded but still usable — advisory WARN everywhere, never blocks. */
const STATUS_DEPRECATED = "deprecated";

export interface RegistryStatusAssessment {
  /** The normalized (trimmed, lower-cased) status, if any. */
  status?: string;
  /** The registry's optional human explanation for the status. */
  statusMessage?: string;
  /** True ONLY for an explicit `deleted` status — callers fail closed. */
  blocks: boolean;
  /** A medium advisory finding for `deleted`|`deprecated`, else undefined. */
  finding?: Finding;
}

function makeFinding(status: string, statusMessage?: string): Finding {
  const detail = statusMessage ? ` — ${statusMessage}` : "";
  const message =
    status === STATUS_DELETED
      ? `Server is marked "deleted" (removed) in the MCP registry${detail}`
      : `Server is marked "deprecated" in the MCP registry${detail}`;
  return { severity: "medium", type: "registry-status", message, location: "registry metadata" };
}

/**
 * Assess a raw registry status string.
 */
export function assessRegistryStatus(
  status: string | undefined,
  statusMessage?: string
): RegistryStatusAssessment {
  const normalized = status?.trim().toLowerCase();
  if (normalized === STATUS_DELETED) {
    return { status: normalized, statusMessage, blocks: true, finding: makeFinding(STATUS_DELETED, statusMessage) };
  }
  if (normalized === STATUS_DEPRECATED) {
    return { status: normalized, statusMessage, blocks: false, finding: makeFinding(STATUS_DEPRECATED, statusMessage) };
  }
  return { status: normalized, statusMessage, blocks: false };
}

/**
 * Assess a ServerEntry's official registry status (convenience over
 * {@link assessRegistryStatus} — reads the `_meta` official block).
 */
export function assessServerStatus(entry: ServerEntry): RegistryStatusAssessment {
  const official = entry._meta?.[OFFICIAL_META_KEY];
  return assessRegistryStatus(official?.status, official?.statusMessage);
}
