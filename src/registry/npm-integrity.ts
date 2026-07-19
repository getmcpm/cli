/**
 * npm artifact integrity tripwire (H11 slice 1 — WARN-only).
 *
 * Fetches npm's published `dist.integrity` for a specific package coordinate
 * from the npm registry and provides a comparison utility so `mcpm up` can
 * detect when the published record changed since the lockfile was written.
 *
 * CRITICAL HONESTY BOUNDARY: mcpm NEVER downloads or runs the artifact
 * (npx/uvx do that, possibly from a different mirror). This module checks the
 * *npm registry's published record*, NOT the bytes the agent runs. No user-
 * facing copy may say "serving different bytes", "you are protected", or "this
 * package is safe". The truthful claim is: "npm's published record for
 * <pkg>@<X.Y.Z> changed since you locked it."
 */

import type { NpmIntegritySnapshot } from "../stack/schema.js";
import { readCappedJsonOrUndefined } from "./http-utils.js";

export type { NpmIntegritySnapshot } from "../stack/schema.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Hard-coded npm registry host — not caller-overridable (SSRF prevention). */
const NPM_REGISTRY_HOST = "registry.npmjs.org";

/** Per-version manifest body cap. A real manifest is ~5-20 KB; 2 MB is generous. */
const BODY_CAP_BYTES = 2 * 1024 * 1024; // 2 MB

/** Default HTTP timeout. */
const DEFAULT_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// fetchNpmIntegrity
// ---------------------------------------------------------------------------

/**
 * Fetch the npm registry's published `dist.integrity` for an exact package
 * coordinate and return a snapshot, or `undefined` on any failure (FAIL-OPEN).
 *
 * The host is hard-coded to `registry.npmjs.org` and HTTPS is guaranteed by
 * the literal URL — the caller cannot redirect this to an internal host.
 *
 * Redirects are NOT followed (`redirect: "manual"`): a 3xx/opaqueredirect
 * resolves to `undefined` (fail-open). In practice this endpoint does not
 * redirect. Mirrors the registry client's security #21 pattern.
 *
 * NEVER throws. All errors resolve to `undefined`.
 *
 * @param identifier - npm package name, scoped or unscoped (e.g. "@scope/name")
 * @param npmVersion - exact npm version string (e.g. "1.3.0")
 */
export async function fetchNpmIntegrity(
  identifier: string,
  npmVersion: string,
  opts?: { fetchImpl?: typeof fetch; timeoutMs?: number }
): Promise<NpmIntegritySnapshot | undefined> {
  const fetchImpl = opts?.fetchImpl ?? fetch;
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const url = `https://${NPM_REGISTRY_HOST}/${encodeURIComponent(identifier)}/${encodeURIComponent(npmVersion)}`;

  try {
    const raw = await fetchManifest(url, fetchImpl, timeoutMs);
    if (raw === undefined) return undefined;

    const integrity = extractIntegrity(raw);
    if (integrity === undefined) return undefined;

    return { npmVersion, integrity };
  } catch {
    // Belt-and-suspenders: the inner helpers return undefined on known errors,
    // but any unexpected throw is caught here so we never reject.
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Single fetch — redirects refused (redirect:"manual")
// ---------------------------------------------------------------------------

async function fetchManifest(
  url: string,
  fetchImpl: typeof fetch,
  timeoutMs: number
): Promise<unknown> {
  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    // redirect:"manual" — never follow a 3xx to an attacker-chosen (possibly
    // internal) host. A redirect surfaces as an opaqueredirect (status 0) or a
    // 3xx status; both resolve to undefined (fail-open). This endpoint does not
    // redirect in practice. Mirrors client.ts / publish-client.ts (security #21).
    response = await fetchImpl(url, { redirect: "manual", signal: controller.signal });
  } catch {
    return undefined;
  } finally {
    clearTimeout(timerId);
  }

  if (
    response.type === "opaqueredirect" ||
    (response.status >= 300 && response.status < 400)
  ) {
    return undefined;
  }

  if (!response.ok) return undefined;

  return readCappedJsonOrUndefined(response, BODY_CAP_BYTES);
}

// ---------------------------------------------------------------------------
// dist.integrity extractor
// ---------------------------------------------------------------------------

function extractIntegrity(raw: unknown): string | undefined {
  if (raw === null || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  if (!("dist" in obj)) return undefined;
  const dist = obj.dist;
  if (dist === null || typeof dist !== "object") return undefined;
  const distObj = dist as Record<string, unknown>;
  if (!("integrity" in distObj)) return undefined;
  if (typeof distObj.integrity !== "string") return undefined;
  return distObj.integrity;
}

// ---------------------------------------------------------------------------
// compareIntegrity
// ---------------------------------------------------------------------------

/** Result of comparing two SRI strings. */
export type IntegrityComparison = "equal" | "differ" | "format-only";

/**
 * Compare two SRI (Subresource Integrity) strings by picking the strongest
 * algorithm present in BOTH. Priority: sha512 > sha384 > sha256 > sha1.
 *
 * - `"equal"` — strongest common algorithm has identical digests
 * - `"differ"` — strongest common algorithm has different digests
 * - `"format-only"` — no common algorithm; cannot confirm bytes changed
 *
 * Robust to extra whitespace and ordering of hash entries within each string.
 */
export function compareIntegrity(
  locked: string,
  fresh: string
): IntegrityComparison {
  const lockedMap = parseSri(locked);
  const freshMap = parseSri(fresh);

  const ALGO_PRIORITY = ["sha512", "sha384", "sha256", "sha1"] as const;

  for (const algo of ALGO_PRIORITY) {
    const lockedDigest = lockedMap.get(algo);
    const freshDigest = freshMap.get(algo);
    if (lockedDigest !== undefined && freshDigest !== undefined) {
      return lockedDigest === freshDigest ? "equal" : "differ";
    }
  }

  return "format-only";
}

/**
 * Parse an SRI string into a Map of algorithm → base64-digest.
 * SRI may contain multiple space-separated hash entries (e.g. "sha512-X sha1-Y").
 */
function parseSri(sri: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const token of sri.trim().split(/\s+/)) {
    const dashIdx = token.indexOf("-");
    if (dashIdx < 1) continue;
    const algo = token.slice(0, dashIdx).toLowerCase();
    const digest = token.slice(dashIdx + 1);
    if (algo && digest) {
      result.set(algo, digest);
    }
  }
  return result;
}
