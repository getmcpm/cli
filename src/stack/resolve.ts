/**
 * Version resolution — resolves semver ranges against available versions.
 *
 * Uses the `semver` package for range matching.
 * Pure functions, no I/O.
 */

import semver from "semver";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ResolveResult {
  readonly resolved: string;
  readonly range: string;
  readonly available: readonly string[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve a version range against a list of available versions.
 *
 * Supports exact versions ("1.2.3"), caret ranges ("^1.0.0"),
 * and tilde ranges ("~1.2.0").
 *
 * @param serverName — used only for error messages
 * @param range — the version range from mcpm.yaml
 * @param available — version strings from the registry
 * @returns the highest satisfying version
 * @throws if no version satisfies the range
 */
export function resolveVersion(
  serverName: string,
  range: string,
  available: readonly string[]
): ResolveResult {
  // Filter to valid semver strings only (registry may return non-semver)
  const validVersions = available.filter((v) => semver.valid(v) !== null);

  // Exact version match — skip range resolution
  if (semver.valid(range) !== null) {
    const exact = validVersions.find((v) => semver.eq(v, range));
    if (exact) {
      return { resolved: exact, range, available: validVersions };
    }
    throw new Error(
      `Version "${range}" not found for "${serverName}". ` +
        `Available: ${formatVersionList(validVersions)}`
    );
  }

  // Range resolution (caret, tilde)
  const match = semver.maxSatisfying(validVersions, range);
  if (match !== null) {
    return { resolved: match, range, available: validVersions };
  }

  throw new Error(
    `No version satisfies "${range}" for "${serverName}". ` +
      `Available: ${formatVersionList(validVersions)}`
  );
}

/**
 * Resolve a version range using a single version (fallback path).
 *
 * When the registry only returns the latest version (no version listing
 * endpoint), check if the single version satisfies the range.
 */
export function resolveWithSingleVersion(
  serverName: string,
  range: string,
  singleVersion: string
): ResolveResult {
  if (semver.valid(range) !== null) {
    // Exact match required
    if (semver.eq(singleVersion, range)) {
      return { resolved: singleVersion, range, available: [singleVersion] };
    }
    throw new Error(
      `Version "${range}" not found for "${serverName}". ` +
        `Only version available: ${singleVersion}`
    );
  }

  if (semver.satisfies(singleVersion, range)) {
    return { resolved: singleVersion, range, available: [singleVersion] };
  }

  throw new Error(
    `Version "${singleVersion}" does not satisfy "${range}" for "${serverName}". ` +
      `This is the only version available from the registry.`
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatVersionList(versions: readonly string[]): string {
  if (versions.length === 0) return "(none)";
  const sorted = [...versions].sort(semver.rcompare);
  if (sorted.length <= 5) return sorted.join(", ");
  return `${sorted.slice(0, 5).join(", ")} (+${sorted.length - 5} more)`;
}
