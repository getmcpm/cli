#!/usr/bin/env node
/**
 * Stamp a release version into `server.json` (the official MCP Registry manifest).
 *
 * WHY THIS IS A SCRIPT AND NOT A `jq` LINE IN THE WORKFLOW: the registry listing
 * carries the version in TWO places — the top-level `version` (the server
 * release) and `packages[].version` (the exact npm version clients resolve). The
 * upstream docs' suggested one-liner stamps only the first. A half-stamped
 * manifest still publishes: the listing then advertises the new release while
 * pinning clients to the old tarball, which is a silent version lie and exactly
 * the failure this file exists to prevent. Both fields move together or neither
 * does, and `registry-listing-invariant.test.ts` executes THIS script to prove
 * it — a guard that only grepped the workflow YAML for a `jq` expression would
 * pass on a `jq` expression that was wrong.
 *
 * Usage: node scripts/stamp-server-json.mjs <version> [path-to-server.json]
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The registry rejects version RANGES on `packages[].version` (`^1.2.3`, `1.x`,
 * `latest`, …) because a range makes the pin meaningless. Refuse anything that
 * is not a concrete dotted version here rather than at publish time, so a bad
 * tag fails on the line that produced it.
 */
const CONCRETE_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

export function stampServerJson(version, filePath) {
  if (typeof version !== "string" || !CONCRETE_VERSION.test(version)) {
    throw new Error(
      `refusing to stamp a non-concrete version: ${JSON.stringify(version)} ` +
        `(expected e.g. "0.30.0"; ranges and dist-tags are rejected by the registry)`,
    );
  }

  const manifest = JSON.parse(readFileSync(filePath, "utf8"));

  manifest.version = version;
  // Every package entry, not just [0] — a future pypi/oci sibling must not be
  // left behind at a stale version by an index that silently only covered npm.
  for (const pkg of manifest.packages ?? []) {
    pkg.version = version;
  }

  writeFileSync(filePath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifest;
}

// Run only when invoked directly, so the test can import the function.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const [version, pathArg] = process.argv.slice(2);
  const filePath = pathArg ? resolve(pathArg) : join(REPO_ROOT, "server.json");
  const manifest = stampServerJson(version, filePath);
  const pkgVersions = (manifest.packages ?? []).map((p) => p.version).join(", ");
  console.log(`server.json stamped: version=${manifest.version} packages=[${pkgVersions}]`);
}
