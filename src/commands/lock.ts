/**
 * `mcpm lock` command handler.
 *
 * Reads mcpm.yaml, resolves version ranges against the registry,
 * runs trust assessment per server, and writes mcpm-lock.yaml.
 *
 * URL-based servers are pinned directly (no version resolution).
 * Per-server errors are collected and reported; one failure does not
 * block resolution of other servers.
 *
 * Exports:
 * - handleLock()           — injectable handler for testing
 * - registerLockCommand()  — Commander registration
 */

import type { ClientId } from "../config/paths.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type {
  StackFile,
  StackServer,
  LockFile,
  LockedServer,
  TrustSnapshot,
  NpmIntegritySnapshot,
  NpmProvenanceSnapshot,
} from "../stack/schema.js";
import {
  parseStackFile,
  serializeYaml,
  isRegistryServer,
  isUrlServer,
  isLockedRegistryServer,
} from "../stack/schema.js";
import { compareProvenance } from "../registry/npm-provenance.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import { resolveVersion, resolveWithSingleVersion } from "../stack/resolve.js";
import { valid as semverValid } from "semver";
import { assessReleaseAge, DEFAULT_MIN_RELEASE_AGE_HOURS } from "../scanner/cooldown.js";
import { extractRegistryMeta } from "../utils/format-trust.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LockOptions {
  stackFile?: string;
}

export interface LockDeps {
  getServerVersions: (name: string) => Promise<{ version: string }[]>;
  getServer: (name: string, version?: string) => Promise<ServerEntry>;
  scanTier1: (server: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  /** Epoch-ms clock for release-age assessment; defaults to Date.now at the CLI boundary. */
  now?: () => number;
  writeLockFile: (path: string, content: string) => Promise<void>;
  output: (text: string) => void;
  /**
   * H11 slice 1: fetch npm's published dist.integrity for an exact package
   * coordinate. FAIL-OPEN: returns undefined on any error. When undefined the
   * snapshot is omitted and lock never blocks.
   */
  fetchNpmIntegrity: (
    identifier: string,
    npmVersion: string
  ) => Promise<NpmIntegritySnapshot | undefined>;
  /**
   * F8 slice 1: fetch npm's parse-only provenance record for an exact npm
   * coordinate. Optional — capture is skipped when absent. FAIL-OPEN (undefined).
   */
  fetchNpmProvenance?: (
    identifier: string,
    npmVersion: string
  ) => Promise<NpmProvenanceSnapshot | undefined>;
  /**
   * F8 slice 1: read the PREVIOUS lock (before overwrite) so provenance-identity
   * drift can be reported. Optional — drift check is skipped when absent.
   */
  readExistingLock?: (lockPath: string) => Promise<LockFile | null>;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

interface LockResult {
  readonly name: string;
  readonly locked: LockedServer;
}

interface LockError {
  readonly name: string;
  readonly error: string;
}

/**
 * Core handler for `mcpm lock`.
 *
 * Resolves all servers in mcpm.yaml, runs trust assessment, writes lock file.
 * Per-server errors are collected — one failure does not block others.
 */
export async function handleLock(
  options: LockOptions,
  deps: LockDeps
): Promise<void> {
  const stackPath = options.stackFile ?? "mcpm.yaml";
  const lockPath = stackPath.replace(/\.yaml$/, "-lock.yaml");
  const stackFile = await parseStackFile(stackPath);

  const scannerAvailable = await deps.checkScannerAvailable();
  const entries = Object.entries(stackFile.servers);

  // F4 lock/up symmetry: snapshots must be scored with the SAME cooldown
  // threshold `up` re-scores with, or blockOnScoreDrop trips spuriously.
  const minAgeHours =
    stackFile.policy?.minReleaseAgeHours ?? DEFAULT_MIN_RELEASE_AGE_HOURS;

  // F8: read the PREVIOUS lock up front — it feeds BOTH the drift baseline and
  // the carry-forward that keeps a known-good provenance snapshot sticky across a
  // transient re-read failure of the same immutable coordinate.
  const prevLock = deps.readExistingLock
    ? await deps.readExistingLock(lockPath).catch(() => null)
    : null;
  const prevProvenance = buildPrevProvenanceMap(prevLock);

  // Resolve all servers in parallel
  const settlements = await Promise.all(
    entries.map(([name, server]) =>
      resolveServer(name, server, scannerAvailable, minAgeHours, deps, prevProvenance.get(name))
        .then((locked): LockResult => ({ name, locked }))
        .catch((err): LockError => ({
          name,
          error: err instanceof Error ? err.message : String(err),
        }))
    )
  );

  const results: LockResult[] = [];
  const errors: LockError[] = [];

  for (const s of settlements) {
    if ("locked" in s) {
      results.push(s);
    } else {
      errors.push(s);
    }
  }

  // Build lock file from successful resolutions
  const lockedServers: Record<string, LockedServer> = {};
  for (const { name, locked } of results) {
    lockedServers[name] = locked;
  }

  const lockFile: LockFile = {
    lockfileVersion: 1,
    lockedAt: new Date().toISOString(),
    servers: lockedServers,
  };

  await deps.writeLockFile(lockPath, serializeYaml(lockFile));
  deps.output(`Locked ${results.length} servers to ${lockPath}`);

  reportProvenanceDrift(prevLock, results, deps.output);

  if (errors.length > 0) {
    deps.output("");
    for (const { name, error } of errors) {
      deps.output(`  Failed: ${name} — ${error}`);
    }
    deps.output(`\n${errors.length} server(s) failed to resolve.`);
  }
}

// ---------------------------------------------------------------------------
// F8 slice 1 — provenance-identity drift reporting (report-only)
// ---------------------------------------------------------------------------

function provenanceOf(server: LockedServer | undefined): NpmProvenanceSnapshot | undefined {
  return server && isLockedRegistryServer(server) ? server.provenance : undefined;
}

/** Human label for a provenance source — SANITIZED: the value is unverified
 * registry / committed-lockfile free text, so strip ANSI/OSC (and bound length)
 * before it reaches a terminal inside a security warning. */
function repoLabel(snap: NpmProvenanceSnapshot | undefined): string {
  const raw = snap?.identity?.sourceRepo ?? snap?.identity?.repositoryId ?? "unknown source";
  return sanitizeForTerminal(raw);
}

/** Index the previous lock's provenance snapshots by server name. */
function buildPrevProvenanceMap(prevLock: LockFile | null): Map<string, NpmProvenanceSnapshot> {
  const map = new Map<string, NpmProvenanceSnapshot>();
  if (!prevLock) return map;
  for (const [name, server] of Object.entries(prevLock.servers)) {
    const prov = provenanceOf(server);
    if (prov) map.set(name, prov);
  }
  return map;
}

/**
 * Compare each freshly-locked server's provenance to the previous lock's and
 * WARN on identity drift / a signed→unsigned drop. Report-only: never blocks,
 * never re-pins (consistent with the H4/H5/H11 tripwire posture). Copy is
 * careful — legitimate repo renames / org transfers happen, so it advises, and
 * never claims "verified".
 */
function reportProvenanceDrift(
  prevLock: LockFile | null,
  results: LockResult[],
  output: (text: string) => void
): void {
  if (!prevLock) return;
  for (const { name, locked } of results) {
    const prev = provenanceOf(prevLock.servers[name]);
    const next = provenanceOf(locked);
    switch (compareProvenance(prev, next)) {
      case "identity-drift":
        output(
          `  ⚠ provenance identity changed for ${name}: ${repoLabel(prev)} → ${repoLabel(next)} — ` +
            `expected if the project moved repos/CI; investigate if not.`
        );
        break;
      case "signed-to-unsigned":
        output(
          `  ⚠ provenance dropped for ${name}: was attested (${repoLabel(prev)}), now unsigned — ` +
            `a poisoned republish can look like this; verify before shipping.`
        );
        break;
    }
  }
}

// ---------------------------------------------------------------------------
// Per-server resolution
// ---------------------------------------------------------------------------

async function resolveServer(
  name: string,
  server: StackServer,
  scannerAvailable: boolean,
  minAgeHours: number,
  deps: LockDeps,
  prevProvenance?: NpmProvenanceSnapshot
): Promise<LockedServer> {
  // URL-based servers: pin directly, no version resolution or trust
  if (isUrlServer(server)) {
    return { url: server.url };
  }

  if (!isRegistryServer(server)) {
    throw new Error(`Invalid server entry for "${name}"`);
  }

  // Step 1: Resolve version
  let resolvedVersion: string;
  try {
    const versions = await deps.getServerVersions(name);
    const versionStrings = versions.map((v) => v.version);
    const result = resolveVersion(name, server.version, versionStrings);
    resolvedVersion = result.resolved;
  } catch {
    // Fallback: try with just the latest version
    const entry = await deps.getServer(name);
    const result = resolveWithSingleVersion(
      name,
      server.version,
      entry.server.version
    );
    resolvedVersion = result.resolved;
  }

  // Step 2: Fetch the resolved version's full entry
  const serverEntry = await deps.getServer(name, resolvedVersion);

  // Step 3: Trust assessment
  const tier1Findings = deps.scanTier1(serverEntry);
  let allFindings: Finding[] = [...tier1Findings];
  if (scannerAvailable) {
    const tier2Findings = await deps.scanTier2(name);
    allFindings = [...allFindings, ...tier2Findings];
  }

  // Release-age assessment (F4): the snapshot carries the same cooldown
  // penalty `up` will re-score with (see handleLock's minAgeHours threading).
  const registryMeta = extractRegistryMeta(serverEntry);
  const releaseAge = assessReleaseAge({
    publishedAt: registryMeta.publishedAt,
    now: (deps.now ?? Date.now)(),
    minAgeHours,
  });
  if (releaseAge.finding) {
    allFindings = [...allFindings, releaseAge.finding];
  }

  const trustInput: TrustScoreInput = {
    findings: allFindings,
    healthCheckPassed: null,
    hasExternalScanner: scannerAvailable,
    registryMeta,
  };
  const trustScore = deps.computeTrustScore(trustInput);

  // Step 4: Determine registry type and identifier
  const pkg =
    serverEntry.server.packages.find((p) => p.registryType === "npm") ??
    serverEntry.server.packages.find((p) => p.registryType === "pypi") ??
    serverEntry.server.packages.find((p) => p.registryType === "oci") ??
    serverEntry.server.packages[0];

  const snapshot: TrustSnapshot = {
    score: trustScore.score,
    maxPossible: trustScore.maxPossible,
    level: trustScore.level,
    assessedAt: new Date().toISOString(),
  };

  // Step 5: H11 slice 1 — capture npm artifact integrity snapshot.
  // Only for npm packages whose pkg.version is a concrete exact semver
  // (not "latest", a dist-tag, or a range). Using pkg.version (the npm
  // coordinate) — NOT the resolved MCP server version — because the npm
  // per-version endpoint uses the npm package version, not the registry's
  // MCP server version field. Fail-open: if fetchNpmIntegrity returns
  // undefined, omit the snapshot and proceed; lock never blocks on this.
  const isConcreteNpm =
    pkg?.registryType === "npm" && semverValid(pkg.version ?? null) !== null;

  let npmIntegritySnap: NpmIntegritySnapshot | undefined;
  if (isConcreteNpm) {
    npmIntegritySnap = await deps.fetchNpmIntegrity(
      pkg.identifier,
      pkg.version as string
    );
  }

  // F8 slice 1: capture the parse-only provenance snapshot behind the SAME gate.
  // Fail-open: undefined omits the block; lock never blocks on this.
  let provenanceSnap: NpmProvenanceSnapshot | undefined;
  if (isConcreteNpm && deps.fetchNpmProvenance) {
    provenanceSnap = await deps.fetchNpmProvenance(
      pkg.identifier,
      pkg.version as string
    );
  }

  // F8: keep a known-good baseline STICKY across a transient failure or an
  // unparseable re-read of the SAME immutable coordinate. A published version's
  // provenance does not change, so one bad run must not erase the recorded
  // baseline and silently disarm the drift tripwire. A DEFINITIVE change — a
  // 404→unsigned, or a different attested identity — is NOT caught here (it is
  // neither undefined nor unsupported), so it still overwrites and warns.
  if (
    isConcreteNpm &&
    prevProvenance?.status === "attested" &&
    prevProvenance.npmVersion === pkg?.version &&
    (provenanceSnap === undefined || provenanceSnap.status === "unsupported")
  ) {
    provenanceSnap = prevProvenance;
  }

  return {
    version: resolvedVersion,
    registryType: pkg?.registryType ?? "unknown",
    identifier: pkg?.identifier ?? name,
    trust: snapshot,
    ...(npmIntegritySnap ? { npmIntegrity: npmIntegritySnap } : {}),
    ...(provenanceSnap ? { provenance: provenanceSnap } : {}),
  };
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import { writeFile } from "fs/promises";
import { RegistryClient } from "../registry/client.js";
import { scanTier1 as _scanTier1 } from "../scanner/tier1.js";
import {
  checkScannerAvailable as _checkScannerAvailable,
  scanTier2 as _scanTier2,
} from "../scanner/tier2.js";
import { computeTrustScore as _computeTrustScore } from "../scanner/trust-score.js";
import { fetchNpmIntegrity as _fetchNpmIntegrity } from "../registry/npm-integrity.js";
import { fetchNpmProvenance as _fetchNpmProvenance } from "../registry/npm-provenance.js";
import { parseLockFile } from "../stack/schema.js";
import { stdoutOutput } from "../utils/output.js";

export function registerLockCommand(program: Command): void {
  program
    .command("lock")
    .description(
      "Resolve versions and create mcpm-lock.yaml with trust snapshots"
    )
    .option("-f, --file <path>", "path to mcpm.yaml", "mcpm.yaml")
    .action(async (opts: { file?: string }) => {
      const chalk = (await import("chalk")).default;
      const client = new RegistryClient();

      try {
        await handleLock(
          { stackFile: opts.file },
          {
            getServerVersions: (name) =>
              client.getServerVersions(name),
            getServer: (name, version?) => client.getServer(name, version),
            scanTier1: _scanTier1,
            checkScannerAvailable: _checkScannerAvailable,
            scanTier2: (name) => _scanTier2(name),
            computeTrustScore: _computeTrustScore,
            now: () => Date.now(),
            writeLockFile: (path, content) =>
              writeFile(path, content, { encoding: "utf-8", mode: 0o600 }),
            fetchNpmIntegrity: _fetchNpmIntegrity,
            fetchNpmProvenance: _fetchNpmProvenance,
            readExistingLock: (p) => parseLockFile(p),
            output: stdoutOutput,
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
