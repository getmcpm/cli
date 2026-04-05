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
} from "../stack/schema.js";
import {
  parseStackFile,
  serializeYaml,
  isRegistryServer,
  isUrlServer,
} from "../stack/schema.js";
import { resolveVersion, resolveWithSingleVersion } from "../stack/resolve.js";
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
  writeLockFile: (path: string, content: string) => Promise<void>;
  output: (text: string) => void;
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

  // Resolve all servers in parallel
  const settlements = await Promise.all(
    entries.map(([name, server]) =>
      resolveServer(name, server, scannerAvailable, deps)
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

  if (errors.length > 0) {
    deps.output("");
    for (const { name, error } of errors) {
      deps.output(`  Failed: ${name} — ${error}`);
    }
    deps.output(`\n${errors.length} server(s) failed to resolve.`);
  }
}

// ---------------------------------------------------------------------------
// Per-server resolution
// ---------------------------------------------------------------------------

async function resolveServer(
  name: string,
  server: StackServer,
  scannerAvailable: boolean,
  deps: LockDeps
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

  const trustInput: TrustScoreInput = {
    findings: allFindings,
    healthCheckPassed: null,
    hasExternalScanner: scannerAvailable,
    registryMeta: extractRegistryMeta(serverEntry),
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

  return {
    version: resolvedVersion,
    registryType: pkg?.registryType ?? "unknown",
    identifier: pkg?.identifier ?? name,
    trust: snapshot,
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
            writeLockFile: (path, content) =>
              writeFile(path, content, { encoding: "utf-8", mode: 0o600 }),
            output: stdoutOutput,
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
