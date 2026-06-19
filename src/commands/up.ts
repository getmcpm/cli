/**
 * `mcpm up` command handler.
 *
 * Reads mcpm.yaml + mcpm-lock.yaml, verifies trust policy, and batch-installs
 * servers across all detected clients. This is a NEW batch pipeline that reuses
 * lower-level primitives (resolveInstallEntry, adapter.addServer, computeTrustScore)
 * rather than extracting from handleInstall().
 *
 * Key behaviors:
 * - Auto-runs `mcpm lock` if no lock file exists
 * - Parallel trust re-assessment, sequential config writes
 * - Single .bak snapshot before batch starts
 * - Per-server error isolation (failures collected, others continue)
 * - URL servers installed on Cursor only, warn for other clients
 * - Env var resolution: process.env → .env → interactive prompt
 *
 * Exports:
 * - handleUp()           — injectable handler for testing
 * - registerUpCommand()  — Commander registration
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type {
  StackFile,
  LockFile,
  LockedServer,
  Policy,
  NpmIntegritySnapshot,
} from "../stack/schema.js";
import {
  parseStackFile,
  parseLockFile,
  isRegistryServer,
  isUrlServer,
  isLockedRegistryServer,
} from "../stack/schema.js";
import { checkTrustPolicy } from "../stack/policy.js";
import { parseEnvFile } from "../stack/env.js";
import { resolveInstallEntry, parseSecretsMode, validateRemoteUrl } from "./install.js";
import { assessReleaseAge, DEFAULT_MIN_RELEASE_AGE_HOURS } from "../scanner/cooldown.js";
import { extractRegistryMeta } from "../utils/format-trust.js";
import { applyKeychainSecrets, type SecretsMode, setSecrets as _setSecrets } from "../store/keychain.js";
import { isNewUnguarded } from "../guard/unguarded.js";
import { compareIntegrity } from "../registry/npm-integrity.js";
import type { PinsFile } from "../guard/pins.js";
import { readPins as _readPins } from "../guard/pins.js";
import {
  detectNameCollisions,
  buildInventoryFromPins,
  serversWithoutBaseline,
} from "../guard/shadow.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UpOptions {
  stackFile?: string;
  profile?: string;
  dryRun?: boolean;
  ci?: boolean;
  strict?: boolean;
  yes?: boolean;
  secrets?: SecretsMode;
  /**
   * Whether declared env vars may be auto-read from `process.env`.
   * DEFAULT (undefined/true) preserves CLI behavior. The MCP surface passes
   * `false` so an attacker-controlled stack file can't harvest ambient secrets.
   */
  allowProcessEnv?: boolean;
  /**
   * Whether URL servers may be installed.
   * DEFAULT (undefined/true) preserves CLI behavior. The MCP surface passes
   * `false` so URL servers are recorded as blocked instead of installed.
   */
  allowUrlServers?: boolean;
  /**
   * Whether declared env vars may be auto-read from the working-directory `.env`
   * file. The `.env` is an ambient secret source just like `process.env`.
   * DEFAULT (undefined/true) preserves CLI behavior. The MCP surface passes
   * `false` so an attacker-controlled stack file can't siphon the host's `.env`
   * into an installed server config.
   */
  allowEnvFile?: boolean;
  /**
   * Hard, non-overridable trust-score floor (absolute, 0–100). When set, any
   * server scoring below it is blocked regardless of the stack file's `policy`
   * (which the caller controls). DEFAULT (undefined) = no floor = CLI behavior.
   * The MCP surface passes the same hard floor the single-install tool enforces
   * (issue #24), so a prompt-injected agent can't use the batch `up` path to
   * install a low-trust server that `mcpm_install` would reject.
   */
  minTrustFloor?: number;
  /**
   * H9 (fail-closed): per-invocation consent (`--allow-unguarded`) to install
   * URL/HTTP-transport servers that run UNGUARDED (no relay wraps a non-stdio
   * transport). When neither this nor `policy.allowUrlServers` is set, such a
   * server is DENIED (recorded `blocked`). DISTINCT from `allowUrlServers`,
   * which is the MCP-surface kill-switch: `allowUrlServers === false` ALWAYS
   * wins — an untrusted caller can never set `allowUnguarded`.
   */
  allowUnguarded?: boolean;
  /**
   * F2 (opt-in): run the cross-server tool-name-collision (shadow) check after
   * install. Also armable via `policy.checkShadowing` in the stack file. WARN-tier
   * — findings are advisory on an interactive run; under `--ci` any collision
   * exits non-zero. Best-effort over already-guarded servers (see `runShadowPass`).
   */
  checkShadowing?: boolean;
  /**
   * F3 (fail-closed): verify every locked npm server's published integrity BEFORE
   * installing, and BLOCK the whole `up` (install nothing) if any drifted, could
   * not be verified, mismatched its baseline format, or is suspiciously missing one.
   * Also armable via `policy.frozen`. The CI supply-chain freeze gate (`npm ci`-like).
   */
  frozen?: boolean;
}

export interface UpDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getPath: (clientId: ClientId) => string;
  getServer: (name: string, version?: string) => Promise<ServerEntry>;
  scanTier1: (server: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  /** Epoch-ms clock for release-age assessment; defaults to Date.now at the CLI boundary. */
  now?: () => number;
  runLock: (stackFile: string) => Promise<void>;
  confirm: (message: string) => Promise<boolean>;
  promptEnvVar: (name: string, isSecret: boolean) => Promise<string>;
  output: (text: string) => void;
  /** Optional; required only when options.secrets === "keychain". */
  setSecrets?: (server: string, values: Record<string, string>) => Promise<void>;
  /**
   * Optional structured per-server result sink. When provided, handleUp invokes
   * it once per processed server (and per strict-mode removal) with the typed
   * status — so callers like the MCP surface can categorize results
   * deterministically instead of scraping emoji from `output` lines (which
   * cannot distinguish "blocked" from "failed"). The CLI does not supply this,
   * so its behavior is unchanged.
   */
  recordResult?: (result: { name: string; status: UpServerStatus }) => void;
  /**
   * H9: read the persistent set of server names previously consented to run
   * unguarded. Injectable for tests; defaults to the real store at the CLI
   * boundary. When omitted, no server is treated as previously-consented.
   */
  readUnguardedConsent?: () => Promise<string[]>;
  /**
   * H9: persist (union into the store) the names newly consented this run.
   * Injectable for tests; defaults to the real store. Called once after the
   * per-server loop with the newly-consented set (additions only).
   */
  recordUnguardedConsent?: (names: readonly string[]) => Promise<void>;
  /**
   * H11 slice 1: fetch npm's published dist.integrity for an exact package
   * coordinate. FAIL-OPEN: returns undefined on any error; the integrity pass
   * is read-only and never alters install results.
   */
  fetchNpmIntegrity: (
    identifier: string,
    npmVersion: string
  ) => Promise<NpmIntegritySnapshot | undefined>;
  /**
   * F2: read ~/.mcpm/pins.json for the cross-server shadow check. Injectable for
   * tests; defaults to the real store at the CLI boundary. When omitted, the
   * shadow check is skipped (fail-soft) even if armed. The check is read-only and
   * never alters install results.
   */
  readPins?: () => Promise<PinsFile>;
}

/** Terminal per-server status reported via UpDeps.recordResult. */
export type UpServerStatus =
  | "installed"
  | "skipped"
  | "removed"
  | "blocked"
  | "failed";

// ---------------------------------------------------------------------------
// Per-server result types
// ---------------------------------------------------------------------------

interface ServerSuccess {
  readonly name: string;
  readonly status: "installed" | "skipped" | "removed";
  readonly message: string;
  /** Number of secrets persisted to the keychain for this server (keychain mode). */
  readonly storedSecrets?: number;
}

interface ServerFailure {
  readonly name: string;
  readonly status: "failed" | "blocked";
  readonly message: string;
}

type ServerResult = ServerSuccess | ServerFailure;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleUp(
  options: UpOptions,
  deps: UpDeps
): Promise<void> {
  // Keychain mode persists secrets locally — never do that on a CI runner.
  if (options.secrets === "keychain" && options.ci) {
    throw new Error(
      "--secrets keychain cannot be combined with --ci (it would persist secrets to the CI runner's keychain). Use --secrets plaintext in CI."
    );
  }

  const stackPath = options.stackFile ?? "mcpm.yaml";
  const lockPath = stackPath.replace(/\.yaml$/, "-lock.yaml");

  // Step 1: Read stack file
  const stackFile = await parseStackFile(stackPath);

  // Step 2: Read or create lock file
  let lockFile = await parseLockFile(lockPath);
  if (lockFile === null) {
    deps.output("No lock file found. Running mcpm lock first...");
    await deps.runLock(stackPath);
    lockFile = await parseLockFile(lockPath);
    if (lockFile === null) {
      throw new Error("Failed to create lock file.");
    }
  }

  // Step 3: Detect clients
  const clients = await deps.detectClients();
  if (clients.length === 0) {
    throw new Error("No supported AI clients found.");
  }

  // Step 4: Filter servers by profile
  const serverEntries = filterByProfile(stackFile, options.profile);
  if (serverEntries.length === 0) {
    deps.output("No servers match the selected profile.");
    return;
  }

  // Step 4.5: F3 — fail-closed integrity freeze. Runs BEFORE any backup or config
  // write (and regardless of --dry-run, since it is a verification gate) so a block
  // installs NOTHING. Throws on drift / could-not-verify / format-mismatch / a
  // suspicious missing baseline; the Commander catch turns the throw into exit 1.
  if (options.frozen === true || stackFile.policy?.frozen === true) {
    await runFrozenPass(lockFile, deps);
  }

  // Step 5: Load .env file for env var resolution.
  // MCP surface lockdown (fix H1): the working-directory `.env` is an ambient
  // secret source just like process.env. When allowEnvFile === false (set by the
  // MCP surface) we skip reading it entirely, so an attacker-controlled stack
  // file can't harvest the host's `.env` into an installed server config. The CLI
  // default (undefined/true) reads `.env` as before.
  const envFileVars =
    options.allowEnvFile === false
      ? ({ vars: {}, warnings: [] } as Awaited<ReturnType<typeof parseEnvFile>>)
      : await parseEnvFile(".env");

  // Step 6: Re-assess trust in parallel
  const scannerAvailable = await deps.checkScannerAvailable();

  // Dry-run header
  if (options.dryRun) {
    deps.output("Dry run — no changes will be made.\n");
  }

  // Step 7: Take single .bak snapshot before batch writes
  if (!options.dryRun) {
    await backupConfigs(clients, deps);
  }

  // Step 8: Process each server
  const results: ServerResult[] = [];

  // H9: pre-read the persistent unguarded-consent set so a previously-consented
  // url server is permitted without re-supplying `--allow-unguarded`, and so we
  // can warn ONCE (only when this run ADDS a server — anti-rubber-stamp).
  const previousConsented = deps.readUnguardedConsent ? await deps.readUnguardedConsent() : [];
  const consentedUnguarded = new Set(previousConsented);

  for (const [name, server] of serverEntries) {
    const locked = lockFile.servers[name];

    try {
      const result = await processServer({
        name,
        server,
        locked,
        policy: stackFile.policy,
        clients,
        scannerAvailable,
        envFileVars: envFileVars.vars,
        consentedUnguarded,
        options,
        deps,
      });
      results.push(result);
      deps.recordResult?.({ name, status: result.status });
      deps.output(`  ${statusIcon(result.status)} ${name}: ${result.message}`);
    } catch (err) {
      const failure: ServerFailure = {
        name,
        status: "failed",
        message: err instanceof Error ? err.message : String(err),
      };
      results.push(failure);
      deps.recordResult?.({ name, status: "failed" });
      deps.output(`  ${statusIcon("failed")} ${name}: ${failure.message}`);
    }
  }

  // Step 9: Strict mode — remove servers not in mcpm.yaml
  if (options.strict && !options.dryRun) {
    await handleStrictRemoval(stackFile, clients, options, deps, results);
  }

  // H9: the set of url servers that installed UNGUARDED this run (consent was
  // given). Warn ONCE — full warning only when this run ADDS a server to the
  // consented set (additions re-warn; unchanged/removed stay quiet). Then
  // persist the newly-consented names so the next `up` stays quiet.
  const urlServerNames = new Set(
    serverEntries.filter(([, s]) => isUrlServer(s)).map(([n]) => n)
  );
  const installedUnguarded = results
    .filter((r) => r.status === "installed" && urlServerNames.has(r.name))
    .map((r) => r.name)
    .sort();
  if (installedUnguarded.length > 0 && !options.dryRun) {
    // Use the canonical additions-only check so `up` and `guard enable` (cli.ts)
    // share ONE implementation of the anti-rubber-stamp warn-once semantics.
    const newlyConsented = installedUnguarded.filter((n) => !consentedUnguarded.has(n));
    if (isNewUnguarded(installedUnguarded, previousConsented)) {
      // List only the NEWLY-consented delta as the servers being rubber-stamped
      // (re-listing already-consented A,B alongside the new C dilutes the "this
      // one is the new risk" signal). Append a quiet count of the rest.
      const alreadyCount = installedUnguarded.length - newlyConsented.length;
      const alreadyNote =
        alreadyCount > 0 ? ` (+${alreadyCount} previously consented)` : "";
      deps.output(
        "\n⚠ UNGUARDED: the following URL/HTTP-transport server(s) now run WITHOUT runtime " +
          `inspection (no relay wraps a non-stdio transport): ${newlyConsented.join(", ")}${alreadyNote}. ` +
          "This grants consent — it does NOT add protection. The only true fix is a streamable-HTTP " +
          "relay (not yet implemented). Future `up` runs stay quiet unless a NEW unguarded server appears."
      );
      if (deps.recordUnguardedConsent) {
        await deps.recordUnguardedConsent(newlyConsented).catch(() => undefined);
      }
    } else {
      deps.output(
        `\n${installedUnguarded.length} server(s) running unguarded (previously consented): ` +
          `${installedUnguarded.join(", ")}`
      );
    }
  }

  // Step 9b: H11 slice 1 — npm integrity drift pass (WARN-only, read-only).
  // Runs regardless of dry-run (read-only network check; `up` already does
  // network). Does NOT alter install results or summary counts. SKIPPED under
  // --frozen: the pre-install freeze (Step 4.5) already fetched + verified the
  // same records and would have blocked on any drift, so re-running it here is
  // pure redundant npm traffic with nothing left to warn about.
  if (options.frozen !== true && stackFile.policy?.frozen !== true) {
    await runIntegrityPass(lockFile, deps);
  }

  // Step 9c: F2 — cross-server tool-name-collision (shadow) check. Opt-in,
  // warn-tier, read-only. Best-effort over already-guarded servers. Under `--ci`
  // a collision exits non-zero (see the throw below); interactively it is advisory.
  let shadowCollisions = 0;
  if (options.checkShadowing === true || stackFile.policy?.checkShadowing === true) {
    shadowCollisions = await runShadowPass(
      serverEntries.map(([name]) => name),
      deps
    );
  }

  // Step 10: Summary
  const installed = results.filter((r) => r.status === "installed").length;
  const blocked = results.filter((r) => r.status === "blocked").length;
  const failed = results.filter((r) => r.status === "failed").length;
  const skipped = results.filter((r) => r.status === "skipped").length;
  const removed = results.filter((r) => r.status === "removed").length;
  const unguarded = installedUnguarded.length;

  deps.output(
    `\n${installed} installed, ${skipped} skipped, ${blocked} blocked, ${failed} failed` +
      (removed > 0 ? `, ${removed} removed` : "") +
      (unguarded > 0 ? `, ${unguarded} unguarded` : "")
  );

  const totalSecretsStored = results.reduce(
    (sum, r) => sum + ((r as ServerSuccess).storedSecrets ?? 0),
    0
  );
  if (options.secrets === "keychain" && totalSecretsStored > 0 && !options.dryRun) {
    deps.output(
      "Secrets stored encrypted at rest in ~/.mcpm. With an OS keychain this protects " +
        "against other-user/offline access (not same-user processes); without one a " +
        "machine-derived key is used that guards casual local inspection only, NOT file " +
        "exfiltration — run `mcpm secrets migrate` once a keychain is available. " +
        "Run `mcpm guard enable` (then restart your IDE) so they resolve at launch."
    );
  }

  if (blocked > 0 || failed > 0) {
    // Signal failure via thrown error (caught by Commander registration)
    throw new Error(`${blocked + failed} server(s) could not be installed.`);
  }

  // F2: under --ci, a tool-name collision is a hard failure (the CI gate the
  // opt-in check exists to provide). Interactive runs only warn (advisory).
  if (shadowCollisions > 0 && options.ci) {
    throw new Error(
      `${shadowCollisions} cross-server tool-name collision(s) detected (--ci). ` +
        "Resolve the shadowing (rename/remove a duplicate tool) or drop --check-shadowing."
    );
  }
}

// ---------------------------------------------------------------------------
// Profile filtering
// ---------------------------------------------------------------------------

function filterByProfile(
  stackFile: StackFile,
  profile?: string
): [string, StackFile["servers"][string]][] {
  return Object.entries(stackFile.servers).filter(([, server]) => {
    const profiles = isRegistryServer(server) || isUrlServer(server)
      ? server.profiles
      : undefined;

    if (!profiles) return true; // No profiles = always included
    if (!profile) return true;  // No --profile flag = include all
    return profiles.includes(profile);
  });
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

async function backupConfigs(
  clients: readonly ClientId[],
  deps: Pick<UpDeps, "getAdapter" | "getPath">
): Promise<void> {
  const { readFile, writeFile } = await import("fs/promises");
  for (const clientId of clients) {
    try {
      const adapter = deps.getAdapter(clientId);
      const configPath = deps.getPath(clientId);
      const content = await readFile(configPath, "utf-8");
      await writeFile(`${configPath}.bak`, content, {
        encoding: "utf-8",
        mode: 0o600,
      });
    } catch {
      // Config may not exist yet — skip backup
    }
  }
}

// ---------------------------------------------------------------------------
// Per-server processing
// ---------------------------------------------------------------------------

interface ProcessInput {
  name: string;
  server: StackFile["servers"][string];
  locked: LockedServer | undefined;
  policy: Policy | undefined;
  clients: ClientId[];
  scannerAvailable: boolean;
  envFileVars: Readonly<Record<string, string>>;
  /** H9: server names already consented to run unguarded (persistent store). */
  consentedUnguarded: ReadonlySet<string>;
  options: UpOptions;
  deps: UpDeps;
}

async function processServer(input: ProcessInput): Promise<ServerResult> {
  const { name, server, locked, policy, clients, scannerAvailable, envFileVars, options, deps } = input;

  // URL servers: install on Cursor only
  if (isUrlServer(server)) {
    return processUrlServer(name, server.url, clients, policy, input.consentedUnguarded, options, deps);
  }

  if (!locked || !isLockedRegistryServer(locked)) {
    return { name, status: "failed", message: "Not found in lock file. Run mcpm lock." };
  }

  // Trust re-assessment
  const serverEntry = await deps.getServer(name, locked.version);
  const tier1 = deps.scanTier1(serverEntry);
  let findings: Finding[] = [...tier1];
  if (scannerAvailable) {
    const tier2 = await deps.scanTier2(name);
    findings = [...findings, ...tier2];
  }

  // Release-age assessment (F4): one assessment per server, with the policy
  // threshold when set, so the soft-penalty finding and the policy gate below
  // can never disagree.
  const registryMeta = extractRegistryMeta(serverEntry);
  const releaseAge = assessReleaseAge({
    publishedAt: registryMeta.publishedAt,
    now: (deps.now ?? Date.now)(),
    minAgeHours: policy?.minReleaseAgeHours ?? DEFAULT_MIN_RELEASE_AGE_HOURS,
  });
  if (releaseAge.finding) {
    findings = [...findings, releaseAge.finding];
  }

  const trustInput: TrustScoreInput = {
    findings,
    healthCheckPassed: null,
    hasExternalScanner: scannerAvailable,
    registryMeta,
  };
  const trustScore = deps.computeTrustScore(trustInput);

  // M2: enforce the hard trust floor BEFORE the (caller-controlled) stack policy.
  // The MCP surface sets this so the batch `up` path honors the same floor the
  // single-install MCP tool enforces (issue #24) — a stack file with no policy (or
  // `minTrustScore: 0`) can't lower it. The CLI leaves it undefined (no floor).
  // Note: this is an ABSOLUTE score floor (matching the sibling handleInstall #24),
  // whereas checkTrustPolicy below compares normalized percentages — intentional
  // and consistent; revisit only if the hard floor is ever made percentage-based.
  if (
    options.minTrustFloor !== undefined &&
    trustScore.score < options.minTrustFloor
  ) {
    return {
      name,
      status: "blocked",
      message: `trust score ${trustScore.score}/${trustScore.maxPossible} is below the required floor of ${options.minTrustFloor}`,
    };
  }

  // Policy check
  const policyResult = checkTrustPolicy({
    serverName: name,
    currentScore: trustScore.score,
    currentMaxPossible: trustScore.maxPossible,
    lockedSnapshot: locked.trust,
    policy,
    releaseAge: {
      ageHours: releaseAge.ageHours,
      status: releaseAge.status,
      blocksArmedGate: releaseAge.blocksArmedGate,
    },
    hasInstallScriptFindings: findings.some((f) => f.type === "install-script"),
  });

  if (!policyResult.pass) {
    return { name, status: "blocked", message: policyResult.reason };
  }

  if (options.dryRun) {
    return {
      name,
      status: "skipped",
      message: `would install v${locked.version} (trust: ${trustScore.score}/${trustScore.maxPossible})`,
    };
  }

  // Resolve env vars (keychain mode swaps secrets for placeholders + a count)
  const { env: envVars, storedCount } = await resolveEnvVars(name, server, envFileVars, options, deps);

  // Install to each client. Track successes so we never report "installed"
  // when every client write failed (e.g. all configs read-only or missing).
  const installedClients: ClientId[] = [];
  const clientErrors: string[] = [];
  for (const clientId of clients) {
    try {
      const entry = resolveInstallEntry(serverEntry, clientId);
      const entryWithEnv: McpServerEntry = {
        ...entry,
        ...(Object.keys(envVars).length > 0 ? { env: { ...entry.env, ...envVars } } : {}),
      };
      const adapter = deps.getAdapter(clientId);
      const configPath = deps.getPath(clientId);
      await adapter.addServer(configPath, name, entryWithEnv, { force: true });
      installedClients.push(clientId);
    } catch (err) {
      clientErrors.push(`${clientId}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // No client accepted the write → this is a failure, not a silent success.
  if (installedClients.length === 0) {
    return {
      name,
      status: "failed",
      message: `could not write to any client (${clientErrors.join("; ")})`,
    };
  }

  // Partial success: surface the clients that failed as a warning suffix.
  const partialNote =
    clientErrors.length > 0
      ? ` (warning: failed on ${clientErrors.join("; ")})`
      : "";

  return {
    name,
    status: "installed",
    message: `v${locked.version} (trust: ${trustScore.score}/${trustScore.maxPossible})${partialNote}`,
    storedSecrets: storedCount,
  };
}

// ---------------------------------------------------------------------------
// H11 slice 1 — npm integrity drift pass
// ---------------------------------------------------------------------------

/**
 * Read-only post-loop integrity pass. Fetches fresh npm dist.integrity in
 * parallel for all locked npm servers that have a baseline snapshot, compares
 * against the locked value, and emits batch WARN output. Never throws; never
 * alters install results or summary counts.
 *
 * HONESTY BOUNDARY: all output must say "npm's published record … changed" and
 * include the clause "mcpm checks the registry's published record, not the code
 * your agent runs." NEVER write "serving different bytes" or claim protection.
 */
/** A locked registry server entry (npm or other), as stored in mcpm-lock.yaml. */
type LockedRegistryEntry = {
  version: string;
  registryType: string;
  identifier: string;
  trust: unknown;
  npmIntegrity?: { npmVersion: string; integrity: string };
};

/** Server coordinate carried through integrity classification. */
type IntegrityCoord = { name: string; identifier: string; npmVersion: string };

interface IntegrityClassification {
  /** locked dist.integrity differs from npm's current published record. */
  readonly drift: (IntegrityCoord & { oldIntegrity: string; newIntegrity: string })[];
  /** npm's record uses no algorithm in common with the lock — cannot compare. */
  readonly formatOnly: IntegrityCoord[];
  /** fetch returned nothing (offline / 404 / no comparable dist.integrity). */
  readonly couldNotVerify: IntegrityCoord[];
  /** npm servers whose lock entry has no npmIntegrity baseline at all. */
  readonly absentBaseline: string[];
  /** servers --frozen cannot integrity-check at all: non-npm registry servers
   *  (pypi/oci — no baseline mechanism yet) plus url servers (no package coordinate). */
  readonly unenforceable: string[];
  /** count of npm servers that DID have a baseline (to tell lock-wide vs mixed gaps). */
  readonly checkedNpmCount: number;
}

/**
 * Shared integrity classifier (H11). Fetches npm's current published dist.integrity
 * for every locked npm server with a baseline (one batched Promise.all) and sorts
 * every locked registry server into buckets. Pure of output — both the WARN pass
 * (runIntegrityPass) and the fail-closed BLOCK pass (runFrozenPass) consume it, so
 * the fetch/compare logic lives in exactly one place.
 */
async function classifyIntegrity(
  lockFile: LockFile,
  deps: Pick<UpDeps, "fetchNpmIntegrity">
): Promise<IntegrityClassification> {
  const registryEntries = Object.entries(lockFile.servers).filter(([, locked]) =>
    isLockedRegistryServer(locked)
  ) as [string, LockedRegistryEntry][];

  const npmEntries = registryEntries.filter(([, l]) => l.registryType === "npm");
  // Everything that is NOT an npm registry server can't be integrity-checked:
  // pypi/oci (no baseline mechanism yet) and url servers (no package coordinate).
  const npmNames = new Set(npmEntries.map(([name]) => name));
  const unenforceable = Object.keys(lockFile.servers).filter((name) => !npmNames.has(name));

  const checkable = npmEntries.filter(([, l]) => l.npmIntegrity !== undefined);
  const absentBaseline = npmEntries
    .filter(([, l]) => l.npmIntegrity === undefined)
    .map(([name]) => name);

  const fresh = await Promise.all(
    checkable.map(([, l]) => deps.fetchNpmIntegrity(l.identifier, l.npmIntegrity!.npmVersion))
  );

  const drift: IntegrityClassification["drift"] = [];
  const formatOnly: IntegrityCoord[] = [];
  const couldNotVerify: IntegrityCoord[] = [];

  for (let i = 0; i < checkable.length; i++) {
    const [name, locked] = checkable[i]!;
    const baseline = locked.npmIntegrity!;
    const snap = fresh[i];
    const coord: IntegrityCoord = { name, identifier: locked.identifier, npmVersion: baseline.npmVersion };

    if (snap === undefined) {
      couldNotVerify.push(coord);
      continue;
    }
    const cmp = compareIntegrity(baseline.integrity, snap.integrity);
    if (cmp === "equal") continue;
    if (cmp === "differ") {
      drift.push({ ...coord, oldIntegrity: baseline.integrity, newIntegrity: snap.integrity });
    } else {
      formatOnly.push(coord);
    }
  }

  return { drift, formatOnly, couldNotVerify, absentBaseline, unenforceable, checkedNpmCount: checkable.length };
}

async function runIntegrityPass(
  lockFile: LockFile,
  deps: Pick<UpDeps, "fetchNpmIntegrity" | "output">
): Promise<void> {
  const c = await classifyIntegrity(lockFile, deps);

  // Emit drift advisories (one per server).
  for (const d of c.drift) {
    const oldShort = d.oldIntegrity.slice(0, 16);
    const newShort = d.newIntegrity.slice(0, 16);
    deps.output(
      `\n⚠ INTEGRITY DRIFT: npm's published record for ${d.identifier}@${d.npmVersion} changed` +
        ` since you locked it (dist.integrity ${oldShort}… → ${newShort}…).` +
        ` A published version's integrity is meant to be immutable, so this can mean a` +
        ` supply-chain republish — but it can also be a legitimate republish or a different` +
        ` registry. mcpm checks the registry's published record, not the code your agent runs.` +
        ` This is a warning only — it does not block \`mcpm up\`; npx/uvx fetch and run the actual` +
        ` package independently when the server starts (possibly from a different mirror).` +
        ` Re-run \`mcpm lock\` if this change is expected.`
    );
  }

  // Emit format-only advisories (one per server).
  for (const f of c.formatOnly) {
    deps.output(
      `\n⚠ ${f.name}: npm changed the integrity format for ${f.identifier}@${f.npmVersion}, so` +
        ` mcpm cannot compare its published record against your locked baseline (mcpm checks the` +
        ` registry's published record, not the code your agent runs).` +
        ` Re-run \`mcpm lock\` to refresh the baseline.`
    );
  }

  // Emit batch could-not-verify line (one total, not one per server). Covers
  // both a genuine outage AND a 200 manifest lacking a comparable dist.integrity
  // — so it must NOT assert "unreachable" (a cause it cannot prove).
  if (c.couldNotVerify.length > 0) {
    deps.output(
      `\ncould not verify npm integrity for ${c.couldNotVerify.length} server(s) this run` +
        ` (no drift result is not proof of integrity).`
    );
  }

  // Emit batch absent-baseline line (one total, not one per server).
  if (c.absentBaseline.length > 0) {
    deps.output(
      `\nintegrity baseline missing for ${c.absentBaseline.length} npm server(s)` +
        ` — re-run \`mcpm lock\` with network access to enable drift detection.`
    );
  }
}

/**
 * F3 — `up --frozen` fail-closed integrity BLOCK pass. Runs PRE-install (before any
 * backup or config write) so a failure installs NOTHING — `npm ci` semantics. Reuses
 * the H11 classifier; under --frozen the WARN buckets become hard blocks.
 *
 * Three absent-baseline cases are kept DISTINCT so the gate isn't a day-one footgun:
 *   - lock-wide (no npm server has a baseline) = an un-upgraded / offline-locked lock,
 *     benign → a single refuse-to-run with `mcpm lock` instructions (NOT a poison verdict).
 *   - mixed gap (some servers have baselines, one npm server doesn't) = a real,
 *     suspicious gap → BLOCK that server.
 *   - non-npm (pypi/oci) = no baseline mechanism exists → a coverage notice, never a
 *     block (blocking would be theater that pushes users off --frozen).
 *
 * Honesty boundary: a block means npm's PUBLISHED RECORD diverged from (or can't be
 * matched against) your lock — NOT that mcpm caught the malicious bytes. npx/uvx fetch
 * the artifact independently at server launch, so --frozen is a deterministic CI
 * tripwire on the registry's published metadata, not code interception.
 */
async function runFrozenPass(
  lockFile: LockFile,
  deps: Pick<UpDeps, "fetchNpmIntegrity" | "output">
): Promise<void> {
  const c = await classifyIntegrity(lockFile, deps);

  // Servers --frozen can't integrity-check (pypi/oci have no baseline mechanism;
  // url servers have no package coordinate) — name them loudly rather than let a
  // clean result read as a full freeze (multi-registry pinning is deferred).
  if (c.unenforceable.length > 0) {
    deps.output(
      `\n${c.unenforceable.length} server(s) (pypi/oci/url) have no integrity baseline mechanism` +
        ` — \`--frozen\` cannot enforce them (multi-registry pinning is deferred).`
    );
  }

  // A lock where NO npm server has a baseline is benign (pre-baseline or offline
  // lock), not an attack — refuse with instructions instead of a per-server verdict.
  if (c.absentBaseline.length > 0 && c.checkedNpmCount === 0) {
    throw new Error(
      "--frozen: this lock has no integrity baselines (it predates them, or was last locked" +
        " offline). Run `mcpm lock` online once to record them, then `mcpm up --frozen`."
    );
  }

  const blocks: string[] = [];
  for (const d of c.drift) {
    const oldShort = d.oldIntegrity.slice(0, 16);
    const newShort = d.newIntegrity.slice(0, 16);
    blocks.push(
      `✗ FROZEN: npm's published record for ${d.identifier}@${d.npmVersion} changed since you` +
        ` locked it (dist.integrity ${oldShort}… → ${newShort}…). --frozen refuses to install on` +
        ` integrity drift. Re-pin with \`mcpm lock\` only if this change is expected.`
    );
  }
  for (const f of c.formatOnly) {
    blocks.push(
      `✗ FROZEN: cannot compare npm's published record for ${f.identifier}@${f.npmVersion} against` +
        ` your locked baseline (integrity format changed). Re-run \`mcpm lock\` to refresh it.`
    );
  }
  // could-not-verify is NON-deterministic (a transient registry blip looks the same
  // as a yanked version) — give it a distinct "re-run" message, separate from the
  // deterministic drift block.
  for (const v of c.couldNotVerify) {
    blocks.push(
      `✗ FROZEN: could not verify npm's published record for ${v.identifier}@${v.npmVersion} this` +
        ` run (offline, a yanked version, or no comparable dist.integrity). --frozen requires proof` +
        ` the record matches your lock — this may be a transient registry error, so re-run; if it` +
        ` persists, drop --frozen.`
    );
  }
  // mixed-lock gap (handled above only when checkedNpmCount === 0).
  for (const name of c.absentBaseline) {
    blocks.push(
      `✗ FROZEN: no integrity baseline recorded for ${name}, though other servers in this lock` +
        ` have one. Re-run \`mcpm lock\` online to record it, then \`mcpm up --frozen\`.`
    );
  }

  if (blocks.length > 0) {
    deps.output(`\n${blocks.join("\n")}`);
    deps.output("\nmcpm verifies the registry's published record, not the code your agent runs at launch.");
    throw new Error(
      `frozen: ${blocks.length} server(s) failed integrity verification; nothing was installed.`
    );
  }
}

/**
 * F2 — cross-server tool-name-collision (shadow) pass. Reads pins once, compares
 * the guarded tool inventories across the resolved server set, and reports any
 * tool name exposed by >= 2 servers. Read-only and FAIL-SOFT: a missing reader or
 * unreadable/integrity-failed pins NEVER crashes `up` (the check is an advisory
 * overlay, run after all install gates have already passed). Returns the number
 * of collisions so the caller can apply the `--ci` exit gate.
 *
 * Honesty is load-bearing: pins only cover servers that have run under guard, so
 * the coverage line names exactly how many servers had no baseline — a clean
 * result over an un-pinned stack is NOT proof of no shadowing.
 */
async function runShadowPass(
  serverNames: readonly string[],
  deps: Pick<UpDeps, "readPins" | "output">
): Promise<number> {
  if (deps.readPins === undefined) {
    // Armed but no pins reader wired — surface it (don't silently no-op) so an
    // un-wired caller never mistakes "nothing printed" for "no shadowing".
    deps.output("\n⚠ shadow check skipped: no pins reader available in this context.");
    return 0;
  }

  let pins: PinsFile;
  try {
    pins = await deps.readPins();
  } catch {
    deps.output(
      "\n⚠ shadow check skipped: ~/.mcpm/pins.json is unreadable (integrity check or corruption)."
    );
    return 0;
  }

  const findings = detectNameCollisions(buildInventoryFromPins(pins, serverNames));
  const noBaseline = serversWithoutBaseline(pins, serverNames);
  const checked = serverNames.length - noBaseline.length;

  // Coverage honesty FIRST — never let a clean result read as "safe".
  deps.output(
    `\nShadow check: compared guarded tool inventories for ${checked} of ${serverNames.length} server(s).`
  );
  if (noBaseline.length > 0) {
    deps.output(
      `  ${noBaseline.length} server(s) have NO guard baseline yet (${noBaseline.join(", ")}) — ` +
        "this check cannot see their tools, so a clean result does NOT mean no shadowing. " +
        "Run them under `mcpm guard` (then re-run `mcpm up`) to include them."
    );
  }

  for (const f of findings) {
    deps.output(
      `\n⚠ SHADOW: tool "${f.toolName}" is exposed by ${f.servers.length} servers (${f.servers.join(", ")}). ` +
        "A lower-trust server can shadow a tool meant for another, so agent calls to " +
        `"${f.toolName}" are ambiguous. This can also be benign (two servers of the same kind ` +
        "legitimately export the same tool). Review which server should own it. (Exact-name match " +
        "only — a homoglyph/case variant evades this check.)"
    );
  }

  return findings.length;
}

async function processUrlServer(
  name: string,
  url: string,
  clients: ClientId[],
  policy: Policy | undefined,
  consentedUnguarded: ReadonlySet<string>,
  options: UpOptions,
  deps: UpDeps
): Promise<ServerResult> {
  // MCP surface lockdown (fix D): URL servers bypass the registry trust gate, so
  // the untrusted MCP caller is not permitted to install them. Record as blocked.
  // H9: this kill-switch ALWAYS wins — an untrusted caller can never opt in via
  // `--allow-unguarded` or a (caller-controlled) policy bit.
  if (options.allowUrlServers === false) {
    return {
      name,
      status: "blocked",
      message: "URL servers are not permitted via the MCP surface",
    };
  }

  // H9 (fail-closed): a URL/HTTP-transport server runs UNGUARDED — the guard
  // relay only wraps stdio servers, so it gets ZERO runtime inspection. DENY by
  // default; permit only with explicit informed consent: `--allow-unguarded`
  // this run, `policy.allowUrlServers: true` in the stack file, or a name
  // already in the persistent consent store. This is informed consent, NOT
  // protection — the only true fix is a streamable-HTTP relay (out of scope).
  const consented =
    options.allowUnguarded === true ||
    policy?.allowUrlServers === true ||
    consentedUnguarded.has(name);
  if (!consented) {
    return {
      name,
      status: "blocked",
      message:
        "URL/HTTP-transport server runs UNGUARDED — no runtime inspection is possible " +
        "(mcpm's guard relay only wraps stdio servers). Re-run with --allow-unguarded or set " +
        "policy.allowUrlServers: true to install it WITHOUT protection.",
    };
  }

  // M4a: validate the URL before it is written to any client config. The up path
  // previously wrote stack-file `url:` servers unvalidated; this rejects non-http(s)
  // schemes and non-loopback plaintext http (interceptable once in an IDE config).
  // Capture (don't throw): `--dry-run` must stay a read-only, exit-zero preview, and
  // an invalid URL is categorized as `blocked` (mirroring trust-policy blocks) rather
  // than crashing the per-server loop into a generic `failed`.
  let urlError: string | undefined;
  try {
    validateRemoteUrl(url);
  } catch (err) {
    urlError = err instanceof Error ? err.message : String(err);
  }

  const cursorClients = clients.filter((c) => c === "cursor");

  if (cursorClients.length === 0) {
    return {
      name,
      status: "skipped",
      message: "URL server — no Cursor client detected (only Cursor supports URL transport)",
    };
  }

  if (options.dryRun) {
    return urlError
      ? { name, status: "skipped", message: `would reject URL ${url}: ${urlError}` }
      : { name, status: "skipped", message: `would install URL ${url} to Cursor` };
  }

  if (urlError) {
    return { name, status: "blocked", message: urlError };
  }

  for (const clientId of cursorClients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getPath(clientId);
    await adapter.addServer(configPath, name, { url }, { force: true });
  }

  return { name, status: "installed", message: `URL ${url} → Cursor` };
}

// ---------------------------------------------------------------------------
// Env var resolution
// ---------------------------------------------------------------------------

async function resolveEnvVars(
  serverName: string,
  server: StackFile["servers"][string],
  envFileVars: Readonly<Record<string, string>>,
  options: UpOptions,
  deps: UpDeps
): Promise<{ env: Record<string, string>; storedCount: number }> {
  const envDecl = (isRegistryServer(server) || isUrlServer(server))
    ? server.env
    : undefined;

  if (!envDecl) return { env: {}, storedCount: 0 };

  const resolved: Record<string, string> = {};
  const secretKeys = new Set<string>();

  for (const [key, decl] of Object.entries(envDecl)) {
    // Resolution order: process.env → .env file → default → prompt.
    // MCP surface lockdown (fix C): when allowProcessEnv === false, the
    // process.env source is skipped so an attacker-controlled stack file can't
    // harvest ambient secrets into installed server configs. The CLI default
    // (allowProcessEnv undefined/true) keeps reading process.env as before.
    const fromEnv = options.allowProcessEnv === false ? undefined : process.env[key];
    const fromFile = envFileVars[key];
    const fromDefault = decl.default;

    // L1: compare against undefined, not truthiness — an explicitly-set empty
    // string ("") is a legitimate value and must not silently fall through to
    // the next source (or to the required-var prompt/throw).
    let value: string | undefined;
    if (fromEnv !== undefined) {
      value = fromEnv;
    } else if (fromFile !== undefined) {
      value = fromFile;
    } else if (fromDefault !== undefined) {
      value = fromDefault;
    } else if (decl.required) {
      if (options.ci) {
        throw new Error(
          `Required env var "${key}" for "${serverName}" is not set. ` +
            `Set it in process.env or .env file (--ci mode, no interactive prompt).`
        );
      }
      value = await deps.promptEnvVar(key, decl.secret);
    }

    if (value === undefined) continue;
    resolved[key] = value;
    if (decl.secret) secretKeys.add(key);
  }

  // In keychain mode this stores secret-flagged values encrypted and replaces
  // them with placeholders; in plaintext mode it returns `resolved` unchanged.
  return applyKeychainSecrets({
    serverName,
    resolvedEnv: resolved,
    isSecret: (key) => secretKeys.has(key),
    mode: options.secrets ?? "plaintext",
    setSecrets: deps.setSecrets,
  });
}

// ---------------------------------------------------------------------------
// Strict mode removal
// ---------------------------------------------------------------------------

async function handleStrictRemoval(
  stackFile: StackFile,
  clients: ClientId[],
  options: UpOptions,
  deps: UpDeps,
  results: ServerResult[]
): Promise<void> {
  const declaredNames = new Set(Object.keys(stackFile.servers));

  for (const clientId of clients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getPath(clientId);
    const installed = await adapter.read(configPath);

    for (const name of Object.keys(installed)) {
      if (declaredNames.has(name)) continue;

      if (options.ci && !options.yes) {
        throw new Error(
          `--strict --ci requires --yes to remove servers not in mcpm.yaml. ` +
            `Server "${name}" in ${clientId} would be removed.`
        );
      }

      if (!options.ci && options.yes !== true) {
        const confirmed = await deps.confirm(
          `Remove "${name}" from ${clientId}? (not in mcpm.yaml)`
        );
        if (!confirmed) continue;
      }

      await adapter.removeServer(configPath, name);
      results.push({
        name,
        status: "removed",
        message: `removed from ${clientId} (not in mcpm.yaml)`,
      });
      deps.recordResult?.({ name, status: "removed" });
      deps.output(`  - ${name}: removed from ${clientId}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function statusIcon(status: string): string {
  switch (status) {
    case "installed": return "\u2713";
    case "removed": return "\u2212";
    case "skipped": return "\u2022";
    case "blocked": return "\u2717";
    case "failed": return "\u2717";
    default: return "?";
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import chalk from "chalk";
import { input, password } from "@inquirer/prompts";
import { detectInstalledClients } from "../config/detector.js";
import { getConfigPath } from "../config/paths.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { RegistryClient } from "../registry/client.js";
import { scanTier1 as _scanTier1 } from "../scanner/tier1.js";
import {
  checkScannerAvailable as _checkScannerAvailable,
  scanTier2 as _scanTier2,
} from "../scanner/tier2.js";
import { computeTrustScore as _computeTrustScore } from "../scanner/trust-score.js";
import { handleLock } from "./lock.js";
import { createConfirm } from "../utils/confirm.js";
import { stdoutOutput } from "../utils/output.js";
import { fetchNpmIntegrity as _fetchNpmIntegrity } from "../registry/npm-integrity.js";

export function registerUpCommand(program: Command): void {
  program
    .command("up")
    .description("Install all servers from mcpm.yaml with trust verification")
    .option("-f, --file <path>", "path to mcpm.yaml", "mcpm.yaml")
    .option("-p, --profile <name>", "install only servers matching this profile")
    .option("--dry-run", "show what would be installed without making changes")
    .option("--ci", "CI mode: no interactive prompts, exit nonzero on failure")
    .option("--strict", "remove servers not declared in mcpm.yaml")
    .option("-y, --yes", "skip confirmation prompts (required with --strict --ci)")
    .option("--secrets <mode>", "where to store secret env vars: 'keychain' (encrypted in ~/.mcpm, resolved by mcpm guard at launch) or 'plaintext' (default); 'keychain' is rejected with --ci", parseSecretsMode)
    .option("--allow-unguarded", "permit URL/HTTP-transport servers to run WITHOUT runtime guard inspection (no relay wraps a non-stdio transport); records consent so future runs stay quiet")
    .option("--check-shadowing", "report tool-name collisions across guarded servers (a shadowing signal); advisory interactively, exits nonzero under --ci")
    .option("--frozen", "fail closed: verify every locked npm server's published integrity BEFORE installing and BLOCK (install nothing, exit nonzero) on drift / unverifiable / missing baseline — the CI supply-chain freeze gate")
    .action(
      async (opts: {
        file?: string;
        profile?: string;
        dryRun?: boolean;
        ci?: boolean;
        strict?: boolean;
        yes?: boolean;
        secrets?: SecretsMode;
        allowUnguarded?: boolean;
        checkShadowing?: boolean;
        frozen?: boolean;
      }) => {
        const client = new RegistryClient();
        const { readUnguardedConsent, writeUnguardedConsent, mergeUnguarded } = await import(
          "../guard/unguarded.js"
        );

        try {
          await handleUp(
            {
              stackFile: opts.file,
              profile: opts.profile,
              dryRun: opts.dryRun,
              ci: opts.ci,
              strict: opts.strict,
              yes: opts.yes,
              secrets: opts.secrets,
              allowUnguarded: opts.allowUnguarded,
              checkShadowing: opts.checkShadowing,
              frozen: opts.frozen,
            },
            {
              detectClients: detectInstalledClients,
              getAdapter: getAdapterDefault,
              getPath: getConfigPath,
              getServer: (name, version?) => client.getServer(name, version),
              scanTier1: _scanTier1,
              checkScannerAvailable: _checkScannerAvailable,
              scanTier2: (name) => _scanTier2(name),
              computeTrustScore: _computeTrustScore,
              now: () => Date.now(),
              runLock: async (stackFile) => {
                const { writeFile } = await import("fs/promises");
                await handleLock(
                  { stackFile },
                  {
                    getServerVersions: (name) => client.getServerVersions(name),
                    getServer: (name, v?) => client.getServer(name, v),
                    scanTier1: _scanTier1,
                    checkScannerAvailable: _checkScannerAvailable,
                    scanTier2: (name) => _scanTier2(name),
                    computeTrustScore: _computeTrustScore,
                    now: () => Date.now(),
                    writeLockFile: (path, content) =>
                      writeFile(path, content, { encoding: "utf-8", mode: 0o600 }),
                    fetchNpmIntegrity: _fetchNpmIntegrity,
                    output: stdoutOutput,
                  }
                );
              },
              confirm: createConfirm(),
              promptEnvVar: async (name, isSecret) => {
                if (isSecret) {
                  return password({ message: `${name}:` });
                }
                return input({ message: `${name}:` });
              },
              output: stdoutOutput,
              setSecrets: _setSecrets,
              fetchNpmIntegrity: _fetchNpmIntegrity,
              readPins: _readPins,
              readUnguardedConsent,
              recordUnguardedConsent: async (names) => {
                const previous = await readUnguardedConsent();
                await writeUnguardedConsent(mergeUnguarded(previous, names));
              },
            }
          );
        } catch (err) {
          console.error(chalk.red((err as Error).message));
          process.exit(1);
        }
      }
    );
}
