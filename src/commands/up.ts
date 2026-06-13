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
