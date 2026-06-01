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
import { resolveInstallEntry, parseSecretsMode } from "./install.js";
import { extractRegistryMeta } from "../utils/format-trust.js";
import { applyKeychainSecrets, type SecretsMode, setSecret as _setSecret } from "../store/keychain.js";

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
  runLock: (stackFile: string) => Promise<void>;
  confirm: (message: string) => Promise<boolean>;
  promptEnvVar: (name: string, isSecret: boolean) => Promise<string>;
  output: (text: string) => void;
  /** Optional; required only when options.secrets === "keychain". */
  setSecret?: (server: string, key: string, value: string) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Per-server result types
// ---------------------------------------------------------------------------

interface ServerSuccess {
  readonly name: string;
  readonly status: "installed" | "skipped";
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

  // Step 5: Load .env file for env var resolution
  const envFileVars = await parseEnvFile(".env");

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
        options,
        deps,
      });
      results.push(result);
      deps.output(`  ${statusIcon(result.status)} ${name}: ${result.message}`);
    } catch (err) {
      const failure: ServerFailure = {
        name,
        status: "failed",
        message: err instanceof Error ? err.message : String(err),
      };
      results.push(failure);
      deps.output(`  ${statusIcon("failed")} ${name}: ${failure.message}`);
    }
  }

  // Step 9: Strict mode — remove servers not in mcpm.yaml
  if (options.strict && !options.dryRun) {
    await handleStrictRemoval(stackFile, clients, options, deps, results);
  }

  // Step 10: Summary
  const installed = results.filter((r) => r.status === "installed").length;
  const blocked = results.filter((r) => r.status === "blocked").length;
  const failed = results.filter((r) => r.status === "failed").length;
  const skipped = results.filter((r) => r.status === "skipped").length;

  deps.output(
    `\n${installed} installed, ${skipped} skipped, ${blocked} blocked, ${failed} failed`
  );

  const totalSecretsStored = results.reduce(
    (sum, r) => sum + ((r as ServerSuccess).storedSecrets ?? 0),
    0
  );
  if (options.secrets === "keychain" && totalSecretsStored > 0 && !options.dryRun) {
    deps.output(
      "Secrets stored encrypted in ~/.mcpm. Run `mcpm guard enable` (then restart your IDE) so they resolve at launch."
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
  for (const clientId of clients) {
    try {
      const adapter = deps.getAdapter(clientId);
      const configPath = deps.getPath(clientId);
      const { readFile, writeFile } = await import("fs/promises");
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
  options: UpOptions;
  deps: UpDeps;
}

async function processServer(input: ProcessInput): Promise<ServerResult> {
  const { name, server, locked, policy, clients, scannerAvailable, envFileVars, options, deps } = input;

  // URL servers: install on Cursor only
  if (isUrlServer(server)) {
    return processUrlServer(name, server.url, clients, options, deps);
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

  const trustInput: TrustScoreInput = {
    findings,
    healthCheckPassed: null,
    hasExternalScanner: scannerAvailable,
    registryMeta: extractRegistryMeta(serverEntry),
  };
  const trustScore = deps.computeTrustScore(trustInput);

  // Policy check
  const policyResult = checkTrustPolicy({
    serverName: name,
    currentScore: trustScore.score,
    currentMaxPossible: trustScore.maxPossible,
    lockedSnapshot: locked.trust,
    policy,
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

  // Install to each client
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
    } catch {
      // Some clients may not support this server type — skip
    }
  }

  return {
    name,
    status: "installed",
    message: `v${locked.version} (trust: ${trustScore.score}/${trustScore.maxPossible})`,
    storedSecrets: storedCount,
  };
}

async function processUrlServer(
  name: string,
  url: string,
  clients: ClientId[],
  options: UpOptions,
  deps: UpDeps
): Promise<ServerResult> {
  const cursorClients = clients.filter((c) => c === "cursor");

  if (cursorClients.length === 0) {
    return {
      name,
      status: "skipped",
      message: "URL server — no Cursor client detected (only Cursor supports URL transport)",
    };
  }

  if (options.dryRun) {
    return { name, status: "skipped", message: `would install URL ${url} to Cursor` };
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
    // Resolution order: process.env → .env file → default → prompt
    const fromEnv = process.env[key];
    const fromFile = envFileVars[key];
    const fromDefault = decl.default;

    let value: string | undefined;
    if (fromEnv) {
      value = fromEnv;
    } else if (fromFile) {
      value = fromFile;
    } else if (fromDefault) {
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
    setSecret: deps.setSecret,
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

      if (!options.ci) {
        const confirmed = await deps.confirm(
          `Remove "${name}" from ${clientId}? (not in mcpm.yaml)`
        );
        if (!confirmed) continue;
      }

      await adapter.removeServer(configPath, name);
      results.push({
        name,
        status: "installed",
        message: `removed from ${clientId} (not in mcpm.yaml)`,
      });
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
    .action(
      async (opts: {
        file?: string;
        profile?: string;
        dryRun?: boolean;
        ci?: boolean;
        strict?: boolean;
        yes?: boolean;
        secrets?: SecretsMode;
      }) => {
        const client = new RegistryClient();

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
              setSecret: _setSecret,
            }
          );
        } catch (err) {
          console.error(chalk.red((err as Error).message));
          process.exit(1);
        }
      }
    );
}
