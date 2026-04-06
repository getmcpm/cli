/**
 * `mcpm install <name>` command handler.
 *
 * Wires together: registry fetch → trust assessment → user confirmation →
 * client detection → env var prompting → config write → store record.
 *
 * All external dependencies are injected for testability.
 *
 * Exports:
 * - handleInstall()      — injectable handler for testing
 * - resolveInstallEntry() — pure function: ServerEntry + ClientId → McpServerEntry
 * - formatTrustScore()   — pure function: TrustScore → formatted string
 * - registerInstallCommand() — Commander registration
 */

import { CLIENT_IDS } from "../config/paths.js";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { ServerEntry, EnvVar } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type { InstalledServer } from "../store/servers.js";
import { scoreBar, levelColor, extractRegistryMeta } from "../utils/format-trust.js";

// ---------------------------------------------------------------------------
// Identifier validation — guard against command injection
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// URL validation — guard against malicious remote URLs
// ---------------------------------------------------------------------------

/**
 * Validate a remote URL before it is written to any IDE config file.
 * Only http: and https: protocols are permitted.
 */
export function validateRemoteUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid remote URL: "${url}"`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(
      `Remote URL must use http or https protocol, got: "${parsed.protocol}"`
    );
  }
}

const NPM_IDENTIFIER_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI_IDENTIFIER_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const OCI_IDENTIFIER_RE =
  /^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*:[a-zA-Z0-9._-]+$/;

/**
 * Validate a package identifier against the expected pattern for its registry
 * type. Throws if the identifier looks potentially malicious.
 */
export function validateIdentifier(identifier: string, registryType: string): void {
  const patterns: Record<string, RegExp> = {
    npm: NPM_IDENTIFIER_RE,
    pypi: PYPI_IDENTIFIER_RE,
    oci: OCI_IDENTIFIER_RE,
  };
  const re = patterns[registryType];
  if (re && !re.test(identifier)) {
    throw new Error(
      `Rejected potentially malicious ${registryType} identifier: "${identifier}"`
    );
  }
}

/**
 * Normalize runtimeArguments from the registry.
 * The registry may return plain strings or {type, value} objects.
 */
function normalizeRuntimeArgs(
  args: ReadonlyArray<string | { type: string; value: string }>
): string[] {
  return args.map((arg) =>
    typeof arg === "string" ? arg : arg.value
  );
}

/**
 * Node.js flags that enable arbitrary code execution.
 * These are rejected regardless of format (bare or with value).
 * This blocklist catches known-dangerous flags; the allowlist below
 * catches unknown/malformed arguments.
 */
const DANGEROUS_FLAG_PREFIXES: readonly string[] = [
  "--eval", "-e",
  "--require", "-r",
  "--import",
  "--loader",
  "--experimental-loader",
  "--inspect",
  "--inspect-brk",
  "--experimental-policy",
  "--experimental-network-imports",
  "--input-type",
];

/**
 * Allowlist of safe runtime argument shapes.
 * After dangerous flags are rejected, arguments must match one of these
 * patterns. This blocks shell metacharacters and path traversal while
 * allowing the wide range of flags real MCP servers use.
 */
const SAFE_ARG_PATTERNS: readonly RegExp[] = [
  // Generic boolean flags (--allow-write, --read-only, --no-sandbox, etc.)
  /^--[a-zA-Z][\w-]*$/,
  // Generic --key=value flags with safe value characters
  // Blocks shell metacharacters: ; | $ ` & ( ) { } < > ! ' "
  /^--[a-zA-Z][\w-]+=[\w./@:, -]+$/,
  // Bare absolute paths (Unix: /path/to/dir)
  /^\/[\w.@/ -]+$/,
  // Home-relative paths (~/Documents)
  /^~[\w.@/ -]*$/,
  // Bare positional arguments (no dashes, no path traversal)
  /^[a-zA-Z0-9][\w.@/-]*$/,
];

/**
 * Validate runtime arguments from the registry.
 * Two-layer defense: reject known-dangerous Node.js flags first,
 * then require remaining args to match safe structural patterns.
 */
export function validateRuntimeArgs(args: string[]): void {
  for (const arg of args) {
    // Layer 1: reject dangerous Node.js flags
    const isDangerous = DANGEROUS_FLAG_PREFIXES.some(
      (prefix) => arg === prefix || arg.startsWith(`${prefix}=`)
    );
    if (isDangerous) {
      throw new Error(`Rejected dangerous runtime argument: "${arg}"`);
    }

    // Layer 2: require safe structural pattern
    const isSafe = SAFE_ARG_PATTERNS.some((pattern) => pattern.test(arg));
    if (!isSafe) {
      throw new Error(`Rejected unrecognized runtime argument: "${arg}"`);
    }
  }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface InstallOptions {
  client?: string;
  yes?: boolean;
  force?: boolean;
  skipHealthCheck?: boolean;
  json?: boolean;
  minTrust?: number;
}

export interface InstallDeps {
  registryClient: { getServer: (name: string) => Promise<ServerEntry> };
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  scanTier1: (server: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  addToStore: (server: InstalledServer) => Promise<void>;
  confirm: (message: string) => Promise<boolean>;
  promptEnvVars: (vars: EnvVar[]) => Promise<Record<string, string>>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// resolveInstallEntry — pure function, no I/O
// ---------------------------------------------------------------------------

/**
 * Resolve the McpServerEntry for a given server + clientId.
 *
 * Decision tree:
 * 1. Cursor + server has HTTP remote → produce { url, headers } entry
 * 2. Otherwise pick from packages[]: npm → pypi → oci (first available)
 * 3. npm: { command: 'npx', args: ['-y', identifier, ...runtimeArgs], env }
 * 4. pypi: { command: 'uvx', args: [identifier, ...runtimeArgs], env }
 * 5. docker: { command: 'docker', args: ['run', '--rm', '-i', image], env }
 * 6. If no packages and no usable remote: throw
 */
export function resolveInstallEntry(
  serverEntry: ServerEntry,
  clientId: ClientId
): McpServerEntry {
  const { server } = serverEntry;

  // Rule 1: Cursor + HTTP remote → streamable-http entry
  if (clientId === "cursor" && server.remotes && server.remotes.length > 0) {
    const httpRemote = server.remotes.find(
      (r) => r.type === "streamable-http" || r.type === "sse"
    );
    if (httpRemote) {
      validateRemoteUrl(httpRemote.url);
      // Build headers record if any
      const headers: Record<string, string> = {};
      for (const h of httpRemote.headers) {
        headers[h.name] = "";
      }
      return {
        url: httpRemote.url,
        ...(Object.keys(headers).length > 0 ? { headers } : {}),
      };
    }
  }

  // Rule 2: Pick best package by priority: npm → pypi → oci
  const npmPkg = server.packages.find((p) => p.registryType === "npm");
  const pypiPkg = server.packages.find((p) => p.registryType === "pypi");
  const ociPkg = server.packages.find((p) => p.registryType === "oci");

  if (npmPkg) {
    validateIdentifier(npmPkg.identifier, "npm");
    const rtArgs = normalizeRuntimeArgs(npmPkg.runtimeArguments ?? []);
    validateRuntimeArgs(rtArgs);
    return {
      command: "npx",
      args: ["-y", npmPkg.identifier, ...rtArgs],
    };
  }

  if (pypiPkg) {
    validateIdentifier(pypiPkg.identifier, "pypi");
    const rtArgs = normalizeRuntimeArgs(pypiPkg.runtimeArguments ?? []);
    validateRuntimeArgs(rtArgs);
    return {
      command: "uvx",
      args: [pypiPkg.identifier, ...rtArgs],
    };
  }

  if (ociPkg) {
    validateIdentifier(ociPkg.identifier, "oci");
    const rtArgs = normalizeRuntimeArgs(ociPkg.runtimeArguments ?? []);
    validateRuntimeArgs(rtArgs);
    return {
      command: "docker",
      args: ["run", "--rm", "-i", ociPkg.identifier, ...rtArgs],
    };
  }

  // Rule 3: Cursor-only path — HTTP remote with no packages
  if (clientId === "cursor" && server.remotes && server.remotes.length > 0) {
    const remote = server.remotes[0];
    validateRemoteUrl(remote.url);
    return { url: remote.url };
  }

  throw new Error(
    `No install path found for server "${server.name}": no packages and no compatible remotes.`
  );
}

// ---------------------------------------------------------------------------
// formatTrustScore — pure function, rich display
// ---------------------------------------------------------------------------

/**
 * Format a trust score as a visual progress bar with breakdown details.
 */
export function formatTrustScore(trustScore: TrustScore): string {
  const { score, maxPossible, level, breakdown } = trustScore;

  const levelLabel = levelColor(level.toUpperCase());
  const bar = scoreBar(score, maxPossible);

  const lines: string[] = [
    `${bar} ${score}/${maxPossible} ${levelLabel}`,
    `  \u251C\u2500 Health check: ${breakdown.healthCheck > 0 ? "not yet run" : "failed or skipped"}`,
    `  \u251C\u2500 Tool descriptions: ${breakdown.staticScan === 40 ? "CLEAN (no injection patterns)" : `score ${breakdown.staticScan}/40`}`,
    `  \u251C\u2500 Package: publisher verification ${breakdown.registryMeta > 0 ? "passed" : "unverified"}`,
    `  \u2514\u2500 External scan: ${breakdown.externalScan > 0 ? `passed (${breakdown.externalScan}/20)` : "not available (install mcp-scan for deeper analysis)"}`,
  ];

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// handleInstall — main handler
// ---------------------------------------------------------------------------

/**
 * Core handler for `mcpm install <name>`.
 * All dependencies are injected for hermetic testability.
 */
export async function handleInstall(
  name: string,
  options: InstallOptions,
  deps: InstallDeps
): Promise<void> {
  const {
    registryClient,
    detectClients,
    getAdapter,
    getConfigPath,
    scanTier1,
    checkScannerAvailable,
    scanTier2,
    computeTrustScore,
    addToStore,
    confirm,
    promptEnvVars,
    output,
  } = deps;

  // -------------------------------------------------------------------------
  // Step 1: Fetch server metadata
  // -------------------------------------------------------------------------
  const serverEntry = await registryClient.getServer(name);

  // -------------------------------------------------------------------------
  // Step 2: Trust assessment
  // -------------------------------------------------------------------------
  const tier1Findings = scanTier1(serverEntry);
  const scannerAvailable = await checkScannerAvailable();

  let allFindings: Finding[] = [...tier1Findings];
  if (scannerAvailable) {
    const tier2Findings = await scanTier2(name);
    allFindings = [...allFindings, ...tier2Findings];
  }

  const trustScoreInput: TrustScoreInput = {
    findings: allFindings,
    healthCheckPassed: null, // health check not yet run at this point
    hasExternalScanner: scannerAvailable,
    registryMeta: extractRegistryMeta(serverEntry),
  };

  const trustScore = computeTrustScore(trustScoreInput);

  // -------------------------------------------------------------------------
  // Step 2b: --min-trust gate (checked before any output or confirmation)
  // -------------------------------------------------------------------------
  if (options.minTrust !== undefined && trustScore.score < options.minTrust) {
    if (options.json === true) {
      output(
        JSON.stringify(
          {
            name,
            error: "min_trust_not_met",
            score: trustScore.score,
            required: options.minTrust,
            level: trustScore.level,
          },
          null,
          2
        )
      );
    }
    throw new Error(
      `Trust score ${trustScore.score}/100 is below the required minimum of ${options.minTrust}. Installation aborted.`
    );
  }

  // -------------------------------------------------------------------------
  // Step 3: Display trust score and confirm
  // -------------------------------------------------------------------------
  // In --json mode suppress all human-readable output; only the final JSON
  // is written to stdout.
  const jsonMode = options.json === true;

  if (!jsonMode) {
    output(formatTrustScore(trustScore));
    output("");
  }

  if (options.yes !== true) {
    let shouldProceed: boolean;

    if (trustScore.level === "risky") {
      if (!jsonMode) {
        output("\u001b[31mWARNING: This server has a low trust score and may be risky to install.\u001b[0m");
        output("\u001b[31mSecurity findings indicate potential dangers. Proceed with extreme caution.\u001b[0m");
      }
      shouldProceed = await confirm(
        "I understand the risks and want to install this server anyway. Continue?"
      );
    } else if (trustScore.level === "caution") {
      if (!jsonMode) {
        output("\u001b[33mCAUTION: This server has a moderate trust score. Review the details above.\u001b[0m");
      }
      shouldProceed = await confirm(`Install '${name}'? (caution recommended)`);
    } else {
      // GREEN — brief display, proceed
      shouldProceed = await confirm(`Install '${name}'?`);
    }

    if (!shouldProceed) {
      if (!jsonMode) output("Installation cancelled.");
      return;
    }
  }

  // -------------------------------------------------------------------------
  // Step 4: Detect and filter clients
  // -------------------------------------------------------------------------
  let targetClients = await detectClients();

  if (targetClients.length === 0) {
    throw new Error(
      "No supported AI clients found. Install Claude Desktop, Cursor, VS Code, or Windsurf first."
    );
  }

  if (options.client !== undefined) {
    if (!CLIENT_IDS.includes(options.client as ClientId)) {
      throw new Error(
        `Unknown client "${options.client}". Valid values: ${CLIENT_IDS.join(", ")}.`
      );
    }
    const requestedId = options.client as ClientId;
    if (!targetClients.includes(requestedId)) {
      throw new Error(
        `Client "${requestedId}" is not installed on this machine.`
      );
    }
    targetClients = [requestedId];
  }

  // -------------------------------------------------------------------------
  // Step 5: Check for already-installed (unless --force)
  // -------------------------------------------------------------------------
  if (options.force !== true) {
    for (const clientId of targetClients) {
      const adapter = getAdapter(clientId);
      const configPath = getConfigPath(clientId);
      const existing = await adapter.read(configPath);
      if (Object.prototype.hasOwnProperty.call(existing, name)) {
        throw new Error(
          `Server '${name}' is already installed in ${clientId}. Use --force to overwrite.`
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 6: Resolve env vars to prompt for
  // -------------------------------------------------------------------------
  // Collect env vars from the best-match package
  const { server } = serverEntry;
  const bestPkg =
    server.packages.find((p) => p.registryType === "npm") ??
    server.packages.find((p) => p.registryType === "pypi") ??
    server.packages.find((p) => p.registryType === "oci") ??
    server.packages[0];

  const envVarDefs: EnvVar[] = bestPkg?.environmentVariables ?? [];
  const resolvedEnvVars = await promptEnvVars(envVarDefs);

  // -------------------------------------------------------------------------
  // Step 7: Validate install path exists
  // -------------------------------------------------------------------------
  // This validates before writing any config
  for (const clientId of targetClients) {
    const entry = resolveInstallEntry(serverEntry, clientId);
    void entry; // used in step 8 below
  }

  // -------------------------------------------------------------------------
  // Step 8: Write config to each client and record in store
  // -------------------------------------------------------------------------
  const installedClients: ClientId[] = [];

  for (const clientId of targetClients) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const rawEntry = resolveInstallEntry(serverEntry, clientId);

    // Merge resolved env vars into the entry (immutable)
    const entry: McpServerEntry = {
      ...rawEntry,
      ...(Object.keys(resolvedEnvVars).length > 0
        ? { env: { ...(rawEntry.env ?? {}), ...resolvedEnvVars } }
        : {}),
    };

    await adapter.addServer(configPath, name, entry, { force: options.force });
    installedClients.push(clientId);
  }

  // -------------------------------------------------------------------------
  // Step 8b: Warn about plaintext secret storage
  // -------------------------------------------------------------------------
  const hasSecrets = envVarDefs.some((ev) => ev.isSecret && resolvedEnvVars[ev.name]);
  if (hasSecrets && !options.json) {
    output(
      "\x1b[33mNote: API keys are stored as plaintext in client config files. " +
      "Ensure config files have appropriate permissions (chmod 600).\x1b[0m"
    );
  }

  // -------------------------------------------------------------------------
  // Step 9: Record in store
  // -------------------------------------------------------------------------
  const storeEntry: InstalledServer = {
    name,
    version: serverEntry.server.version,
    clients: [...installedClients],
    installedAt: new Date().toISOString(),
  };
  await addToStore(storeEntry);

  // -------------------------------------------------------------------------
  // Step 10: Output result
  // -------------------------------------------------------------------------
  if (options.json === true) {
    const result = {
      name,
      version: serverEntry.server.version,
      clients: installedClients,
      trustScore: {
        score: trustScore.score,
        maxPossible: trustScore.maxPossible,
        level: trustScore.level,
      },
    };
    output(JSON.stringify(result, null, 2));
    return;
  }

  const clientList = installedClients.join(", ");
  output(`\u001b[32mInstalled '${name}' successfully into: ${clientList}\u001b[0m`);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command, InvalidArgumentError } from "commander";
import chalk from "chalk";
import { input, password } from "@inquirer/prompts";
import { detectInstalledClients as _detectClients } from "../config/detector.js";
import { getConfigPath as _getConfigPath } from "../config/paths.js";
import { addInstalledServer as _addToStore } from "../store/servers.js";
import { scanTier1 as _scanTier1 } from "../scanner/tier1.js";
import { checkScannerAvailable as _checkScannerAvailable, scanTier2 as _scanTier2 } from "../scanner/tier2.js";
import { computeTrustScore as _computeTrustScore } from "../scanner/trust-score.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { createConfirm } from "../utils/confirm.js";
import { stdoutOutput } from "../utils/output.js";

async function promptEnvVarsDefault(
  vars: EnvVar[]
): Promise<Record<string, string>> {
  if (vars.length === 0) return {};

  const result: Record<string, string> = {};
  for (const envVar of vars) {
    if (!envVar.isRequired && !envVar.isSecret) continue;

    const defaultVal = envVar.default ?? "";
    const promptMessage = envVar.description
      ? `${envVar.name} (${envVar.description}):`
      : `${envVar.name}:`;

    let prompted: string;
    if (envVar.isSecret) {
      // Use password prompt to mask secret input — value is never echoed to the terminal
      prompted = await password({ message: promptMessage });
      if (!prompted && defaultVal) {
        prompted = defaultVal;
      }
    } else {
      prompted = await input({ message: promptMessage, default: defaultVal });
    }

    if (prompted) {
      result[envVar.name] = prompted;
    }
  }
  return result;
}

export function parseMinTrust(raw: string): number {
  // Reject anything that isn't plain decimal digits (blocks hex "0x50", scientific
  // notation "1e2", spaces, empty string, and negative sign before range check).
  if (!/^\d+$/.test(raw)) {
    throw new InvalidArgumentError(
      `--min-trust must be an integer between 0 and 100, got: "${raw}"`
    );
  }
  const n = Number(raw);
  if (n < 0 || n > 100) {
    throw new InvalidArgumentError(
      `--min-trust must be an integer between 0 and 100, got: "${raw}"`
    );
  }
  return n;
}

export function registerInstallCommand(program: Command): void {
  program
    .command("install <name>")
    .description("Install an MCP server from the registry")
    .option("-c, --client <id>", "install to a specific client only")
    .option("-y, --yes", "skip all confirmation prompts")
    .option("-f, --force", "overwrite if server already installed")
    .option("--skip-health-check", "skip post-install health check")
    .option("--json", "output result as JSON")
    .option("--min-trust <n>", "abort install if pre-install trust score is below this threshold (0-100; health check runs after install)", parseMinTrust)
    .action(async (name: string, opts: { client?: string; yes?: boolean; force?: boolean; skipHealthCheck?: boolean; json?: boolean; minTrust?: number }) => {
      const { RegistryClient } = await import("../registry/client.js");
      const client = new RegistryClient();

      const installOptions: InstallOptions = {
        client: opts.client,
        yes: opts.yes,
        force: opts.force,
        skipHealthCheck: opts.skipHealthCheck,
        json: opts.json,
        minTrust: opts.minTrust,
      };

      const installDeps: InstallDeps = {
        registryClient: client,
        detectClients: _detectClients,
        getAdapter: getAdapterDefault,
        getConfigPath: _getConfigPath,
        scanTier1: _scanTier1,
        checkScannerAvailable: _checkScannerAvailable,
        scanTier2: (serverName: string) => _scanTier2(serverName),
        computeTrustScore: _computeTrustScore,
        addToStore: _addToStore,
        confirm: createConfirm(),
        promptEnvVars: promptEnvVarsDefault,
        output: stdoutOutput,
      };

      try {
        await handleInstall(name, installOptions, installDeps);
      } catch (err) {
        if (installOptions.json !== true) {
          console.error(chalk.red((err as Error).message));
        }
        process.exit(1);
      }
    });
}
