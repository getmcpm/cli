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

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { ServerEntry, EnvVar } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type { InstalledServer } from "../store/servers.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface InstallOptions {
  client?: string;
  yes?: boolean;
  force?: boolean;
  skipHealthCheck?: boolean;
  json?: boolean;
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
    return {
      command: "npx",
      args: ["-y", npmPkg.identifier, ...(npmPkg.runtimeArguments ?? [])],
    };
  }

  if (pypiPkg) {
    return {
      command: "uvx",
      args: [pypiPkg.identifier, ...(pypiPkg.runtimeArguments ?? [])],
    };
  }

  if (ociPkg) {
    return {
      command: "docker",
      args: ["run", "--rm", "-i", ociPkg.identifier, ...(ociPkg.runtimeArguments ?? [])],
    };
  }

  // Rule 3: Cursor-only path — HTTP remote with no packages
  if (clientId === "cursor" && server.remotes && server.remotes.length > 0) {
    const remote = server.remotes[0];
    return { url: remote.url };
  }

  throw new Error(
    `No install path found for server "${server.name}": no packages and no compatible remotes.`
  );
}

// ---------------------------------------------------------------------------
// formatTrustScore — pure function, rich display
// ---------------------------------------------------------------------------

const BAR_LENGTH = 20;
const BAR_FULL = "█";
const BAR_EMPTY = "░";

/**
 * Format a trust score as a visual progress bar with breakdown details.
 * Uses chalk for colours — ANSI codes stripped in tests via regex.
 */
export function formatTrustScore(trustScore: TrustScore): string {
  // Lazy-import chalk to keep this module testable without chalk side-effects
  // We use a synchronous approach via the chalk module that is already loaded.
  // Since ESM top-level imports must be static, we access chalk at runtime.
  const { score, maxPossible, level, breakdown } = trustScore;
  const ratio = score / maxPossible;
  const filled = Math.round(ratio * BAR_LENGTH);
  const bar = BAR_FULL.repeat(filled) + BAR_EMPTY.repeat(BAR_LENGTH - filled);

  let levelLabel: string;
  let barColour: (s: string) => string;
  let labelColour: (s: string) => string;

  // We use a runtime-safe colour helper that wraps chalk.
  // chalk is already a dependency — no new imports needed.
  try {
    // Dynamic require not available in ESM — chalk is already in scope if imported at top.
    // We use ANSI escape sequences directly to avoid circular import issues.
    if (level === "safe") {
      levelLabel = "\u001b[32mSAFE\u001b[0m"; // green
      barColour = (s) => `\u001b[32m${s}\u001b[0m`;
      labelColour = (s) => `\u001b[32m${s}\u001b[0m`;
    } else if (level === "caution") {
      levelLabel = "\u001b[33mCAUTION\u001b[0m"; // yellow
      barColour = (s) => `\u001b[33m${s}\u001b[0m`;
      labelColour = (s) => `\u001b[33m${s}\u001b[0m`;
    } else {
      levelLabel = "\u001b[31mRISKY\u001b[0m"; // red
      barColour = (s) => `\u001b[31m${s}\u001b[0m`;
      labelColour = (s) => `\u001b[31m${s}\u001b[0m`;
    }
    void labelColour;
  } catch {
    barColour = (s) => s;
    levelLabel = level.toUpperCase();
  }

  const lines: string[] = [
    `${barColour(bar)} ${score}/${maxPossible} ${levelLabel}`,
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

  const official = serverEntry._meta?.["io.modelcontextprotocol.registry/official"] ?? {};
  const trustScoreInput: TrustScoreInput = {
    findings: allFindings,
    healthCheckPassed: null, // health check not yet run at this point
    hasExternalScanner: scannerAvailable,
    registryMeta: {
      isVerifiedPublisher: official?.status === "active",
      publishedAt: official?.publishedAt,
    },
  };

  const trustScore = computeTrustScore(trustScoreInput);

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
      const existing = await adapter.listServers(configPath);
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

    await adapter.addServer(configPath, name, entry);
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

import { Command } from "commander";
import chalk from "chalk";
import { detectInstalledClients as _detectClients } from "../config/detector.js";
import { getConfigPath as _getConfigPath } from "../config/paths.js";
import { addInstalledServer as _addToStore } from "../store/servers.js";
import { scanTier1 as _scanTier1 } from "../scanner/tier1.js";
import { checkScannerAvailable as _checkScannerAvailable, scanTier2 as _scanTier2 } from "../scanner/tier2.js";
import { computeTrustScore as _computeTrustScore } from "../scanner/trust-score.js";
import {
  ClaudeDesktopAdapter,
  CursorAdapter,
  VSCodeAdapter,
  WindsurfAdapter,
} from "../config/index.js";
import readline from "readline";

function getAdapterDefault(clientId: ClientId): ConfigAdapter {
  switch (clientId) {
    case "claude-desktop":
      return new ClaudeDesktopAdapter();
    case "cursor":
      return new CursorAdapter();
    case "vscode":
      return new VSCodeAdapter();
    case "windsurf":
      return new WindsurfAdapter();
    default: {
      const _never: never = clientId;
      throw new Error(`Unknown clientId: ${String(_never)}`);
    }
  }
}

function createConfirm(message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(`${message} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === "y");
    });
  });
}

async function promptEnvVarsDefault(
  vars: EnvVar[]
): Promise<Record<string, string>> {
  if (vars.length === 0) return {};

  const result: Record<string, string> = {};
  for (const envVar of vars) {
    if (!envVar.isRequired && !envVar.isSecret) continue;

    const defaultVal = envVar.default ?? "";
    const prompted = await new Promise<string>((resolve) => {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      const prompt = envVar.description
        ? `  ${envVar.name} (${envVar.description})${defaultVal ? ` [${defaultVal}]` : ""}: `
        : `  ${envVar.name}${defaultVal ? ` [${defaultVal}]` : ""}: `;
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer.trim() || defaultVal);
      });
    });

    if (prompted) {
      result[envVar.name] = prompted;
    }
  }
  return result;
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
    .action(async (name: string, opts: { client?: string; yes?: boolean; force?: boolean; skipHealthCheck?: boolean; json?: boolean }) => {
      const { RegistryClient } = await import("../registry/client.js");
      const client = new RegistryClient();

      const installOptions: InstallOptions = {
        client: opts.client,
        yes: opts.yes,
        force: opts.force,
        skipHealthCheck: opts.skipHealthCheck,
        json: opts.json,
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
        confirm: createConfirm,
        promptEnvVars: promptEnvVarsDefault,
        output: (text: string) => process.stdout.write(text + "\n"),
      };

      try {
        await handleInstall(name, installOptions, installDeps);
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
