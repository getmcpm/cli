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
import { argvTokens, type RuntimeArgument } from "../registry/argument-tokens.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type { InstalledServer } from "../store/servers.js";
import { scoreBar, levelColor, extractRegistryMeta } from "../utils/format-trust.js";
import { assessReleaseAge, DEFAULT_MIN_RELEASE_AGE_HOURS } from "../scanner/cooldown.js";
import { DANGEROUS_FLAG_PREFIXES } from "../scanner/patterns.js";
import { applyKeychainSecrets, type SecretsMode, setSecrets as _setSecrets } from "../store/keychain.js";

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
  // M4a: plaintext http to a non-loopback host is interceptable once written to an
  // IDE config. Allow http only for loopback (local dev servers); require https for
  // every other host. https is always allowed.
  if (parsed.protocol === "http:" && !isLoopbackHost(parsed.hostname)) {
    throw new Error(
      `Remote URL must use https for non-loopback hosts (plaintext http is ` +
        `vulnerable to interception), got: "${url}"`
    );
  }
}

/**
 * True for localhost / loopback literals, where plaintext http is acceptable.
 * Recognizes localhost / *.localhost / 127.0.0.1 / ::1. Exotic loopback spellings
 * (IPv4-mapped `::ffff:127.0.0.1`, `127.x.x.x`, decimal/octal/hex IPs) are NOT
 * recognized and fall through to the https requirement — over-rejection only, never
 * a bypass (a non-loopback host can never be mistaken for loopback).
 */
function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h === "127.0.0.1" ||
    h === "::1"
  );
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
 * Render runtimeArguments from the registry into a launch argv slice.
 *
 * Delegates to argvTokens (name + value, never valueHint) so the SAME function
 * defines both what gets executed here and what the F4 dangerous-flag scan
 * matches in scanner/patterns.ts — they cannot diverge. valueHint (a
 * documentation placeholder like "directory") is deliberately not rendered:
 * emitting it would inject a bogus literal argument. The injection scanner
 * (scanner/tier1.ts) uses argumentTokens instead, which DOES read valueHint as
 * user-facing text; that divergence is intentional and documented there.
 */
function normalizeRuntimeArgs(
  args: ReadonlyArray<RuntimeArgument>
): string[] {
  return args.flatMap(argvTokens);
}

/**
 * Allowlist of safe runtime argument shapes.
 * After dangerous flags are rejected, arguments must match one of these
 * patterns. This blocks shell metacharacters and path traversal while
 * allowing the wide range of flags real MCP servers use.
 */
const SAFE_ARG_PATTERNS: readonly RegExp[] = [
  // Generic boolean flags (--allow-write, --read-only, --no-sandbox, etc.)
  /^--[a-zA-Z][\w-]*$/,
  // Single-dash short flags the live registry legitimately declares (-i, -y, -p).
  // EXACTLY one alpha char — no bundled tail. Allowing a tail (-rmodule, -eCODE)
  // would let a dangerous flag bundle its payload and slip past the Layer-1
  // DANGEROUS_FLAG_PREFIXES check, which only rejects the exact token (-e/-r) or
  // its '=' form. The live registry's short flags are all single-letter, so the
  // narrow form loses no real coverage while closing the bundling bypass.
  /^-[a-zA-Z]$/,
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
    // Layer 0 (M4b): reject a ".." path-traversal segment anywhere in the argument
    // — "../x", "a/../../etc/passwd", "--config=../secret". A ".." segment is one
    // bounded by start-of-arg, "=" (flag value), or a path separator on the left,
    // and a separator or end-of-arg on the right. The Layer-2 allowlist permits "."
    // and "/" inside values, so without this a traversal would slip through; a
    // non-traversal double dot like "--range=1..10" is left untouched.
    if (/(?:^|[=\\/])\.\.(?:[\\/]|$)/.test(arg)) {
      throw new Error(`Rejected path traversal in runtime argument: "${arg}"`);
    }

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
  minReleaseAge?: number;
  allowFresh?: boolean;
  secrets?: SecretsMode;
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
  /** Optional; required only when options.secrets === "keychain". */
  setSecrets?: (server: string, values: Record<string, string>) => Promise<void>;
  /** Epoch-ms clock for release-age assessment; defaults to Date.now at the CLI boundary. */
  now?: () => number;
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

  // Release-age cooldown: assessed ONCE so the score finding and the Step 2c
  // gate can never disagree — passing --min-release-age below 24 therefore also
  // lowers the scoring cooldown threshold (documented in the flag help text).
  // The medium finding lands unconditionally for fresh releases, with or
  // without the gate — that is the inversion fix, independent of the gate.
  const registryMeta = extractRegistryMeta(serverEntry);
  const releaseAge = assessReleaseAge({
    publishedAt: registryMeta.publishedAt,
    now: (deps.now ?? Date.now)(),
    minAgeHours: options.minReleaseAge ?? DEFAULT_MIN_RELEASE_AGE_HOURS,
  });
  if (releaseAge.finding) {
    allFindings = [...allFindings, releaseAge.finding];
  }

  const trustScoreInput: TrustScoreInput = {
    findings: allFindings,
    healthCheckPassed: null, // health check not yet run at this point
    hasExternalScanner: scannerAvailable,
    registryMeta,
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
  // Step 2c: --min-release-age gate (checked before any output or confirmation)
  // -------------------------------------------------------------------------
  // Fail-closed when armed: a MISSING publish timestamp blocks too (blocksArmedGate)
  // — otherwise a registry/compromised mirror could defeat the gate by omitting
  // _meta (publishedAt is .optional() in OfficialMetaSchema). The score finding
  // stays fail-open for absent; only the explicitly armed gate hardens.
  if (
    options.minReleaseAge !== undefined &&
    options.allowFresh !== true &&
    releaseAge.blocksArmedGate
  ) {
    if (options.json === true) {
      output(
        JSON.stringify(
          {
            name,
            error: "release_age_not_met",
            ageHours: releaseAge.ageHours,
            required: options.minReleaseAge,
            reason: releaseAge.status,
          },
          null,
          2
        )
      );
    }
    const tail = "Installation aborted. Use --allow-fresh to bypass.";
    throw new Error(
      releaseAge.status === "future"
        ? `Release publish timestamp is in the future (clock skew or forged metadata); treated as within the ${options.minReleaseAge}-hour minimum release age. ${tail}`
        : releaseAge.status === "unparseable"
          ? `Release publish timestamp could not be parsed; treated as within the ${options.minReleaseAge}-hour minimum release age. ${tail}`
          : releaseAge.status === "absent"
            ? `Release publish timestamp is missing from the registry metadata, so release age cannot be verified against the ${options.minReleaseAge}-hour minimum. ${tail}`
            : `Release age ${releaseAge.ageHours}h is below the required minimum of ${options.minReleaseAge}h. ${tail}`
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

  // Step 6b: In keychain mode, persist secret-flagged values encrypted and swap
  // them for `mcpm:keychain:…` placeholders, so no plaintext is written to any
  // client config. Non-secret vars stay inline; each secret is stored once and
  // reused for every client. The placeholder resolves at launch only while mcpm
  // guard wraps the server (run-inner.ts → resolveEnvPlaceholders). The swap
  // (and the "no plaintext in config" invariant) lives in applyKeychainSecrets.
  const secretsMode: SecretsMode = options.secrets ?? "plaintext";
  const { env: envForConfig, storedCount: storedSecretCount } = await applyKeychainSecrets({
    serverName: name,
    resolvedEnv: resolvedEnvVars,
    isSecret: (key) => envVarDefs.find((d) => d.name === key)?.isSecret === true,
    mode: secretsMode,
    setSecrets: deps.setSecrets,
  });

  // -------------------------------------------------------------------------
  // Step 7: Resolve (and thereby validate) each client's entry up front
  // -------------------------------------------------------------------------
  // resolveInstallEntry throws on an invalid identifier, so resolving here
  // before any config is written preserves fail-fast validation. The resolved
  // entries are reused in Step 8 to avoid recomputing them.
  const resolvedEntries = new Map<ClientId, McpServerEntry>();
  for (const clientId of targetClients) {
    resolvedEntries.set(clientId, resolveInstallEntry(serverEntry, clientId));
  }

  // -------------------------------------------------------------------------
  // Step 8: Write config to each client and record in store
  // -------------------------------------------------------------------------
  const installedClients: ClientId[] = [];

  for (const clientId of targetClients) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const rawEntry = resolvedEntries.get(clientId)!;

    // Merge env vars into the entry (immutable). In keychain mode envForConfig
    // carries placeholders in place of secret values; otherwise it === resolvedEnvVars.
    const entry: McpServerEntry = {
      ...rawEntry,
      ...(Object.keys(envForConfig).length > 0
        ? { env: { ...(rawEntry.env ?? {}), ...envForConfig } }
        : {}),
    };

    await adapter.addServer(configPath, name, entry, { force: options.force });
    installedClients.push(clientId);
  }

  // -------------------------------------------------------------------------
  // Step 8b: Secret-storage notice
  // -------------------------------------------------------------------------
  if (!options.json) {
    if (secretsMode === "keychain" && storedSecretCount > 0) {
      output(
        `\x1b[32mStored ${storedSecretCount} secret(s) encrypted at rest in ~/.mcpm. ` +
        "With an OS keychain this protects against other-user/offline access (not " +
        "same-user processes); without one a machine-derived key is used that guards " +
        "casual local inspection only, NOT file exfiltration — run `mcpm secrets migrate` " +
        "once a keychain is available. " +
        "Run `mcpm guard enable` (then restart your IDE) so they resolve at launch — " +
        "until guard wraps this server it receives the literal placeholder.\x1b[0m"
      );
    } else {
      const hasSecrets = envVarDefs.some((ev) => ev.isSecret && resolvedEnvVars[ev.name]);
      if (hasSecrets) {
        output(
          "\x1b[33mNote: API keys are stored as plaintext in client config files. " +
          "Ensure config files have appropriate permissions (chmod 600).\x1b[0m"
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 9: Record in store
  // -------------------------------------------------------------------------
  const storeEntry: InstalledServer = {
    name,
    version: serverEntry.server.version,
    clients: [...installedClients],
    installedAt: new Date().toISOString(),
    trustScore: trustScore.score,
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

export function parseSecretsMode(raw: string): SecretsMode {
  if (raw !== "keychain" && raw !== "plaintext") {
    throw new InvalidArgumentError(
      `--secrets must be "keychain" or "plaintext", got: "${raw}"`
    );
  }
  return raw;
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

export function parseMinReleaseAge(raw: string): number {
  // Same regex-first discipline as parseMinTrust: blocks hex "0x18", "1e2",
  // spaces, empty string, negatives. Safe-integer check guards absurd lengths.
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
    throw new InvalidArgumentError(
      `--min-release-age must be a non-negative integer number of hours, got: "${raw}"`
    );
  }
  return Number(raw);
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
    .option("--min-release-age <hours>", "abort install if the release is younger than this many hours OR its publish timestamp is missing/unparseable (fail-closed when set; also sets the scoring cooldown threshold; bypass with --allow-fresh)", parseMinReleaseAge)
    .option("--allow-fresh", "bypass the --min-release-age gate (including the missing-timestamp block)")
    .option("--secrets <mode>", "where to store secret env vars: 'keychain' (encrypted in ~/.mcpm, resolved by mcpm guard at launch) or 'plaintext' (default)", parseSecretsMode)
    .action(async (name: string, opts: { client?: string; yes?: boolean; force?: boolean; skipHealthCheck?: boolean; json?: boolean; minTrust?: number; minReleaseAge?: number; allowFresh?: boolean; secrets?: SecretsMode }) => {
      const { RegistryClient } = await import("../registry/client.js");
      const client = new RegistryClient();

      const installOptions: InstallOptions = {
        client: opts.client,
        yes: opts.yes,
        force: opts.force,
        skipHealthCheck: opts.skipHealthCheck,
        json: opts.json,
        minTrust: opts.minTrust,
        minReleaseAge: opts.minReleaseAge,
        allowFresh: opts.allowFresh,
        secrets: opts.secrets,
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
        setSecrets: _setSecrets,
        now: () => Date.now(),
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
