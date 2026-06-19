/**
 * MCP tool handlers for mcpm serve.
 *
 * Each handler wraps existing mcpm logic and returns structured JSON.
 * All dependencies are injectable for testability.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import type { ClientId } from "../config/paths.js";
import { CLIENT_IDS } from "../config/paths.js";
import type { ConfigAdapter } from "../config/adapters/index.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { extractRegistryMeta } from "../utils/format-trust.js";
import { formatMcpEntryCommand } from "../utils/format-entry.js";
import { resolveInstallEntry } from "../commands/install.js";
import { fetchNpmIntegrity as _fetchNpmIntegrity } from "../registry/npm-integrity.js";
import { readPins as _readPins } from "../guard/pins.js";

// ---------------------------------------------------------------------------
// Input validation for MCP server tool arguments
// ---------------------------------------------------------------------------

/**
 * Server name pattern for MCP registry names.
 * Format: "namespace/server-name" — alphanumeric with dots, hyphens, underscores.
 * Max length 256 to prevent abuse. Must not contain shell metacharacters,
 * path traversal sequences, or control characters.
 */
const SERVER_NAME_RE =
  /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}\/[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}$/;

/**
 * Validate a server name received from an MCP tool call.
 * This is the trust boundary — AI agents provide these strings, and they
 * could be influenced by prompt injection or adversarial inputs.
 */
function validateMcpServerName(name: string): void {
  if (typeof name !== "string" || name.length === 0 || name.length > 256) {
    throw new Error(`Invalid server name: must be a non-empty string under 256 characters.`);
  }
  if (!SERVER_NAME_RE.test(name)) {
    throw new Error(
      `Invalid server name format: "${name}". Expected format: "namespace/server-name" ` +
      `(alphanumeric, dots, hyphens, underscores only).`
    );
  }
}

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------
// Dependency injection types
// ---------------------------------------------------------------------------

export interface ServerDeps {
  registrySearch: (query: string, limit: number) => Promise<ServerEntry[]>;
  registryGetServer: (name: string) => Promise<ServerEntry>;
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  scanTier1: (server: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  addToStore: (server: { name: string; version: string; clients: ClientId[]; installedAt: string }) => Promise<void>;
  removeFromStore: (name: string) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * F4 scope note: this helper deliberately does NOT include the
 * release-cooldown finding (ServerDeps has no injectable clock; the F4 spec
 * file list excludes server/). Consequence: mcpm_install / mcpm_search score
 * a fresh (<24h) package up to 5 points higher than CLI install/why AND than
 * the sibling mcpm_up tool (which inherits the finding via up.ts
 * processServer), and HARD_TRUST_FLOOR evaluates that inflated score — do NOT
 * compensate by raising the floor. Fast-follow is mechanical:
 * ServerDeps += now?: () => number, then append
 * assessReleaseAge({...}).finding here; no schema changes.
 */
function computeTrust(entry: ServerEntry, deps: ServerDeps): TrustScore {
  const findings = deps.scanTier1(entry);
  return deps.computeTrustScore({
    findings,
    healthCheckPassed: null,
    hasExternalScanner: false,
    registryMeta: extractRegistryMeta(entry),
  });
}

async function resolveClients(
  requestedClient: string | undefined,
  deps: ServerDeps
): Promise<ClientId[]> {
  const detected = await deps.detectClients();
  if (detected.length === 0) {
    throw new Error("No supported AI clients found.");
  }
  if (requestedClient !== undefined) {
    if (!CLIENT_IDS.includes(requestedClient as ClientId)) {
      throw new Error(
        `Unknown client "${requestedClient}". Valid values: ${CLIENT_IDS.join(", ")}.`
      );
    }
    const id = requestedClient as ClientId;
    if (!detected.includes(id)) {
      throw new Error(`Client "${requestedClient}" is not installed.`);
    }
    return [id];
  }
  return detected;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export async function handleSearch(
  args: { query: string; limit: number },
  deps: ServerDeps
): Promise<object> {
  const entries = await deps.registrySearch(args.query, args.limit);
  const servers = entries.map((entry) => {
    const trust = computeTrust(entry, deps);
    return {
      name: entry.server.name,
      description: entry.server.description ?? "",
      version: entry.server.version,
      trustScore: trust.score,
    };
  });
  return { servers };
}

/** Default minimum trust score for MCP server tool installs (no human in the loop). */
const DEFAULT_MIN_TRUST_SCORE = 50;

/**
 * Hard, non-overridable trust floor for the MCP server surface (issue #24).
 *
 * The MCP `minTrustScore` input accepts `0`, which a prompt-injected agent could
 * pass to disable the install gate entirely. We clamp the effective threshold to
 * `Math.max(userValue, HARD_TRUST_FLOOR)` so no caller-supplied value can lower
 * the gate below this floor. This protects the no-human-in-loop path; the CLI
 * (with a human confirmation prompt) is the only place to install below it.
 */
const HARD_TRUST_FLOOR = 25;

/** Clamp a requested minimum trust score so it can never sink below the floor. */
function effectiveMinTrustScore(requested: number | undefined): number {
  return Math.max(requested ?? DEFAULT_MIN_TRUST_SCORE, HARD_TRUST_FLOOR);
}

export async function handleInstall(
  args: { name: string; client?: string; minTrustScore?: number },
  deps: ServerDeps,
  preResolved?: { entry: ServerEntry; trust: TrustScore }
): Promise<object> {
  validateMcpServerName(args.name);
  const entry = preResolved?.entry ?? await deps.registryGetServer(args.name);
  const trust = preResolved?.trust ?? computeTrust(entry, deps);

  // Security gate: reject servers below the minimum trust score.
  // Unlike the CLI path which has a human confirmation prompt, the MCP server
  // path is driven by AI agents with no human in the loop. A malicious prompt
  // could trick an agent into installing a dangerous server, so we enforce a
  // hard trust floor here. Issue #24: minTrustScore:0 must NOT disable the gate —
  // the effective threshold is clamped to HARD_TRUST_FLOOR.
  const minScore = effectiveMinTrustScore(args.minTrustScore);
  if (trust.score < minScore) {
    throw new Error(
      `Server "${args.name}" has trust score ${trust.score}/${trust.maxPossible} ` +
      `(level: ${trust.level}), which is below the minimum threshold of ${minScore}. ` +
      `Install rejected for safety. Use mcpm CLI with --yes to override after manual review.`
    );
  }

  const clients = await resolveClients(args.client, deps);

  const installedClients: ClientId[] = [];
  for (const clientId of clients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getConfigPath(clientId);
    const mcpEntry = resolveInstallEntry(entry, clientId);
    // H9 (fail-closed): a URL/HTTP-transport entry (url, no command) runs
    // UNGUARDED — the guard relay only wraps a stdio process. The MCP surface is
    // driven by an untrusted agent with no human in the loop and no
    // `--allow-unguarded` opt-in, so url-transport installs are HARD-DENIED here
    // (mirrors the batch `up` MCP wiring's allowUrlServers:false kill-switch).
    if (mcpEntry.url !== undefined && mcpEntry.command === undefined) {
      throw new Error(
        `Server "${args.name}" uses a URL/HTTP transport and runs UNGUARDED ` +
        `(the guard relay only wraps stdio servers). Installing it is not permitted ` +
        `via the MCP surface. Use the mcpm CLI with --allow-unguarded after manual review.`
      );
    }
    await adapter.addServer(configPath, args.name, mcpEntry);
    installedClients.push(clientId);
  }

  await deps.addToStore({
    name: args.name,
    version: entry.server.version,
    clients: [...installedClients],
    installedAt: new Date().toISOString(),
  });

  return {
    installed: true,
    name: args.name,
    version: entry.server.version,
    clients: installedClients,
    trustScore: trust,
  };
}

export async function handleInfo(
  args: { name: string },
  deps: ServerDeps
): Promise<object> {
  validateMcpServerName(args.name);
  const entry = await deps.registryGetServer(args.name);
  const trust = computeTrust(entry, deps);
  return {
    name: entry.server.name,
    description: entry.server.description ?? "",
    version: entry.server.version,
    packages: entry.server.packages.map((p) => ({
      registryType: p.registryType,
      identifier: p.identifier,
    })),
    trustScore: trust,
  };
}

export async function handleList(
  args: { client?: string },
  deps: ServerDeps
): Promise<object> {
  const clients = await resolveClients(args.client, deps);
  const servers: Array<{ name: string; client: string; command: string }> = [];

  for (const clientId of clients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getConfigPath(clientId);
    const installed = await adapter.read(configPath);

    for (const [name, entry] of Object.entries(installed)) {
      const command = formatMcpEntryCommand(entry, "unknown");
      servers.push({ name, client: clientId, command });
    }
  }

  return { servers };
}

export async function handleRemove(
  args: { name: string; client?: string },
  deps: ServerDeps
): Promise<object> {
  validateMcpServerName(args.name);
  const clients = await resolveClients(args.client, deps);
  const removedClients: ClientId[] = [];

  for (const clientId of clients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getConfigPath(clientId);
    try {
      await adapter.removeServer(configPath, args.name);
      removedClients.push(clientId);
    } catch {
      // Server not in this client, skip
    }
  }

  if (removedClients.length === 0) {
    throw new Error(`Server "${args.name}" not found in any client config.`);
  }

  try {
    await deps.removeFromStore(args.name);
  } catch {
    // Not in store, fine
  }

  return { removed: true, name: args.name, clients: removedClients };
}

export async function handleAudit(deps: ServerDeps): Promise<object> {
  const clients = await deps.detectClients();
  const results: Array<{ name: string; client: string; trustScore: TrustScore }> = [];

  for (const clientId of clients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getConfigPath(clientId);
    const installed = await adapter.read(configPath);

    for (const name of Object.keys(installed)) {
      try {
        const entry = await deps.registryGetServer(name);
        const trust = computeTrust(entry, deps);
        results.push({ name, client: clientId, trustScore: trust });
      } catch {
        results.push({
          name,
          client: clientId,
          trustScore: { score: 0, maxPossible: 80, level: "risky", breakdown: { healthCheck: 0, staticScan: 0, externalScan: 0, registryMeta: 0 } },
        });
      }
    }
  }

  return { results };
}

export async function handleDoctor(deps: ServerDeps): Promise<object> {
  const detected = await deps.detectClients();
  const clients = detected.map((id) => ({ id, detected: true }));

  const cmds = ["npx", "uvx", "docker"] as const;
  const results = await Promise.allSettled(
    cmds.map((cmd) => execFileAsync(cmd, ["--version"], { timeout: 5000 }))
  );
  const runtimes = cmds.map((name, i) => ({
    name,
    available: results[i].status === "fulfilled",
  }));

  return { clients, runtimes, issues: [] };
}

export async function handleSetup(
  args: { description: string; client?: string; minTrustScore: number },
  deps: ServerDeps
): Promise<object> {
  if (!args.description.trim()) {
    throw new Error("Could not extract any keywords from empty description.");
  }
  const keywords = extractKeywords(args.description);

  // Issue #24: clamp to the hard floor so minTrustScore:0 can't disable the gate
  // on the no-human-in-loop setup path either.
  const minScore = effectiveMinTrustScore(args.minTrustScore);

  const installed: Array<{ name: string; trustScore: TrustScore }> = [];
  const skipped: Array<{ name: string; reason: string }> = [];

  // Parallel search pass — all keywords searched concurrently. Capture the
  // thrown error per keyword so a registry outage is distinguishable from a
  // genuine empty result (both otherwise look like "no servers").
  type SearchOutcome =
    | { ok: true; entries: ServerEntry[] }
    | { ok: false; error: string };
  const searchResults: SearchOutcome[] = await Promise.all(
    keywords.map((kw) =>
      deps
        .registrySearch(kw, 5)
        .then((entries): SearchOutcome => ({ ok: true, entries }))
        .catch((err): SearchOutcome => ({
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        }))
    )
  );

  const seenNames = new Set<string>();

  // Sequential evaluate/install pass (installs depend on previous state)
  for (let i = 0; i < keywords.length; i++) {
    const keyword = keywords[i];
    const outcome = searchResults[i];

    if (!outcome.ok) {
      skipped.push({ name: keyword, reason: `Registry search failed: ${outcome.error}` });
      continue;
    }

    const entries = outcome.entries;

    if (entries.length === 0) {
      skipped.push({ name: keyword, reason: `No servers found for "${keyword}"` });
      continue;
    }

    let bestEntry: ServerEntry | null = null;
    let bestTrust: TrustScore | null = null;

    for (const entry of entries) {
      if (seenNames.has(entry.server.name)) continue;
      const trust = computeTrust(entry, deps);
      if (bestTrust === null || trust.score > bestTrust.score) {
        bestEntry = entry;
        bestTrust = trust;
      }
    }

    if (bestEntry === null || bestTrust === null) {
      skipped.push({ name: keyword, reason: "All results already installed or duplicated" });
      continue;
    }

    if (bestTrust.score < minScore) {
      skipped.push({
        name: bestEntry.server.name,
        reason: `Trust score ${bestTrust.score}/${bestTrust.maxPossible} is below minimum ${minScore}`,
      });
      continue;
    }

    try {
      await handleInstall(
        { name: bestEntry.server.name, client: args.client },
        deps,
        { entry: bestEntry, trust: bestTrust }
      );
      seenNames.add(bestEntry.server.name);
      installed.push({ name: bestEntry.server.name, trustScore: bestTrust });
    } catch (err) {
      skipped.push({
        name: bestEntry.server.name,
        reason: `Install failed: ${(err as Error).message}`,
      });
    }
  }

  const note = installed.length > 0
    ? "Restart your AI client to use the newly installed servers."
    : undefined;

  return { installed, skipped, ...(note ? { note } : {}) };
}

// ---------------------------------------------------------------------------
// mcpm_up — batch install from stack file
// ---------------------------------------------------------------------------

export async function handleMcpUp(
  args: { stackFile?: string; profile?: string; dryRun?: boolean },
  deps: ServerDeps
): Promise<{
  installed: string[];
  blocked: string[];
  failed: string[];
  skipped: string[];
  error?: string;
  note?: string;
}> {
  // Validate stackFile path (AI agent trust boundary). Zod defaults stackFile to
  // "mcpm.yaml", so the old `if (args.stackFile !== undefined)` guard was dead.
  // Enforce real containment unconditionally via resolved paths: path.resolve
  // normalizes Windows backslashes and "..", so this catches traversal and
  // absolute escapes that string-only checks miss.
  const stackFile = args.stackFile ?? "mcpm.yaml";
  const resolved = path.resolve(process.cwd(), stackFile);
  if (
    resolved !== process.cwd() &&
    !resolved.startsWith(process.cwd() + path.sep)
  ) {
    throw new Error("stackFile must be within the working directory");
  }
  // M3: the lexical check above catches "../" and absolute escapes, but NOT a
  // symlink that lives inside cwd yet points outside it — the file reader would
  // follow it (arbitrary out-of-tree read). Resolve the REAL path and re-check.
  // realpath throws ENOENT when the file does not exist yet; that's fine — handleUp
  // reports the missing file. A containment failure thrown inside the try is not
  // an ErrnoException, so the catch re-throws it.
  {
    const { realpath } = await import("node:fs/promises");
    try {
      const [realStack, realCwd] = await Promise.all([
        realpath(resolved),
        realpath(process.cwd()),
      ]);
      if (realStack !== realCwd && !realStack.startsWith(realCwd + path.sep)) {
        throw new Error("stackFile must be within the working directory");
      }
    } catch (err) {
      // ENOENT (no such file), ELOOP (circular symlink), and ENOTDIR (a path
      // component is a file) all mean "no real path to contain" — fall through and
      // let handleUp report the missing/invalid file. Re-throwing them would leak a
      // raw internal ErrnoException (with stack) to the untrusted caller. The
      // containment Error thrown just above has no `.code`, so it still propagates.
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (!["ENOENT", "ELOOP", "ENOTDIR"].includes(code)) throw err;
    }
  }

  const { handleUp } = await import("../commands/up.js");
  const { writeFile } = await import("fs/promises");
  const { handleLock } = await import("../commands/lock.js");
  const { RegistryClient } = await import("../registry/client.js");
  const { scanTier1: st1 } = await import("../scanner/tier1.js");
  const { checkScannerAvailable: csa, scanTier2: st2 } = await import("../scanner/tier2.js");
  const { computeTrustScore: cts } = await import("../scanner/trust-score.js");

  const client = new RegistryClient();
  const outputLines: string[] = [];
  // Fix A/D: structured per-server results from handleUp. Authoritative source
  // for categorization — emoji-scraping cannot distinguish blocked from failed.
  const records: Array<{ name: string; status: string }> = [];
  let thrownError: string | undefined;

  try {
    await handleUp(
      {
        stackFile,
        profile: args.profile,
        dryRun: args.dryRun,
        ci: true,
        yes: false,
        // MCP surface lockdown (fixes C, D & H1): never auto-read ambient
        // secrets from process.env OR the working-directory .env file, and never
        // install URL servers (they bypass the registry trust gate). All three
        // default to true on the CLI; the MCP (untrusted-caller) surface opts in
        // to the locked-down behavior.
        allowProcessEnv: false,
        allowUrlServers: false,
        allowEnvFile: false,
        // M2: the batch `up` path must honor the same non-overridable trust floor
        // the single-install MCP tool enforces (issue #24), so a low-trust server
        // an agent could not install via mcpm_install can't slip in via mcpm_up.
        minTrustFloor: HARD_TRUST_FLOOR,
      },
      {
        detectClients: deps.detectClients,
        getAdapter: deps.getAdapter,
        getPath: deps.getConfigPath,
        getServer: (name, version?) => client.getServer(name, version),
        scanTier1: st1,
        checkScannerAvailable: csa,
        scanTier2: (name) => st2(name),
        computeTrustScore: cts,
        runLock: async (stackFile) => {
          await handleLock(
            { stackFile },
            {
              getServerVersions: (name) => client.getServerVersions(name),
              getServer: (name, v?) => client.getServer(name, v),
              scanTier1: st1,
              checkScannerAvailable: csa,
              scanTier2: (name) => st2(name),
              computeTrustScore: cts,
              writeLockFile: (path, content) =>
                writeFile(path, content, { encoding: "utf-8", mode: 0o600 }),
              fetchNpmIntegrity: _fetchNpmIntegrity,
              output: (text) => outputLines.push(text),
            }
          );
        },
        // Issue #22: never auto-confirm on the MCP (no-human-in-loop) surface.
        // The previous `async () => true` blanket-approved every confirmation,
        // including strict-mode *removals* of servers not in mcpm.yaml — a
        // prompt-injected agent could silently mutate client configs. Refusing
        // confirmation here means destructive prompts are declined; the trust
        // policy still gates installs via checkTrustPolicy in handleUp.
        confirm: async () => false,
        promptEnvVar: async () => "",
        output: (text) => outputLines.push(text),
        fetchNpmIntegrity: _fetchNpmIntegrity,
        readPins: _readPins,
        recordResult: (r) => records.push(r),
      }
    );
  } catch (err) {
    // Fix A: handleUp throws on early/whole-batch failures (no clients, lock-file
    // creation failure, missing required env in CI, the summary "N could not be
    // installed" throw, etc.). The previous bare catch swallowed these into a
    // clean-looking empty result. Capture the message so the caller can never
    // mistake a thrown failure for success.
    thrownError = err instanceof Error ? err.message : String(err);
  }

  const installed: string[] = [];
  const blocked: string[] = [];
  const failed: string[] = [];
  const skipped: string[] = [];

  if (records.length > 0) {
    // Authoritative path (fix D, F.3/F.5): categorize from handleUp's typed
    // per-server statuses. Unlike emoji-scraping, this reliably separates
    // "blocked" (policy/URL-lockdown) from "failed".
    for (const r of records) {
      switch (r.status) {
        case "installed": installed.push(r.name); break;
        case "blocked": blocked.push(r.name); break;
        case "failed": failed.push(r.name); break;
        case "skipped":
        case "removed": skipped.push(r.name); break;
      }
    }
  } else {
    // Fallback for the no-record path (e.g. a throw before any server is
    // processed): preserve the original output-line parsing.
    for (const line of outputLines) {
      if (line.includes("\u2713")) installed.push(line.trim());
      else if (line.includes("\u2717") && line.includes("blocked")) blocked.push(line.trim());
      else if (line.includes("\u2717")) failed.push(line.trim());
      else if (line.includes("\u2022")) skipped.push(line.trim());
    }
  }

  // Fix A, refined for M1: a thrown handleUp failure MUST be signaled \u2014 but only
  // via the top-level `error` field (set in the return below). The previous
  // version pushed the error *message* into `failed`, which is contracted to hold
  // server NAMES; a consumer iterating it as names got a stray sentence. `error`
  // is the authoritative batch-failure signal; `failed` stays names-only (genuine
  // per-server failures are already recorded into it above via `records`).

  return {
    installed,
    blocked,
    failed,
    skipped,
    ...(thrownError !== undefined ? { error: thrownError } : {}),
    ...(installed.length > 0
      ? { note: "Restart your AI client to use the newly installed servers." }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Keyword extraction
// ---------------------------------------------------------------------------

const STOPWORDS = /\b(i need|set up|access|work with|connect to|a server that|a server for|to|the|a|an|my|for|and|with)\b/gi;

export function extractKeywords(description: string): string[] {
  const cleaned = description
    .toLowerCase()
    .replace(STOPWORDS, " ")
    .replace(/[,&]/g, " ");

  const tokens = cleaned
    .split(/\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 2);

  // If splitting produced too many tokens, use the full cleaned string
  if (tokens.length > 5) {
    return [cleaned.replace(/\s+/g, " ").trim()];
  }

  return tokens.length > 0 ? tokens : [description.trim()];
}

