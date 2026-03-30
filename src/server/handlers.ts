/**
 * MCP tool handlers for mcpm serve.
 *
 * Each handler wraps existing mcpm logic and returns structured JSON.
 * All dependencies are injectable for testability.
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { extractRegistryMeta } from "../utils/format-trust.js";

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

export async function handleInstall(
  args: { name: string; client?: string },
  deps: ServerDeps
): Promise<object> {
  const entry = await deps.registryGetServer(args.name);
  const trust = computeTrust(entry, deps);
  const clients = await resolveClients(args.client, deps);

  const { resolveInstallEntry } = await import("../commands/install.js");

  const installedClients: ClientId[] = [];
  for (const clientId of clients) {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getConfigPath(clientId);
    const mcpEntry = resolveInstallEntry(entry, clientId);
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
      const command = formatCommand(entry);
      servers.push({ name, client: clientId, command });
    }
  }

  return { servers };
}

export async function handleRemove(
  args: { name: string; client?: string },
  deps: ServerDeps
): Promise<object> {
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

  // Check runtimes
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const execFileAsync = promisify(execFile);

  const runtimes: Array<{ name: string; available: boolean }> = [];
  for (const cmd of ["npx", "uvx", "docker"]) {
    try {
      await execFileAsync(cmd, ["--version"], { timeout: 5000 });
      runtimes.push({ name: cmd, available: true });
    } catch {
      runtimes.push({ name: cmd, available: false });
    }
  }

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

  const installed: Array<{ name: string; trustScore: TrustScore }> = [];
  const skipped: Array<{ name: string; reason: string }> = [];

  const seenNames = new Set<string>();

  for (const keyword of keywords) {
    const entries = await deps.registrySearch(keyword, 5);
    if (entries.length === 0) {
      skipped.push({ name: keyword, reason: `No servers found for "${keyword}"` });
      continue;
    }

    // Pick best by trust score, skip duplicates
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

    if (bestTrust.score < args.minTrustScore) {
      skipped.push({
        name: bestEntry.server.name,
        reason: `Trust score ${bestTrust.score}/${bestTrust.maxPossible} is below minimum ${args.minTrustScore}`,
      });
      continue;
    }

    // Install
    try {
      await handleInstall({ name: bestEntry.server.name, client: args.client }, deps);
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

// ---------------------------------------------------------------------------
// Format helper
// ---------------------------------------------------------------------------

function formatCommand(entry: McpServerEntry): string {
  if ("url" in entry && typeof entry.url === "string") return entry.url;
  if ("command" in entry && typeof entry.command === "string") {
    const args = "args" in entry && Array.isArray(entry.args) ? entry.args : [];
    return `${entry.command} ${args.join(" ")}`.trim();
  }
  return "unknown";
}
