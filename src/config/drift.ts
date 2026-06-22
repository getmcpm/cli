/**
 * Cross-client config-drift model (pure, injectable).
 *
 * `mcpm diff` answers "installed vs declared stack" in ONE direction. This module
 * answers the symmetric N-client question: for every server name, which clients
 * have it, which are missing it, and do the clients that DO have it agree on the
 * server's shape? It is the shared core behind `mcpm sync --check` and the doctor
 * "Cross-client" section.
 *
 * Design notes:
 * - Read-only. No writes, no registry/lock/network — it only reads client configs
 *   (the collect loop mirrors diff.ts:76-93 / export.ts).
 * - `buildDriftModel` is pure and takes already-collected `ClientState[]` so the
 *   doctor command can feed it the reads it already did (no double I/O).
 * - Conflict comparison is over command + ordered args + env KEY set + url +
 *   header KEY set. It NEVER compares env / header VALUES — those are secrets, and
 *   two clients legitimately hold the same key with a per-machine value.
 *
 * Exports: DriftDeps, ClientState, ServerDrift, DriftModel, collectClientStates,
 * buildDriftModel.
 */

import type { ClientId } from "./paths.js";
import type { ConfigAdapter, McpServerEntry } from "./adapters/index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DriftDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "read">;
  getPath: (clientId: ClientId) => string;
}

/** A single client's full set of MCP server entries (one successful read). */
export interface ClientState {
  readonly clientId: ClientId;
  readonly servers: Record<string, McpServerEntry>;
}

export interface ServerDrift {
  readonly name: string;
  /** Clients (with readable configs) that declare this server. */
  readonly present: readonly ClientId[];
  /** Clients (with readable configs) that lack this server. */
  readonly absent: readonly ClientId[];
  /** True when the `present` clients disagree on the server's shape. */
  readonly conflict: boolean;
  /** Which fields diverge among the `present` clients (only when conflict). */
  readonly conflictFields?: readonly string[];
}

export interface DriftModel {
  /** Clients considered — those whose config was readable. Sorted. */
  readonly clients: readonly ClientId[];
  /** One entry per distinct server name, sorted by name. */
  readonly servers: readonly ServerDrift[];
  /** Servers present in every considered client with no shape conflict. */
  readonly inSync: number;
  /** Servers with at least one absence or a shape conflict. */
  readonly drifted: number;
}

// ---------------------------------------------------------------------------
// Collection (I/O)
// ---------------------------------------------------------------------------

/**
 * Read each detected client's config into a `ClientState`. Clients whose config
 * is unreadable (missing / malformed) are skipped — never throws — so a single
 * broken config can't blind the whole cross-client view (same posture as
 * `diff` / `export`).
 */
export async function collectClientStates(deps: DriftDeps): Promise<ClientState[]> {
  const clients = await deps.detectClients();
  const states: ClientState[] = [];
  for (const clientId of clients) {
    try {
      const servers = await deps.getAdapter(clientId).read(deps.getPath(clientId));
      states.push({ clientId, servers });
    } catch {
      // Skip unreadable clients (missing or malformed config).
    }
  }
  return states;
}

// ---------------------------------------------------------------------------
// Drift model (pure)
// ---------------------------------------------------------------------------

/**
 * Per-field canonical projection used for conflict detection. Each value is a
 * stable string; two entries conflict on a field iff their projected strings
 * differ. Deliberately excludes env / header VALUES (secrets) and the per-client
 * `disabled` flag (an intentional per-client toggle, not a definition drift).
 */
function fieldProjection(entry: McpServerEntry): Record<string, string> {
  return {
    command: entry.command ?? "",
    args: JSON.stringify(entry.args ?? []),
    "env keys": JSON.stringify(Object.keys(entry.env ?? {}).sort()),
    url: entry.url ?? "",
    "header keys": JSON.stringify(Object.keys(entry.headers ?? {}).sort()),
  };
}

const COMPARED_FIELDS = ["command", "args", "env keys", "url", "header keys"] as const;

/** Fields on which the given entries (≥1) disagree. Empty ⇒ all identical. */
function divergingFields(entries: readonly McpServerEntry[]): string[] {
  const projections = entries.map(fieldProjection);
  return COMPARED_FIELDS.filter((field) => {
    const distinct = new Set(projections.map((p) => p[field]));
    return distinct.size > 1;
  });
}

export function buildDriftModel(states: readonly ClientState[]): DriftModel {
  const clients = states.map((s) => s.clientId).sort();

  // Gather, per server name, the clients that declare it and their entries.
  const byName = new Map<string, Array<{ clientId: ClientId; entry: McpServerEntry }>>();
  for (const { clientId, servers } of states) {
    for (const [name, entry] of Object.entries(servers)) {
      const list = byName.get(name) ?? [];
      list.push({ clientId, entry });
      byName.set(name, list);
    }
  }

  const servers: ServerDrift[] = [];
  for (const name of [...byName.keys()].sort()) {
    const holders = byName.get(name)!;
    const present = holders.map((h) => h.clientId).sort();
    const presentSet = new Set(present);
    const absent = clients.filter((c) => !presentSet.has(c));

    const fields = holders.length > 1 ? divergingFields(holders.map((h) => h.entry)) : [];
    const conflict = fields.length > 0;

    servers.push({
      name,
      present,
      absent,
      conflict,
      ...(conflict ? { conflictFields: fields } : {}),
    });
  }

  const drifted = servers.filter((s) => s.absent.length > 0 || s.conflict).length;
  return { clients, servers, inSync: servers.length - drifted, drifted };
}
