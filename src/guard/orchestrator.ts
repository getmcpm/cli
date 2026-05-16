/**
 * Orchestration for `mcpm guard enable` / `disable` / `status` (v0.5.0).
 *
 * Walks detected clients, reads each config, computes the wrap / unwrap
 * transform, and applies via a two-phase pattern (Eng review F5.1):
 *
 *   Phase 1: read every adapter's current state + compute the new state.
 *            Validate the transform doesn't lose data.
 *   Phase 2: apply each adapter's replaceServer in sequence. Each adapter
 *            already does atomic write-then-rename + `.bak` discipline,
 *            so a partial failure leaves the unmodified clients untouched
 *            and the failed client recoverable from its `.bak`.
 *
 * Pure orchestration — no I/O outside the adapter calls.
 */

import { copyFile } from "node:fs/promises";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import { wrapEntry, unwrapEntry, isWrapped, type WrapContext } from "./wrap.js";

export interface ClientReport {
  readonly clientId: ClientId;
  /** Servers visited in this client's config. */
  readonly servers: ReadonlyArray<{
    readonly name: string;
    readonly status: "wrapped" | "unwrapped" | "skipped";
    readonly reason?: string;
  }>;
  readonly error?: string;
}

export interface EnableDisableSummary {
  readonly action: "enable" | "disable";
  readonly clients: readonly ClientReport[];
  readonly totalChanged: number;
  readonly totalSkipped: number;
  readonly errors: number;
}

export interface OrchestratorDeps {
  readonly detectClients: () => Promise<ClientId[]>;
  readonly getAdapter: (clientId: ClientId) => ConfigAdapter;
  readonly getConfigPath: (clientId: ClientId) => string;
  readonly wrapContext: WrapContext;
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

export function enableGuardAcrossClients(
  deps: OrchestratorDeps,
  filter?: { client?: ClientId; server?: string },
): Promise<EnableDisableSummary> {
  return runAcrossClients(deps, "enable", filter);
}

export function disableGuardAcrossClients(
  deps: OrchestratorDeps,
  filter?: { client?: ClientId; server?: string },
): Promise<EnableDisableSummary> {
  return runAcrossClients(deps, "disable", filter);
}

async function runAcrossClients(
  deps: OrchestratorDeps,
  action: "enable" | "disable",
  filter: { client?: ClientId; server?: string } | undefined,
): Promise<EnableDisableSummary> {
  const targetClients = await selectTargetClients(deps, filter?.client);

  // Phase 1: read all + compute plans (no writes yet).
  const plans = await Promise.all(
    targetClients.map((clientId) => planForClient(clientId, deps, action, filter?.server)),
  );

  // SECURITY F7: pre-batch snapshot of each touched client's config to
  // <config>.guard-<action>.bak before any replaceServer call. The per-write
  // .bak that replaceServer maintains gets overwritten by each successive
  // server in a multi-server client. The pre-batch snapshot gives users a
  // recovery point for the whole enable/disable operation. Best-effort —
  // we don't block on snapshot failures (e.g., file didn't exist yet).
  for (const plan of plans) {
    if (plan.transforms.length === 0) continue;
    const configPath = deps.getConfigPath(plan.clientId);
    await copyFile(configPath, `${configPath}.guard-${action}.bak`).catch(() => undefined);
  }

  // Phase 2: apply each plan (sequential — each adapter already uses
  // atomic write + .bak, so partial failures leave unmodified clients alone).
  const reports: ClientReport[] = [];
  for (const plan of plans) {
    reports.push(await applyPlan(plan, deps));
  }

  // SECURITY F9: surface a non-matching --server filter explicitly so the
  // operator sees the typo rather than getting a silent "0 changed" result.
  if (filter?.server !== undefined) {
    const matched = reports.some((r) => r.servers.some((s) => s.name === filter.server));
    if (!matched) {
      throw new Error(
        `--server "${filter.server}" not found in any detected client config. ` +
          `Run \`mcpm guard status\` to see available servers.`,
      );
    }
  }

  return summarize(action, reports);
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export interface StatusReport {
  readonly clients: readonly {
    readonly clientId: ClientId;
    readonly wrapped: number;
    readonly unwrapped: number;
    readonly servers: ReadonlyArray<{ name: string; wrapped: boolean }>;
    readonly error?: string;
  }[];
  readonly totalWrapped: number;
  readonly totalUnwrapped: number;
}

export async function statusAcrossClients(deps: OrchestratorDeps): Promise<StatusReport> {
  const targetClients = await deps.detectClients();
  const clients = await Promise.all(
    targetClients.map(async (clientId) => {
      try {
        const adapter = deps.getAdapter(clientId);
        const entries = await adapter.read(deps.getConfigPath(clientId));
        const servers = Object.entries(entries).map(([name, entry]) => ({
          name,
          wrapped: isWrapped(entry),
        }));
        return {
          clientId,
          wrapped: servers.filter((s) => s.wrapped).length,
          unwrapped: servers.filter((s) => !s.wrapped).length,
          servers,
        };
      } catch (err) {
        return {
          clientId,
          wrapped: 0,
          unwrapped: 0,
          servers: [],
          error: err instanceof Error ? err.message : String(err),
        };
      }
    }),
  );

  return {
    clients,
    totalWrapped: clients.reduce((sum, c) => sum + c.wrapped, 0),
    totalUnwrapped: clients.reduce((sum, c) => sum + c.unwrapped, 0),
  };
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async function selectTargetClients(
  deps: OrchestratorDeps,
  clientFilter: ClientId | undefined,
): Promise<ClientId[]> {
  const detected = await deps.detectClients();
  if (clientFilter === undefined) return detected;
  if (!detected.includes(clientFilter)) {
    throw new Error(
      `Client "${clientFilter}" not detected. Available: ${detected.join(", ") || "(none)"}`,
    );
  }
  return [clientFilter];
}

interface ClientPlan {
  readonly clientId: ClientId;
  readonly action: "enable" | "disable";
  readonly transforms: ReadonlyArray<{
    readonly name: string;
    readonly nextEntry: McpServerEntry;
  }>;
  readonly skipped: ReadonlyArray<{ readonly name: string; readonly reason: string }>;
  readonly readError?: string;
}

async function planForClient(
  clientId: ClientId,
  deps: OrchestratorDeps,
  action: "enable" | "disable",
  serverFilter: string | undefined,
): Promise<ClientPlan> {
  const adapter = deps.getAdapter(clientId);
  let entries: Record<string, McpServerEntry>;
  try {
    entries = await adapter.read(deps.getConfigPath(clientId));
  } catch (err) {
    return {
      clientId,
      action,
      transforms: [],
      skipped: [],
      readError: err instanceof Error ? err.message : String(err),
    };
  }

  const transforms: { name: string; nextEntry: McpServerEntry }[] = [];
  const skipped: { name: string; reason: string }[] = [];

  for (const [name, entry] of Object.entries(entries)) {
    if (serverFilter !== undefined && name !== serverFilter) continue;
    if (action === "enable") {
      if (isWrapped(entry)) {
        skipped.push({ name, reason: "already wrapped" });
        continue;
      }
      if (!entry.command) {
        skipped.push({ name, reason: "no command (HTTP-transport server; deferred to V2)" });
        continue;
      }
      transforms.push({ name, nextEntry: wrapEntry(name, entry, deps.wrapContext) });
    } else {
      if (!isWrapped(entry)) {
        skipped.push({ name, reason: "not wrapped" });
        continue;
      }
      const unwrapped = unwrapEntry(entry);
      if (unwrapped === null) {
        skipped.push({ name, reason: "wrap marker malformed; .bak restore may be required" });
        continue;
      }
      transforms.push({ name, nextEntry: unwrapped });
    }
  }

  return { clientId, action, transforms, skipped };
}

async function applyPlan(plan: ClientPlan, deps: OrchestratorDeps): Promise<ClientReport> {
  if (plan.readError) {
    return {
      clientId: plan.clientId,
      servers: [],
      error: plan.readError,
    };
  }

  const adapter = deps.getAdapter(plan.clientId);
  const configPath = deps.getConfigPath(plan.clientId);
  const servers: Array<{ name: string; status: "wrapped" | "unwrapped" | "skipped"; reason?: string }> = [];

  for (const { name, nextEntry } of plan.transforms) {
    try {
      await adapter.replaceServer(configPath, name, nextEntry);
      servers.push({ name, status: plan.action === "enable" ? "wrapped" : "unwrapped" });
    } catch (err) {
      servers.push({
        name,
        status: "skipped",
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  for (const skip of plan.skipped) {
    servers.push({ name: skip.name, status: "skipped", reason: skip.reason });
  }

  return { clientId: plan.clientId, servers };
}

function summarize(
  action: "enable" | "disable",
  reports: readonly ClientReport[],
): EnableDisableSummary {
  let totalChanged = 0;
  let totalSkipped = 0;
  let errors = 0;
  for (const report of reports) {
    if (report.error) errors++;
    for (const server of report.servers) {
      if (server.status === "wrapped" || server.status === "unwrapped") totalChanged++;
      else totalSkipped++;
    }
  }
  return { action, clients: reports, totalChanged, totalSkipped, errors };
}
