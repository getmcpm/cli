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
import { wrapEntry, unwrapEntry, isWrapped, type WrapContext, type ConfineMarker } from "./wrap.js";

export interface ClientReport {
  readonly clientId: ClientId;
  /** Servers visited in this client's config. */
  readonly servers: ReadonlyArray<{
    readonly name: string;
    // "unguarded" (H9): a URL/HTTP-transport server the user CONSENTED to run
    // without the relay. It is NOT "wrapped" (no relay covers it) and NOT a
    // silent "skipped" — a distinct, visible status so the operator sees that a
    // server runs with zero runtime inspection.
    readonly status: "wrapped" | "unwrapped" | "skipped" | "unguarded";
    readonly reason?: string;
  }>;
  readonly error?: string;
}

export interface EnableDisableSummary {
  readonly action: "enable" | "disable";
  readonly clients: readonly ClientReport[];
  readonly totalChanged: number;
  readonly totalSkipped: number;
  // H9: consented-'unguarded' servers counted DISTINCTLY from totalSkipped.
  // Running unguarded is an explicit security-posture decision, not "not acted
  // on" — folding it into "skipped" understates that a server runs with zero
  // runtime inspection.
  readonly totalUnguarded: number;
  readonly errors: number;
}

export interface OrchestratorDeps {
  readonly detectClients: () => Promise<ClientId[]>;
  readonly getAdapter: (clientId: ClientId) => ConfigAdapter;
  readonly getConfigPath: (clientId: ClientId) => string;
  readonly wrapContext: WrapContext;
  /**
   * F1: per-server confine info to embed into the wrap marker at enable time,
   * keyed by server name. Built by the cli layer (derive + store the profile,
   * then map name → {profileHash, required}). A name absent from the map is
   * wrapped without confinement (today's behavior). Only consulted on `enable`.
   */
  readonly confineMarkers?: ReadonlyMap<string, ConfineMarker>;
  /**
   * H9: per-invocation consent to run URL/HTTP-transport (unwrappable) servers
   * UNGUARDED. Set from the `--allow-unguarded` flag. When absent/false, a url
   * server is permitted only if the persistent consent store already lists it.
   */
  readonly allowUnguarded?: boolean;
  /**
   * H9: read the persistent set of server names previously consented to run
   * unguarded. Injectable for tests; defaults to the real store at the CLI
   * boundary. When omitted, no server is treated as previously-consented.
   */
  readonly readUnguardedConsent?: () => Promise<string[]>;
  /**
   * H9: record (union into the store) the server names consented to run
   * unguarded this run. Injectable for tests; defaults to the real store.
   * Called only when at least one server is newly consented.
   */
  readonly recordUnguardedConsent?: (names: readonly string[]) => Promise<void>;
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

  // H9: pre-read the persistent unguarded-consent set once so every client's
  // plan can recognise a previously-consented url server without per-invocation
  // `--allow-unguarded`. Only relevant on enable (disable never wraps).
  const consentedUnguarded =
    action === "enable" && deps.readUnguardedConsent ? await deps.readUnguardedConsent() : [];

  // Phase 1: read all + compute plans (no writes yet).
  const plans = await Promise.all(
    targetClients.map((clientId) =>
      planForClient(clientId, deps, action, filter?.server, consentedUnguarded),
    ),
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

  // H9: persist consent for any server newly consented this run (a NEW url
  // server not already in the store). Union into the store; the warn-once
  // anti-rubber-stamp logic lives at the CLI layer (cli.ts) which compares the
  // current set against the previous one. Recording is best-effort and never
  // turns an otherwise-successful enable into a failure.
  if (deps.recordUnguardedConsent) {
    const nowUnguarded = [
      ...new Set(
        reports.flatMap((r) => r.servers.filter((s) => s.status === "unguarded").map((s) => s.name)),
      ),
    ];
    const previous = new Set(consentedUnguarded);
    const newlyConsented = nowUnguarded.filter((n) => !previous.has(n));
    if (newlyConsented.length > 0) {
      await deps.recordUnguardedConsent(newlyConsented).catch(() => undefined);
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
    // H9: `unguarded` is true for a URL/HTTP-transport server (no command) that
    // the relay cannot wrap. Surfaced distinctly so status output never implies
    // an unwrappable server is "just unwrapped" (a coverage gap, not a toggle).
    readonly servers: ReadonlyArray<{ name: string; wrapped: boolean; unguarded: boolean }>;
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
          // A non-stdio (url-transport) entry has no command — it cannot be
          // wrapped, so even when "not wrapped" it is specifically UNGUARDED.
          unguarded: !isWrapped(entry) && !entry.command,
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
  /** H9: url servers the user CONSENTED to run unguarded (reported visibly). */
  readonly unguarded: ReadonlyArray<{ readonly name: string; readonly reason: string }>;
  readonly readError?: string;
}

async function planForClient(
  clientId: ClientId,
  deps: OrchestratorDeps,
  action: "enable" | "disable",
  serverFilter: string | undefined,
  consentedUnguarded: readonly string[],
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
      unguarded: [],
      readError: err instanceof Error ? err.message : String(err),
    };
  }

  const transforms: { name: string; nextEntry: McpServerEntry }[] = [];
  const skipped: { name: string; reason: string }[] = [];
  const unguarded: { name: string; reason: string }[] = [];
  const consentedSet = new Set(consentedUnguarded);

  for (const [name, entry] of Object.entries(entries)) {
    if (serverFilter !== undefined && name !== serverFilter) continue;
    if (action === "enable") {
      if (isWrapped(entry)) {
        skipped.push({ name, reason: "already wrapped" });
        continue;
      }
      if (!entry.command) {
        // H9: a URL/HTTP-transport server has no stdio process to wrap, so the
        // relay can give it ZERO runtime inspection. DENY by default; permit
        // only with explicit informed consent (`--allow-unguarded` this run, or
        // a name already in the persistent consent store). Even when consented
        // it CANNOT be wrapped (no relay) — it stays out of `transforms` and is
        // reported with a distinct `unguarded` status, never silently dropped.
        if (deps.allowUnguarded === true || consentedSet.has(name)) {
          unguarded.push({
            name,
            reason:
              "unguarded (consented) — runs WITHOUT runtime inspection; this grants " +
              "consent, it does not add protection. The only true fix is a streamable-HTTP " +
              "relay (not yet implemented).",
          });
        } else {
          skipped.push({
            name,
            reason:
              "DENIED: URL/HTTP-transport server runs UNGUARDED — no runtime inspection is " +
              "possible (the guard relay only wraps stdio servers). Re-run `mcpm guard enable " +
              "--allow-unguarded` to permit it without protection.",
          });
        }
        continue;
      }
      transforms.push({
        name,
        nextEntry: wrapEntry(name, entry, deps.wrapContext, deps.confineMarkers?.get(name)),
      });
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

  return { clientId, action, transforms, skipped, unguarded };
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
  const servers: Array<{
    name: string;
    status: "wrapped" | "unwrapped" | "skipped" | "unguarded";
    reason?: string;
  }> = [];

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

  // H9: consented-unguarded servers are reported with a distinct status (no
  // config write — there is no relay to wrap them with).
  for (const u of plan.unguarded) {
    servers.push({ name: u.name, status: "unguarded", reason: u.reason });
  }

  return { clientId: plan.clientId, servers };
}

function summarize(
  action: "enable" | "disable",
  reports: readonly ClientReport[],
): EnableDisableSummary {
  let totalChanged = 0;
  let totalSkipped = 0;
  let totalUnguarded = 0;
  let errors = 0;
  for (const report of reports) {
    if (report.error) errors++;
    for (const server of report.servers) {
      if (server.status === "wrapped" || server.status === "unwrapped") totalChanged++;
      else if (server.status === "unguarded") totalUnguarded++;
      else totalSkipped++;
    }
  }
  return { action, clients: reports, totalChanged, totalSkipped, totalUnguarded, errors };
}
