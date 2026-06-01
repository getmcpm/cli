/**
 * CLI handlers for `mcpm guard enable / disable / status` (v0.5.0).
 *
 * Glue between Commander and the orchestrator. Format-only — no
 * filesystem I/O outside the orchestrator's adapter calls.
 */

import type { ClientId } from "../config/paths.js";
import { getConfigPath } from "../config/paths.js";
import { detectInstalledClients } from "../config/detector.js";
import { getAdapter } from "../config/adapters/factory.js";
import {
  enableGuardAcrossClients,
  disableGuardAcrossClients,
  statusAcrossClients,
  type ClientReport,
  type EnableDisableSummary,
  type StatusReport,
  type OrchestratorDeps,
} from "./orchestrator.js";
import { defaultWrapContext } from "./wrap.js";
import { placeholderEnvKeys } from "../store/keychain.js";

const CLIENT_LABELS: Record<ClientId, string> = {
  "claude-desktop": "Claude Desktop",
  cursor: "Cursor",
  vscode: "VS Code",
  windsurf: "Windsurf",
};

// Re-export the shared sanitizer under the local name (security review Step 7 F5:
// the cli.ts local version missed ESC + OSC; share the run-inner.ts one instead).
import { sanitizeForTerminal as sanitize } from "./sanitize.js";

interface CommandIO {
  readonly write: (s: string) => void;
}

function buildDeps(): OrchestratorDeps {
  return {
    detectClients: detectInstalledClients,
    getAdapter,
    getConfigPath,
    wrapContext: defaultWrapContext(),
  };
}

// ---------------------------------------------------------------------------
// enable
// ---------------------------------------------------------------------------

export interface EnableOpts extends CommandIO {
  readonly client?: ClientId;
  readonly server?: string;
  readonly dryRun?: boolean;
}

export async function runEnableCommand(opts: EnableOpts): Promise<void> {
  const deps = buildDeps();

  if (opts.dryRun === true) {
    const status = await statusAcrossClients(deps);
    opts.write("Dry-run: planned wraps\n");
    for (const c of status.clients) {
      if (opts.client !== undefined && c.clientId !== opts.client) continue;
      const candidates = c.servers.filter((s) => {
        if (opts.server !== undefined && s.name !== opts.server) return false;
        return !s.wrapped;
      });
      opts.write(`  ${CLIENT_LABELS[c.clientId]}: would wrap ${candidates.length} server(s)\n`);
      for (const s of candidates) opts.write(`    + ${s.name}\n`);
    }
    return;
  }

  const summary = await enableGuardAcrossClients(deps, opts);
  printEnableDisable(summary, opts);
  printRestartReminder(opts);
}

// ---------------------------------------------------------------------------
// disable
// ---------------------------------------------------------------------------

export interface DisableOpts extends CommandIO {
  readonly client?: ClientId;
  readonly server?: string;
}

export async function runDisableCommand(opts: DisableOpts): Promise<void> {
  const deps = buildDeps();
  const summary = await disableGuardAcrossClients(deps, opts);
  printEnableDisable(summary, opts);
  printRestartReminder(opts);
  await warnUnresolvablePlaceholders(opts);
}

/**
 * After disabling guard, any server config that referenced a secret via a
 * `mcpm:keychain:…` placeholder is now launched directly by the IDE — which
 * cannot resolve the placeholder. Warn (read-only) so the user isn't surprised
 * by a server that receives the literal placeholder and fails to start. We
 * never silently rewrite plaintext into the config (security-first).
 *
 * Respects the disable command's `--client`/`--server` filters, so it only
 * checks the subset that was just disabled. Purely advisory: it never throws,
 * so it cannot turn an otherwise-successful disable into a failure.
 */
async function warnUnresolvablePlaceholders(opts: DisableOpts): Promise<void> {
  let clients: ClientId[];
  try {
    clients = await detectInstalledClients();
  } catch {
    return;
  }

  const affected: Array<{ client: ClientId; server: string; keys: string[] }> = [];

  for (const clientId of clients) {
    if (opts.client !== undefined && clientId !== opts.client) continue;
    let entries;
    try {
      entries = await getAdapter(clientId).read(getConfigPath(clientId));
    } catch (err) {
      // A missing config is expected; surface anything else (permissions,
      // malformed JSON) rather than silently skipping it.
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        opts.write(
          `  (could not read ${CLIENT_LABELS[clientId]} config: ${sanitize((err as Error).message)})\n`,
        );
      }
      continue;
    }
    for (const [name, entry] of Object.entries(entries)) {
      if (opts.server !== undefined && name !== opts.server) continue;
      const keys = placeholderEnvKeys(entry.env);
      if (keys.length > 0) affected.push({ client: clientId, server: name, keys });
    }
  }

  if (affected.length === 0) return;

  opts.write(
    "\n\x1b[33mwarning: these servers reference encrypted secrets " +
      "(mcpm:keychain:…) that only resolve while mcpm guard is enabled. Without " +
      "guard they receive the literal placeholder and will fail to start:\x1b[0m\n",
  );
  for (const a of affected) {
    opts.write(
      `  - ${sanitize(a.server)} (${CLIENT_LABELS[a.client]}): ${formatAffectedKeys(a.keys)}\n`,
    );
  }
  opts.write(
    "Re-enable with `mcpm guard enable`, or replace those env values with plaintext.\n",
  );
}

/**
 * Sanitize + join the affected env-key names for the disable warning.
 *
 * The explicit arrow is load-bearing: `keys.map(sanitize)` would pass the array
 * index as `sanitizeForTerminal`'s `maxLen`, truncating the first key to "…",
 * the second to one char, etc. Wrapping ensures each key is passed alone.
 */
export function formatAffectedKeys(keys: readonly string[]): string {
  return keys.map((k) => sanitize(k)).join(", ");
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

export interface StatusOpts extends CommandIO {
  /** When provided, called instead of writing "no clients detected". */
  readonly helpFallback?: () => void;
}

export async function runStatusCommand(opts: StatusOpts): Promise<void> {
  const deps = buildDeps();
  const status = await statusAcrossClients(deps);
  if (status.clients.length === 0) {
    if (opts.helpFallback) {
      opts.helpFallback();
      return;
    }
    opts.write("No MCP clients detected.\n");
    return;
  }
  if (status.totalWrapped === 0 && opts.helpFallback) {
    opts.helpFallback();
    return;
  }
  printStatus(status, opts);
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function printEnableDisable(summary: EnableDisableSummary, opts: CommandIO): void {
  const verb = summary.action === "enable" ? "wrapped" : "unwrapped";
  opts.write(`mcpm guard ${summary.action}: ${summary.totalChanged} ${verb}, `);
  opts.write(`${summary.totalSkipped} skipped, ${summary.errors} error(s)\n\n`);
  for (const client of summary.clients) {
    printClientReport(client, opts);
  }
}

function printClientReport(report: ClientReport, opts: CommandIO): void {
  opts.write(`  ${CLIENT_LABELS[report.clientId]}:\n`);
  if (report.error !== undefined) {
    opts.write(`    error: ${sanitize(report.error)}\n`);
    return;
  }
  if (report.servers.length === 0) {
    opts.write(`    (no servers)\n`);
    return;
  }
  for (const s of report.servers) {
    const symbol = s.status === "wrapped" ? "+" : s.status === "unwrapped" ? "-" : "·";
    const reason = s.reason !== undefined ? ` (${sanitize(s.reason)})` : "";
    opts.write(`    ${symbol} ${sanitize(s.name)}${reason}\n`);
  }
}

function printStatus(status: StatusReport, opts: CommandIO): void {
  opts.write(`mcpm guard status: ${status.totalWrapped} wrapped, ${status.totalUnwrapped} unwrapped\n\n`);
  for (const c of status.clients) {
    opts.write(`  ${CLIENT_LABELS[c.clientId]}: ${c.wrapped} wrapped / ${c.unwrapped} unwrapped\n`);
    if (c.error !== undefined) {
      opts.write(`    error: ${sanitize(c.error)}\n`);
      continue;
    }
    for (const s of c.servers) {
      opts.write(`    ${s.wrapped ? "+" : "·"} ${sanitize(s.name)}\n`);
    }
  }
}

function printRestartReminder(opts: CommandIO): void {
  opts.write(
    "\n→ Restart your IDE (Claude Desktop / Cursor / VS Code / Windsurf) " +
      "for changes to take effect.\n",
  );
}

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

export interface CleanupOpts extends CommandIO {
  readonly apply: boolean;
}

export async function runCleanupCommand(opts: CleanupOpts): Promise<void> {
  const deps = buildDeps();
  const status = await statusAcrossClients(deps);

  // Collect the union of server names seen across detected client configs.
  // Anything pinned that doesn't appear here is an orphan pin entry.
  const installedServerNames = new Set<string>();
  for (const c of status.clients) {
    for (const s of c.servers) installedServerNames.add(sanitize(s.name));
  }

  const { readPins, writePins, clearServerPins } = await import("./pins.js");
  const pins = await readPins().catch(() => null);
  const orphanPinned: string[] = [];
  if (pins !== null) {
    for (const serverName of Object.keys(pins.servers)) {
      if (!installedServerNames.has(serverName)) orphanPinned.push(serverName);
    }
  }

  // Orphan wrapped entries: servers wrapped in some client config but whose
  // original binary is no longer reachable (v0.5.0 simplification: we can't
  // cheaply check binary reachability; report wraps that reference a
  // command name not present in any other client's UNWRAPPED entries).
  // Conservative: skip for v0.5.0, report only pin orphans.

  if (orphanPinned.length === 0) {
    opts.write("mcpm guard cleanup: nothing to prune (0 orphan pins, 0 orphan wraps).\n");
    return;
  }

  opts.write(`mcpm guard cleanup: ${orphanPinned.length} orphan pin entr${orphanPinned.length === 1 ? "y" : "ies"} found:\n`);
  for (const s of orphanPinned) opts.write(`  - ${s}\n`);

  if (!opts.apply) {
    opts.write("\nDry run. Re-run with --yes to prune.\n");
    return;
  }

  if (pins === null) return;
  let next = pins;
  for (const serverName of orphanPinned) next = clearServerPins(next, serverName);
  await writePins(next);
  opts.write(`\nPruned ${orphanPinned.length} orphan pin entr${orphanPinned.length === 1 ? "y" : "ies"} from ~/.mcpm/pins.json.\n`);
}
