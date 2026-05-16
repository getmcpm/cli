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
