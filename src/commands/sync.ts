/**
 * `mcpm sync` command handler.
 *
 * A read-only, symmetric cross-client drift dashboard: for every server name it
 * shows which of the detected clients (Claude Desktop / Cursor / VS Code /
 * Windsurf) have it, which are missing it, and whether the clients that DO have
 * it agree on the server's shape. This is the N-client complement to `mcpm diff`
 * (installed-vs-stack, one direction).
 *
 * `--check` turns drift into a non-zero exit (2) for CI; `--json` emits the model.
 * Exit-code contract: 0 = in sync (or nothing to compare), 2 = drift found under
 * `--check`, 1 = error (reserved for thrown failures). Drift is therefore NEVER
 * signalled by throwing — the handler returns a flag the action maps to exit 2.
 *
 * The WRITE / convergence path (`--union`, `--from-client`) is intentionally out
 * of this slice; this command never mutates a config.
 *
 * Exports: handleSync(), registerSyncCommand().
 */

import Table from "cli-table3";
import type { ClientId } from "../config/paths.js";
import {
  buildDriftModel,
  collectClientStates,
  type DriftDeps,
  type DriftModel,
  type ServerDrift,
} from "../config/drift.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SyncOptions {
  json?: boolean;
}

export interface SyncDeps extends DriftDeps {
  output: (text: string) => void;
}

export interface SyncResult {
  readonly model: DriftModel;
  /** True iff at least one server is absent somewhere or has a shape conflict. */
  readonly drift: boolean;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleSync(options: SyncOptions, deps: SyncDeps): Promise<SyncResult> {
  const states = await collectClientStates(deps);
  const model = buildDriftModel(states);
  const drift = model.drifted > 0;

  if (options.json) {
    deps.output(JSON.stringify(model, null, 2));
    return { model, drift };
  }

  renderDashboard(model, deps.output);
  return { model, drift };
}

/**
 * Map a result to the process exit code: 2 when `--check` is set AND drift was
 * found (the CI gate), else 0. A thrown failure maps to 1 in the action wrapper;
 * drift is never an error. Pure + exported so the headline `--check` contract is
 * unit-testable without spawning the process.
 */
export function exitCodeFor(result: SyncResult, check: boolean | undefined): number {
  return check && result.drift ? 2 : 0;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function cell(server: ServerDrift, clientId: ClientId): string {
  if (!server.present.includes(clientId)) return "·"; // absent
  if (server.conflict) return "≠"; // present but the clients disagree on shape
  return "✓";
}

function renderDashboard(model: DriftModel, output: (text: string) => void): void {
  if (model.clients.length === 0) {
    output("No client configs found. Install a server first (e.g. `mcpm install <name>`).");
    return;
  }
  if (model.clients.length === 1) {
    output(
      `Only 1 client has a readable config (${model.clients[0]}) — nothing to compare across clients.`,
    );
    return;
  }
  if (model.servers.length === 0) {
    output(`${model.clients.length} clients detected, but no servers configured — nothing to compare.`);
    return;
  }

  const table = new Table({ head: ["server", ...model.clients], style: { head: [], border: [] } });
  for (const server of model.servers) {
    table.push([server.name, ...model.clients.map((c) => cell(server, c))]);
  }
  output(table.toString());
  output("  legend: ✓ present · absent ≠ shape conflict");

  const conflicts = model.servers.filter((s) => s.conflict);
  if (conflicts.length > 0) {
    output("");
    for (const s of conflicts) {
      output(`  ≠ ${s.name}: differs on ${s.conflictFields!.join(", ")} (across ${s.present.join(", ")})`);
    }
  }

  const missing = model.servers.filter((s) => s.absent.length > 0);
  if (missing.length > 0) {
    output("");
    for (const s of missing) {
      output(`  · ${s.name}: in ${s.present.join(", ")}; missing in ${s.absent.join(", ")}`);
    }
  }

  output("");
  const conflictWord = conflicts.length === 1 ? "conflict" : "conflicts";
  // `inSync + drifted` partitions the servers; the parenthetical sub-counts can
  // overlap (a server can be both missing-somewhere and conflicting-elsewhere).
  output(
    `${model.inSync} in sync · ${model.drifted} drifted (${missing.length} missing in ≥1 client, ${conflicts.length} shape ${conflictWord})`,
  );
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import { detectInstalledClients } from "../config/detector.js";
import { getConfigPath } from "../config/paths.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { stdoutOutput } from "../utils/output.js";

export function registerSyncCommand(program: Command): void {
  program
    .command("sync")
    .description("Show cross-client config drift across all detected clients (read-only)")
    .option("--check", "exit with code 2 if any drift is found (CI gate)")
    .option("--json", "output the drift model as JSON")
    .action(async (opts: { check?: boolean; json?: boolean }) => {
      const chalk = (await import("chalk")).default;
      try {
        const result = await handleSync(
          { json: opts.json },
          {
            detectClients: detectInstalledClients,
            getAdapter: getAdapterDefault,
            getPath: getConfigPath,
            output: stdoutOutput,
          },
        );
        const code = exitCodeFor(result, opts.check);
        if (code !== 0) process.exit(code);
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
