/**
 * CLI handlers for `mcpm guard enable / disable / status` (v0.5.0).
 *
 * Glue between Commander and the orchestrator. Format-only — no
 * filesystem I/O outside the orchestrator's adapter calls.
 */

import chalk from "chalk";
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
import os from "node:os";
import { defaultWrapContext, isWrapped, type ConfineMarker } from "./wrap.js";
import { deriveDefaultProfile } from "./confine/derive.js";
import {
  readConfineStore,
  writeConfineStore,
  withProfile,
  confineSandboxRoot,
} from "./confine/store.js";
import { hashConfineProfile, emptyConfineStore } from "./confine/profile.js";
import { isConfineBackendAvailable } from "./confine/apply.js";
import { SANDBOX_EXEC_PATH } from "./confine/backend-macos.js";
import { placeholderEnvKeys } from "../store/keychain.js";
import {
  readUnguardedConsent,
  writeUnguardedConsent,
  mergeUnguarded,
  isNewUnguarded,
} from "./unguarded.js";

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

function buildDeps(extra: Partial<OrchestratorDeps> = {}): OrchestratorDeps {
  return {
    detectClients: detectInstalledClients,
    getAdapter,
    getConfigPath,
    wrapContext: defaultWrapContext(),
    readUnguardedConsent,
    recordUnguardedConsent: async (names) => {
      // Union the newly-consented names into the persistent store.
      const previous = await readUnguardedConsent();
      await writeUnguardedConsent(mergeUnguarded(previous, names));
    },
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// enable
// ---------------------------------------------------------------------------

export interface EnableOpts extends CommandIO {
  readonly client?: ClientId;
  readonly server?: string;
  readonly dryRun?: boolean;
  /** H9: `--allow-unguarded` — consent to run url servers without the relay. */
  readonly allowUnguarded?: boolean;
  /** F1: `--confine` — enroll wrapped stdio servers in OS confinement (v1: standard). */
  readonly confine?: "standard" | "off";
}

export async function runEnableCommand(opts: EnableOpts): Promise<void> {
  // H9: capture the previous consent set BEFORE the run so we can warn-once
  // (full UNGUARDED warning only when the set GAINS a server — additions
  // re-warn; removals/unchanged stay quiet — anti-rubber-stamp, §5 H9).
  const previousConsented = await readUnguardedConsent();

  if (opts.dryRun === true) {
    const deps = buildDeps({ allowUnguarded: opts.allowUnguarded });
    const status = await statusAcrossClients(deps);
    const confineNote = opts.confine === "standard" ? " (with OS confinement)" : "";
    opts.write(`Dry-run: planned wraps${confineNote}\n`);
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

  // F1: when confining, derive+store each target server's profile ONCE and build
  // the name→marker map BEFORE the orchestrator runs, so the same content hash is
  // embedded across every client that wraps that server.
  const confineMarkers =
    opts.confine === "standard"
      ? await computeConfineMarkers({ server: opts.server, write: opts.write })
      : undefined;

  const deps = buildDeps({ allowUnguarded: opts.allowUnguarded, confineMarkers });
  const summary = await enableGuardAcrossClients(deps, opts);
  printEnableDisable(summary, opts);
  printUnguardedWarning(summary, previousConsented, opts);
  if (confineMarkers !== undefined) printConfineNotice(confineMarkers, opts);
  printRestartReminder(opts);
}

// ---------------------------------------------------------------------------
// F1 confine: marker computation + doctor
// ---------------------------------------------------------------------------

export interface ConfineComputeOpts {
  readonly server?: string;
  readonly net?: "all" | "none";
  readonly requireConfine?: boolean;
  readonly write: (s: string) => void;
}

/**
 * Derive + persist a ConfineProfile for every unwrapped STDIO server that
 * `enable` will wrap (respecting `--server`), returning a name→marker map for the
 * orchestrator to embed. Each server is derived ONCE (a single `capturedAt`) so
 * its content hash is identical across every client that wraps it — otherwise the
 * spawn-time verify (decide.ts row 3) would mismatch and fail closed. Merges into
 * the existing store so other enrolled servers are preserved.
 */
export async function computeConfineMarkers(
  opts: ConfineComputeOpts,
): Promise<ReadonlyMap<string, ConfineMarker>> {
  const markers = new Map<string, ConfineMarker>();

  let clients: ClientId[];
  try {
    clients = await detectInstalledClients();
  } catch {
    return markers;
  }

  // De-dupe by name across clients; url/HTTP (no command) and already-wrapped
  // servers are not wrapped by `enable`, so they need no confine profile.
  const targets = new Map<string, { command: string; args?: readonly string[] }>();
  for (const clientId of clients) {
    let entries;
    try {
      entries = await getAdapter(clientId).read(getConfigPath(clientId));
    } catch {
      continue; // missing/unreadable config — skip (mirrors enable's read handling)
    }
    for (const [name, entry] of Object.entries(entries)) {
      if (opts.server !== undefined && name !== opts.server) continue;
      if (!entry.command || isWrapped(entry)) continue;
      if (!targets.has(name)) targets.set(name, { command: entry.command, args: entry.args });
    }
  }
  if (targets.size === 0) return markers;

  let store;
  try {
    store = await readConfineStore();
  } catch (err) {
    opts.write(
      `⚠ could not read ~/.mcpm/guard-confine.yaml (${sanitize((err as Error).message)}); ` +
        `starting a fresh confine store for this enable.\n`,
    );
    store = emptyConfineStore();
  }

  const home = os.homedir();
  const sandboxRoot = await confineSandboxRoot();
  const tmpDir = os.tmpdir();
  const capturedAt = new Date().toISOString();
  for (const [name, target] of targets) {
    const profile = deriveDefaultProfile({
      serverName: name,
      command: target.command,
      args: target.args,
      home,
      sandboxRoot,
      tmpDir,
      capturedAt,
      requireConfine: opts.requireConfine,
      net: opts.net,
    });
    store = withProfile(store, name, profile);
    markers.set(name, {
      profileHash: hashConfineProfile(profile),
      required: profile.require_confine,
    });
  }
  await writeConfineStore(store);
  return markers;
}

function printConfineNotice(
  confineMarkers: ReadonlyMap<string, ConfineMarker>,
  opts: CommandIO,
): void {
  if (confineMarkers.size === 0) {
    opts.write("\nOS confinement: no unwrapped stdio servers to enroll.\n");
    return;
  }
  opts.write(
    `\n🔒 ${confineMarkers.size} server(s) enrolled in OS confinement (standard tier). ` +
      "Run `mcpm guard doctor-confine` for status.\n",
  );
  if (!isConfineBackendAvailable()) {
    opts.write(
      chalk.yellow(
        "⚠ No OS sandbox backend on this platform — enrolled servers run UNCONFINED until a " +
          "backend is present (they are NOT blocked; a require_confine server would fail closed).",
      ) + "\n",
    );
  }
}

export interface DoctorConfineOpts extends CommandIO {
  readonly json?: boolean;
}

export async function runDoctorConfineCommand(opts: DoctorConfineOpts): Promise<void> {
  const backendAvailable = isConfineBackendAvailable();
  let servers: Array<{
    name: string;
    tier: string;
    net: string;
    requireConfine: boolean;
    scratchDir: string;
  }> = [];
  let storeError: string | undefined;
  try {
    const store = await readConfineStore();
    servers = Object.entries(store.servers).map(([name, p]) => ({
      name,
      tier: p.tier,
      net: p.net,
      requireConfine: p.require_confine,
      scratchDir: p.scratch_dir,
    }));
  } catch (err) {
    storeError = (err as Error).message;
  }

  if (opts.json === true) {
    opts.write(
      JSON.stringify(
        {
          platform: process.platform,
          backendAvailable,
          sandboxExecPath: process.platform === "darwin" ? SANDBOX_EXEC_PATH : null,
          storeError: storeError ?? null,
          servers: servers.map((s) => ({
            name: s.name,
            tier: s.tier,
            net: s.net,
            requireConfine: s.requireConfine,
          })),
        },
        null,
        2,
      ) + "\n",
    );
    return;
  }

  opts.write("mcpm guard doctor-confine\n\n");
  opts.write(`  platform        : ${process.platform}\n`);
  opts.write(`  sandbox backend : ${backendAvailable ? "available" : "UNAVAILABLE"}`);
  if (process.platform === "darwin") opts.write(` (${SANDBOX_EXEC_PATH})`);
  opts.write("\n");
  if (!backendAvailable) {
    opts.write(
      "  → enrolled servers run UNCONFINED here (hybrid posture); a require_confine server fails closed.\n",
    );
  }
  opts.write("\n");
  if (storeError !== undefined) {
    opts.write(`  ⚠ could not read the confine store: ${sanitize(storeError)}\n`);
    return;
  }
  if (servers.length === 0) {
    opts.write(
      "  No servers enrolled in confinement. Enroll with `mcpm guard enable --confine`.\n",
    );
    return;
  }
  opts.write(`  Enrolled servers (${servers.length}):\n`);
  for (const s of servers) {
    opts.write(
      `    ${sanitize(s.name)} — tier=${s.tier} net=${s.net} require_confine=${s.requireConfine}\n`,
    );
  }
  opts.write("\n  Run `mcpm guard status` for per-client wrap state.\n");
}

/**
 * H9 (A.4): "warn once unless the set changes". Emit the full multi-line
 * UNGUARDED warning only when this run ADDS a server to the consented-unguarded
 * set (additions = new risk). When the set is unchanged (or only shrank), emit
 * at most a single quiet line. Removals never re-warn.
 */
export function printUnguardedWarning(
  summary: EnableDisableSummary,
  previousConsented: readonly string[],
  opts: CommandIO,
): void {
  const current = [
    ...new Set(
      summary.clients.flatMap((c) =>
        c.servers.filter((s) => s.status === "unguarded").map((s) => s.name),
      ),
    ),
  ].sort();
  if (current.length === 0) return;

  if (isNewUnguarded(current, previousConsented)) {
    // List only the NEWLY-consented delta as the servers being rubber-stamped;
    // re-listing already-consented names dilutes the "this one is the new risk"
    // signal the warn-once design exists to sharpen.
    const prev = new Set(previousConsented);
    const newlyConsented = current.filter((n) => !prev.has(n));
    const alreadyCount = current.length - newlyConsented.length;
    opts.write(
      chalk.yellow(
        "\n⚠ UNGUARDED: the following server(s) run WITHOUT runtime inspection — " +
          "the guard relay cannot wrap a non-stdio (URL/HTTP) transport:",
      ) + "\n",
    );
    for (const name of newlyConsented) opts.write(`  ⚠ ${sanitize(name)}\n`);
    if (alreadyCount > 0) {
      opts.write(`  (+${alreadyCount} previously consented)\n`);
    }
    opts.write(
      "This grants consent to run them UNGUARDED — it does NOT add protection. The only " +
        "true fix is a streamable-HTTP relay (not yet implemented). Future `enable` runs " +
        "stay quiet unless a NEW unguarded server appears.\n",
    );
  } else {
    opts.write(
      `\n${current.length} server(s) running unguarded (previously consented): ` +
        `${current.map((n) => sanitize(n)).join(", ")}\n`,
    );
  }
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
  opts.write(`${summary.totalSkipped} skipped`);
  if (summary.totalUnguarded > 0) {
    opts.write(`, ${summary.totalUnguarded} unguarded`);
  }
  opts.write(`, ${summary.errors} error(s)\n\n`);
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
    const symbol =
      s.status === "wrapped"
        ? "+"
        : s.status === "unwrapped"
          ? "-"
          : s.status === "unguarded"
            ? "⚠"
            : "·";
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
      // H9: a url/HTTP-transport server cannot be wrapped — mark it UNGUARDED
      // distinctly rather than letting it read as a plain unwrapped stdio server.
      const marker = s.wrapped ? "+" : s.unguarded ? "⚠ UNGUARDED" : "·";
      opts.write(`    ${marker} ${sanitize(s.name)}\n`);
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
  // #28: compare RAW names — pins.json is keyed by the raw server name, so
  // sanitizing here would mismatch every pin key and wrongly flag live pins as
  // orphans (or miss real orphans). sanitize() is for terminal display only.
  const installedServerNames = new Set<string>();
  for (const c of status.clients) {
    for (const s of c.servers) installedServerNames.add(s.name);
  }

  const { readPins, writePins, clearServerPins, PinsIntegrityError } = await import("./pins.js");
  // readPins returns an empty pins file (not a throw) when pins.json is absent,
  // so a thrown error here is never "no pins yet" — it is a PinsIntegrityError
  // (tampered/corrupted sidecar) or an I/O error. Swallowing it to `null` would
  // make `cleanup` print "nothing to prune" on a TAMPERED pins file, hiding the
  // exact tamper signal the user needs. Surface it loudly and abort instead.
  let pins: Awaited<ReturnType<typeof readPins>>;
  try {
    pins = await readPins();
  } catch (err) {
    if (err instanceof PinsIntegrityError) {
      opts.write(
        `mcpm guard cleanup: cannot read ~/.mcpm/pins.json — integrity check failed.\n` +
          `${err.message}\n` +
          `Refusing to prune until this is resolved.\n`,
      );
    } else {
      opts.write(
        `mcpm guard cleanup: cannot read ~/.mcpm/pins.json — ${(err as Error).message}\n` +
          `Refusing to prune until this is resolved.\n`,
      );
    }
    return;
  }
  const orphanPinned: string[] = [];
  for (const serverName of Object.keys(pins.servers)) {
    if (!installedServerNames.has(serverName)) orphanPinned.push(serverName);
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
  for (const s of orphanPinned) opts.write(`  - ${sanitize(s)}\n`);

  if (!opts.apply) {
    opts.write("\nDry run. Re-run with --yes to prune.\n");
    return;
  }

  let next = pins;
  for (const serverName of orphanPinned) next = clearServerPins(next, serverName);
  await writePins(next);
  opts.write(`\nPruned ${orphanPinned.length} orphan pin entr${orphanPinned.length === 1 ? "y" : "ies"} from ~/.mcpm/pins.json.\n`);
}
