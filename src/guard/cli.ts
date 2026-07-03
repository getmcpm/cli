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
import { hashConfineProfile, type ConfineStore } from "./confine/profile.js";
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
  "claude-code": "Claude Code",
  cursor: "Cursor",
  vscode: "VS Code",
  windsurf: "Windsurf",
  "gemini-cli": "Gemini CLI",
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
    await printEnableDryRun(opts);
    return;
  }

  if (opts.confine === "off") {
    // Acknowledge the flag so `--confine off` isn't a silent no-op.
    opts.write("OS confinement: skipped (--confine off).\n");
  }

  // F1: build the name→marker map BEFORE the orchestrator runs, so the same
  // content hash is embedded across every client that wraps a given server. A
  // corrupt/tampered confine store ABORTS the enable (store left untouched)
  // rather than silently clobbering previously-enrolled servers or masking tamper.
  let confineMarkers: ReadonlyMap<string, ConfineMarker> | undefined;
  if (opts.confine === "standard") {
    try {
      confineMarkers = await computeConfineMarkers({
        client: opts.client,
        server: opts.server,
        write: opts.write,
      });
    } catch (err) {
      opts.write(
        chalk.yellow(`\n⚠ OS confinement aborted: ${sanitize((err as Error).message)}`) + "\n",
      );
      return;
    }
  }

  const deps = buildDeps({ allowUnguarded: opts.allowUnguarded, confineMarkers });
  const summary = await enableGuardAcrossClients(deps, opts);
  printEnableDisable(summary, opts);
  printUnguardedWarning(summary, previousConsented, opts);
  if (confineMarkers !== undefined) printConfineNotice(confineMarkers, opts);
  printRestartReminder(opts);
}

async function printEnableDryRun(opts: EnableOpts): Promise<void> {
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
}

// ---------------------------------------------------------------------------
// F1 confine: marker computation + doctor
// ---------------------------------------------------------------------------

export interface ConfineComputeOpts {
  readonly client?: ClientId;
  readonly server?: string;
  readonly net?: "all" | "none";
  readonly requireConfine?: boolean;
  readonly write: (s: string) => void;
}

interface ConfineTarget {
  readonly command: string;
  readonly args?: readonly string[];
}

/**
 * De-duped (by name) set of servers `enable` will wrap and therefore need a
 * confine profile: unwrapped STDIO servers only (url/HTTP have no command;
 * already-wrapped servers aren't re-wrapped), respecting `--client`/`--server`.
 */
async function collectConfineTargets(opts: ConfineComputeOpts): Promise<Map<string, ConfineTarget>> {
  const targets = new Map<string, ConfineTarget>();
  let clients: ClientId[];
  try {
    clients = await detectInstalledClients();
  } catch {
    return targets;
  }
  if (opts.client !== undefined) clients = clients.filter((c) => c === opts.client);
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
      // Tie-breaker: first client wins. If the same server NAME runs a different
      // command across clients (e.g. `npx` in one, `node` in another), the net
      // classification is taken from the first-seen command. Pass `--client` to
      // enroll per-client and avoid the ambiguity.
      if (!targets.has(name)) targets.set(name, { command: entry.command, args: entry.args });
    }
  }
  return targets;
}

/**
 * Build the name→marker map for the servers `enable` will wrap, persisting a
 * ConfineProfile for genuinely-new servers. Returns markers for the orchestrator
 * to embed. Two load-bearing properties:
 *
 *   1. FAIL CLOSED on a corrupt/tampered store — `readConfineStore` throws only on
 *      a genuine integrity/shape/version error (ENOENT returns an empty store), so
 *      we let it PROPAGATE (the caller aborts the enable). We must never fall back
 *      to an empty store + overwrite: that would erase previously-enrolled servers
 *      and mask the tamper signal.
 *   2. REUSE an already-stored profile rather than re-deriving it. A re-derive would
 *      mint a fresh `capturedAt`; even though captured_at is excluded from the hash,
 *      reusing avoids churning the store on a retry and keeps the binding stable.
 *      (v1 does not re-enroll a server whose command changed — that's the deferred
 *      per-server `guard confine` command; the existing profile is the safe choice.)
 */
export async function computeConfineMarkers(
  opts: ConfineComputeOpts,
): Promise<ReadonlyMap<string, ConfineMarker>> {
  const targets = await collectConfineTargets(opts);
  if (targets.size === 0) return new Map();

  let store: ConfineStore;
  try {
    store = await readConfineStore();
  } catch (err) {
    throw new Error(
      `cannot read the confine store (~/.mcpm/guard-confine.yaml): ${(err as Error).message} ` +
        `Review it for unauthorized changes; if you edited it intentionally, restore or remove it. ` +
        `Refusing to enroll — the store was left untouched.`,
    );
  }

  const { markers, storeToWrite } = await resolveConfineMarkers(targets, store, opts);
  if (storeToWrite !== null) await writeConfineStore(storeToWrite);
  return markers;
}

/**
 * Build the markers for `targets`: reuse an already-stored profile (stable hash,
 * no store churn) or derive+stage a new one. Returns the markers and the store to
 * persist (null when nothing new was added, so the caller skips the write).
 */
async function resolveConfineMarkers(
  targets: Map<string, ConfineTarget>,
  store: ConfineStore,
  opts: ConfineComputeOpts,
): Promise<{ markers: Map<string, ConfineMarker>; storeToWrite: ConfineStore | null }> {
  const markers = new Map<string, ConfineMarker>();
  const home = os.homedir();
  const sandboxRoot = await confineSandboxRoot();
  const tmpDir = os.tmpdir();
  const capturedAt = new Date().toISOString();
  let next = store;
  let added = 0;
  for (const [name, target] of targets) {
    const existing = Object.hasOwn(store.servers, name) ? store.servers[name] : undefined;
    if (existing !== undefined) {
      markers.set(name, {
        profileHash: hashConfineProfile(existing),
        required: existing.require_confine,
      });
      continue;
    }
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
    next = withProfile(next, name, profile);
    added += 1;
    markers.set(name, {
      profileHash: hashConfineProfile(profile),
      required: profile.require_confine,
    });
  }
  return { markers, storeToWrite: added > 0 ? next : null };
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

interface DoctorConfineServer {
  readonly name: string;
  readonly tier: string;
  readonly net: string;
  readonly requireConfine: boolean;
}

export async function runDoctorConfineCommand(opts: DoctorConfineOpts): Promise<void> {
  const backendAvailable = isConfineBackendAvailable();
  let servers: DoctorConfineServer[] = [];
  let storeError: string | undefined;
  try {
    const store = await readConfineStore();
    servers = Object.entries(store.servers).map(([name, p]) => ({
      name,
      tier: p.tier,
      net: p.net,
      requireConfine: p.require_confine,
    }));
  } catch (err) {
    storeError = (err as Error).message;
  }
  opts.write(
    opts.json === true
      ? renderDoctorConfineJson(backendAvailable, servers, storeError)
      : renderDoctorConfineText(backendAvailable, servers, storeError),
  );
}

function renderDoctorConfineJson(
  backendAvailable: boolean,
  servers: readonly DoctorConfineServer[],
  storeError: string | undefined,
): string {
  return (
    JSON.stringify(
      {
        platform: process.platform,
        backendAvailable,
        sandboxExecPath: process.platform === "darwin" ? SANDBOX_EXEC_PATH : null,
        // sanitize: an OS error message can carry control chars / ANSI (parity
        // with the text branch, which already sanitizes).
        storeError: storeError !== undefined ? sanitize(storeError) : null,
        servers,
      },
      null,
      2,
    ) + "\n"
  );
}

function renderDoctorConfineText(
  backendAvailable: boolean,
  servers: readonly DoctorConfineServer[],
  storeError: string | undefined,
): string {
  const out: string[] = ["mcpm guard doctor-confine", ""];
  out.push(`  platform        : ${process.platform}`);
  let backendLine = `  sandbox backend : ${backendAvailable ? "available" : "UNAVAILABLE"}`;
  if (process.platform === "darwin") backendLine += ` (${SANDBOX_EXEC_PATH})`;
  out.push(backendLine);
  if (!backendAvailable) {
    out.push(
      "  → enrolled servers run UNCONFINED here (hybrid posture); a require_confine server fails closed.",
    );
  }
  out.push("");
  if (storeError !== undefined) {
    out.push(`  ⚠ could not read the confine store: ${sanitize(storeError)}`, "");
    return out.join("\n");
  }
  if (servers.length === 0) {
    out.push("  No servers enrolled in confinement. Enroll with `mcpm guard enable --confine`.", "");
    return out.join("\n");
  }
  out.push(`  Enrolled servers (${servers.length}):`);
  for (const s of servers) {
    out.push(`    ${sanitize(s.name)} — tier=${s.tier} net=${s.net} require_confine=${s.requireConfine}`);
  }
  out.push("", "  Run `mcpm guard status` for per-client wrap state.", "");
  return out.join("\n");
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
