/**
 * `mcpm update` command — check for newer versions and update installed servers.
 *
 * Exports:
 * - handleUpdate() — pure handler with injectable deps for testing
 * - registerUpdateCommand() — registers the command on a Commander program
 *
 * Architecture:
 * - "Update" means: re-fetch registry metadata, compare version, update store record.
 * - For npm servers (npx -y package), the actual binary is fetched at runtime —
 *   so update mainly updates the stored version record and re-runs trust assessment.
 * - Registry unavailability is graceful — skip that server with an error note.
 * - All external deps are injectable for hermetic testing.
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import type { InstalledServer } from "../store/servers.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import { levelColor, levelLabel, extractRegistryMeta } from "../utils/format-trust.js";
import { resolveInstallEntry } from "./install.js";
import { stdoutOutput } from "../utils/output.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import { describeRegistryError } from "../registry/errors.js";
import { assessServerStatus } from "../scanner/registry-status.js";
import { isWrapped, unwrapEntry, rewrapEntry } from "../guard/wrap.js";
import { assertPublication } from "../registry/package-coordinate.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UpdateOptions {
  yes?: boolean;
  json?: boolean;
}

export interface UpdateDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string, version?: string) => Promise<ServerEntry>;
  addInstalledServer: (server: InstalledServer) => Promise<void>;
  removeInstalledServer: (name: string) => Promise<void>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

interface UpdateResult {
  name: string;
  oldVersion: string;
  newVersion: string;
  updated: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Keep the full validated entry. Malformed unguarded entries retain the #59
 * per-key env recovery path; unreadable configs must never be overwritten.
 */
async function readExistingEntry(
  getAdapter: UpdateDeps["getAdapter"],
  getConfigPath: UpdateDeps["getConfigPath"],
  clientId: ClientId,
  name: string,
  onNote: (message: string) => void,
  onNeighbour: (clientId: ClientId, skipped: string) => void
): Promise<McpServerEntry | undefined> {
  const adapter = getAdapter(clientId);
  const configPath = getConfigPath(clientId);
  // #59: since #23 (v0.34.0) an entry failing shape validation is omitted
  // from the returned map, so a plain `servers[name]?.env` returned undefined
  // for it — and the caller's `force: true` re-write then DISCARDED a
  // perfectly good env block (API keys) held by an entry malformed in some
  // OTHER field, while printing "✓ Updated".
  //
  // The fix is to recover the env, NOT to refuse the write. Overwriting a
  // mis-shaped entry with a freshly resolved one is the user's self-repair
  // path; refusing it turns a self-healing case into a permanently stuck one.
  //
  // Recovery is PER KEY, not all-or-nothing. `env` is frequently the field
  // that makes the entry invalid in the first place — a numeric port is the
  // archetypal hand-edit — and parsing the whole record then rejects every
  // key, destroying the API key beside the bad one. Only string-valued keys
  // can be carried into a valid entry; any key that cannot is NAMED rather
  // than dropped in silence.
  let recovered: McpServerEntry | undefined;
  let malformedGuard = false;
  const servers = await adapter.read(configPath, (skipped, raw) => {
    if (skipped !== name) {
      // Another malformed entry in the same config. Replacing the default
      // onSkip suppressed its warning, so it is collected — but reported ONCE
      // at the end of the run, and only for names this run did not itself
      // update. Reporting here said `srv-b … (not updated)` one line before
      // `✓ Updated srv-b`, and repeated it once per updated server.
      onNeighbour(clientId, skipped);
      return;
    }
    recovered = {};
    const rawArgs = (raw as { args?: unknown } | null | undefined)?.args;
    if (Array.isArray(rawArgs) && isWrapped({ args: rawArgs })) {
      malformedGuard = true;
      return;
    }
    if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
      // Native client settings are opaque passthrough fields, as in BaseAdapter.
      // Recover valid launch fields too: a bad env value must not erase custom args.
      const { command, args, url, headers, env: _env, disabled, ...settings } = raw as Record<string, unknown>;
      recovered = { ...settings, ...(typeof disabled === "boolean" ? { disabled } : {}) };
      if (typeof command === "string" &&
          (args === undefined || (Array.isArray(args) && args.every((arg) => typeof arg === "string")))) {
        recovered.command = command;
        if (args !== undefined) recovered.args = args as string[];
      }
      if (typeof url === "string") recovered.url = url;
      if (headers !== null && typeof headers === "object" && !Array.isArray(headers) &&
          Object.values(headers).every((value) => typeof value === "string")) {
        recovered.headers = headers as Record<string, string>;
      }
    }
    const env = (raw as { env?: unknown } | null | undefined)?.env;
    if (env !== undefined && (env === null || typeof env !== "object" || Array.isArray(env))) {
      onNote(`${clientId}: env is not an object — nothing could be carried over`);
      return;
    }
    if (env === undefined) return;
    // Object.create(null): a plain literal routes an own `__proto__` key to
    // Object.prototype's setter, which silently drops a string value — the
    // same class v0.36.0 closed in the guard's pin hash, and it would break
    // this block's own promise to NAME anything it cannot carry.
    const kept = Object.create(null) as Record<string, string>;
    const dropped: string[] = [];
    for (const [k, v] of Object.entries(env as Record<string, unknown>)) {
      if (typeof v === "string") kept[k] = v;
      else dropped.push(k);
    }
    if (dropped.length > 0) {
      onNote(
        `${clientId}: env ${dropped.length === 1 ? "key" : "keys"} ` +
          `${dropped.map((k) => `"${sanitizeForTerminal(k)}"`).join(", ")} ` +
          `${dropped.length === 1 ? "is" : "are"} not a string and could not be carried over ` +
          `— re-set ${dropped.length === 1 ? "it" : "them"} with the value quoted`
      );
    }
    if (Object.keys(kept).length > 0) recovered = { ...recovered, env: kept };
  });
  if (malformedGuard) throw new Error("Malformed guarded entry; repair it before updating so the guard is not removed");
  return servers[name] ?? recovered;
}

/** Replace only registry-generated launch args; retain a user's appended args. */
export function mergeUpdateEntry(existing: McpServerEntry, next: McpServerEntry, previous: McpServerEntry): McpServerEntry {
  if ((existing.command !== undefined) !== (next.command !== undefined)) {
    throw new Error("Registry transport changed; update this client's launch configuration by hand");
  }
  if (existing.command !== previous.command || existing.url !== previous.url ||
      !(previous.args ?? []).every((arg, i) => existing.args?.[i] === arg)) {
    throw new Error("Custom launch command or arguments differ from the installed registry version; update them by hand");
  }
  const extraArgs = (existing.args ?? []).slice(previous.args?.length ?? 0);
  if (extraArgs.length > 0 && existing.command !== next.command) {
    throw new Error("Registry launcher changed; cannot safely carry custom arguments to it — update them by hand");
  }
  const { command: _command, args: _args, url: _url, headers, ...settings } = existing;
  return {
    ...settings, ...next,
    ...(next.command !== undefined ? { args: [...(next.args ?? []), ...extraArgs] } : {}),
    ...(existing.env !== undefined ? { env: { ...next.env, ...existing.env } } : {}),
    ...(next.url !== undefined && headers !== undefined ? { headers: { ...next.headers, ...headers } } : {}),
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm update`.
 */
export async function handleUpdate(
  options: UpdateOptions,
  deps: UpdateDeps
): Promise<void> {
  const {
    getInstalledServers,
    getServer,
    addInstalledServer,
    removeInstalledServer,
    getAdapter,
    getConfigPath,
    scanTier1,
    computeTrustScore,
    confirm,
    output,
  } = deps;

  const servers = await getInstalledServers();

  if (servers.length === 0) {
    output("No servers installed.");
    return;
  }

  const spinner = ora({ text: "Checking for updates...", isSilent: !process.stdout.isTTY }).start();

  // Fetch current metadata from registry for all servers — in parallel
  type FetchOutcome =
    | { kind: "ok"; installed: InstalledServer; entry: ServerEntry }
    | { kind: "error"; installed: InstalledServer; error: string };

  const fetchResults = await Promise.all(
    servers.map(async (installed): Promise<FetchOutcome> => {
      try {
        const entry = await getServer(installed.name);
        assertPublication(entry, installed.name);
        return { kind: "ok", installed, entry };
      } catch (err) {
        // #92: a 404 (delisted) and an unparseable response are not "unavailable".
        return { kind: "error", installed, error: describeRegistryError(err).message };
      }
    })
  );

  // Build the entry map and initial results list from fetch outcomes
  const entryMap = new Map<string, ServerEntry>();
  const results: UpdateResult[] = fetchResults.map((outcome) => {
    if (outcome.kind === "error") {
      return {
        name: outcome.installed.name,
        oldVersion: outcome.installed.version,
        newVersion: outcome.installed.version,
        updated: false,
        error: outcome.error,
      };
    }
    const { installed, entry } = outcome;
    const status = assessServerStatus(entry);
    if (status.blocks) {
      return {
        name: installed.name, oldVersion: installed.version, newVersion: entry.server.version, updated: false,
        error: `Deleted from the MCP registry${status.statusMessage ? ` (${sanitizeForTerminal(status.statusMessage)})` : ""}; update refused`,
      };
    }
    entryMap.set(installed.name, entry);
    return {
      name: installed.name,
      oldVersion: installed.version,
      newVersion: entry.server.version,
      updated: false,
      error: undefined,
    };
  });

  spinner.stop();

  // Filter to those with updates available
  const withUpdates = results.filter((r) => r.newVersion !== r.oldVersion && !r.error);

  const isJson = options.json === true;

  // Show registry errors (non-JSON mode only)
  if (!isJson) {
    for (const r of results.filter((r) => r.error)) {
      output(chalk.yellow(`  ${r.name}: ${r.error}`));
    }
  }

  if (withUpdates.length === 0) {
    if (!isJson) {
      // Show up-to-date message unless all were errors
      if (results.filter((r) => !r.error).length > 0) {
        output(chalk.green("All servers are up to date."));
      }
    } else {
      output(
        JSON.stringify(
          results.map((r) => ({
            name: r.name,
            oldVersion: r.oldVersion,
            newVersion: r.newVersion,
            updated: false,
            error: r.error ?? null,
          })),
          null,
          2
        )
      );
    }
    return;
  }

  // Show available updates (non-JSON mode)
  if (!isJson) {
    output(chalk.bold("\nUpdates available:"));
    for (const r of withUpdates) {
      output(`  ${chalk.white(r.name)}: ${chalk.yellow(r.oldVersion)} → ${chalk.green(r.newVersion)}`);
    }
  }

  // Prompt for confirmation (unless --yes)
  if (options.yes !== true) {
    const confirmed = await confirm(
      `Update ${withUpdates.length} server${withUpdates.length !== 1 ? "s" : ""}?`
    );
    if (!confirmed) {
      if (!isJson) {
        output("Update cancelled — skipping all updates.");
      } else {
        output(
          JSON.stringify(
            results.map((r) => ({ name: r.name, oldVersion: r.oldVersion, newVersion: r.newVersion, updated: false, error: r.error ?? null })),
            null,
            2
          )
        );
      }
      return;
    }
  }

  // Track update outcomes immutably (name → { updated, trustScore, clientErrors })
  const updateOutcomes = new Map<
    string,
    { updated: boolean; trustScore: TrustScore; clientErrors: string[]; clientNotes: string[] }
  >();

  // Perform updates.
  //
  // #59: malformed entries seen in passing while reading configs, collected
  // across the whole run and reported ONCE below rather than per updated
  // server. Keyed by (client, name), not name: the same malformed name in two
  // clients is two facts, and a name-only key silently dropped one of them.
  const neighbours = new Map<string, { name: string; clientId: ClientId }>();
  // The (client, name) pairs this run actually re-wrote. Suppression must be
  // keyed the same way the FACT is: `update` writes only to a server's own
  // `originalClients`, so a malformed copy of that name in a DIFFERENT client
  // is neither updated nor — under a name-scoped filter — reported, silently
  // suppressed by its own success elsewhere.
  const writtenPairs = new Set<string>();

  for (const r of withUpdates) {
    const entry = entryMap.get(r.name);

    if (!entry) continue;

    // Run trust assessment on new version
    const tier1Findings = scanTier1(entry);
    const trustScore = computeTrustScore({
      findings: tier1Findings,
      healthCheckPassed: null,
      hasExternalScanner: false,
      registryMeta: {
        ...extractRegistryMeta(entry),
        downloadCount: undefined,
      },
    });

    // Preserve original clients from installed server list (servers fetched once before this loop)
    const original = servers.find((s) => s.name === r.name);
    const originalClients = original?.clients ?? [];

    // Re-resolve the server entry for the new version and write it back to each
    // client config. Without this the store record advances but the client
    // config keeps the stale command/args — most visible for OCI/pypi servers
    // whose image:tag or version changes between releases.
    //
    // Mirror the up.ts partial-failure pattern: collect the clients that failed
    // so we can warn the user instead of silently leaving them on the old
    // version. Any successful client write advances the store record.
    const clientErrors: string[] = [];
    // #59: kept separate from clientErrors. These are things the user should
    // know about a client that WAS updated — routing them through the error
    // list made the output say "could not update claude-desktop" about a
    // client it had just updated.
    const clientNotes: string[] = [];
    let written = 0;
    let previousMetadata: Promise<ServerEntry> | undefined;
    const resolved = new Map<ClientId, McpServerEntry>();
    try {
      for (const client of originalClients) resolved.set(client, resolveInstallEntry(entry, client));
    } catch (err) {
      resolved.clear();
      clientErrors.push(`Package preflight: ${err instanceof Error ? err.message : String(err)}`);
    }
    for (const [clientId, rawEntry] of resolved) {
      try {
        const configured = await readExistingEntry(
          getAdapter,
          getConfigPath,
          clientId,
          r.name,
          (note) => clientNotes.push(note),
          (cid, skipped) =>
            neighbours.set(JSON.stringify([cid, skipped]), { name: skipped, clientId: cid })
        );
        if (!configured) throw new Error("Server is missing from this client config; update will not reinstall it");
        const wrapped = isWrapped(configured);
        const existing = wrapped ? unwrapEntry(configured) : configured;
        if (!existing) throw new Error("Guard wrap is malformed or has an integrity mismatch; refusing to update it");
        // An unchanged launch needs no historical registry request. A malformed
        // unguarded entry with no recoverable launch is repaired fresh (#59).
        let previous = rawEntry;
        if ((existing.command !== undefined || existing.url !== undefined) &&
            (existing.command !== rawEntry.command || existing.url !== rawEntry.url ||
             JSON.stringify(existing.args ?? []) !== JSON.stringify(rawEntry.args ?? []))) {
          previousMetadata ??= getServer(r.name, original!.version).catch((err: unknown) => {
            throw new Error(`Could not load installed registry version ${original!.version} to preserve launch arguments: ${describeRegistryError(err).message}`);
          });
          const old = await previousMetadata;
          if (old.server.name !== r.name || old.server.version !== original!.version) {
            throw new Error("Registry did not return the installed version; cannot safely preserve custom launch arguments");
          }
          // Pre-#120 entries used the unversioned generated prefix. Match it
          // only against this same verified publication; never infer a launcher.
          const legacy = resolveInstallEntry(old, clientId, undefined, true);
          previous = existing.command === legacy.command && existing.url === legacy.url &&
              (legacy.args ?? []).every((arg, i) => existing.args?.[i] === arg)
            ? legacy : resolveInstallEntry(old, clientId);
        }
        const merged = existing.command === undefined && existing.url === undefined
          ? { ...rawEntry, ...existing }
          : mergeUpdateEntry(existing, rawEntry, previous);
        const newEntry = wrapped ? rewrapEntry(configured, merged) : merged;
        const adapter = getAdapter(clientId);
        const configPath = getConfigPath(clientId);
        await adapter.addServer(configPath, r.name, newEntry, { force: true });
        written += 1;
        writtenPairs.add(JSON.stringify([clientId, r.name]));
      } catch (err) {
        // Some clients may not support this server type, or the config may be
        // unwritable — collect the failure and leave that client untouched.
        clientErrors.push(`${clientId}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const finalRecord: InstalledServer = {
      name: r.name,
      version: r.newVersion,
      clients: originalClients,
      installedAt: new Date().toISOString(),
    };

    const updated = written > 0 || originalClients.length === 0;
    if (updated) {
      try { await removeInstalledServer(r.name); } catch { /* Server may not be in store. */ }
      await addInstalledServer(finalRecord);
    }

    // Record outcome immutably instead of mutating the result object
    updateOutcomes.set(r.name, { updated, trustScore, clientErrors, clientNotes });

    if (!isJson) {
      // Surface partial config-write failures so a client silently left on the
      // old version is visible to the user (mirrors the up.ts warning suffix).
      const warning =
        (clientErrors.length > 0
          ? chalk.yellow(` (warning: could not update ${clientErrors.join("; ")})`)
          : "") +
        (clientNotes.length > 0 ? chalk.yellow(` (note: ${clientNotes.join("; ")})`) : "");
      output(
        updated
          ? `  ${chalk.green("✓")} Updated ${chalk.white(r.name)} to ${chalk.green(r.newVersion)} [${levelColor(levelLabel(trustScore))}]${warning}`
          : `  ${chalk.yellow("✗")} Could not update ${chalk.white(r.name)}; installed version remains ${r.oldVersion}${warning}`
      );
    }
  }

  const unrelated = [...neighbours].filter(([key]) => !writtenPairs.has(key));
  if (unrelated.length > 0) {
    const body =
      `${unrelated.length} other malformed entr${unrelated.length === 1 ? "y was" : "ies were"} ` +
      `skipped and not updated: ` +
      `${unrelated.map(([, e]) => `${sanitizeForTerminal(e.name)} (${e.clientId})`).join(", ")}. ` +
      `Run \`mcpm doctor\` for details.`;
    // #59: --json has no field for this and stdout must stay parseable, so the
    // notice goes to stderr — otherwise replacing read()'s stderr default
    // emitted it NOWHERE, leaving a malformed entry LESS visible than before
    // this PR. Same resolution list.ts uses for the same problem.
    if (isJson) process.stderr.write(`mcpm: ${body}\n`);
    else output(chalk.yellow(`  ${body}`));
  }

  if (isJson) {
    output(
      JSON.stringify(
        results.map((r) => {
          const outcome = updateOutcomes.get(r.name);
          const clientErrors = outcome?.clientErrors ?? [];
          const clientNotes = outcome?.clientNotes ?? [];
          return {
            name: r.name,
            oldVersion: r.oldVersion,
            newVersion: r.newVersion,
            updated: outcome?.updated ?? r.updated,
            trustScore: outcome?.trustScore ?? null,
            error: r.error ?? null,
            clientErrors: clientErrors.length > 0 ? clientErrors : null,
            clientNotes: clientNotes.length > 0 ? clientNotes : null,
          };
        }),
        null,
        2
      )
    );
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerUpdateCommand(program: Command): void {
  program
    .command("update")
    .description("Check for newer versions and update installed servers")
    .option("-y, --yes", "Skip confirmation prompt")
    .option("--json", "Output raw JSON")
    .action(async (opts: { yes?: boolean; json?: boolean }) => {
      const { getInstalledServers, addInstalledServer, removeInstalledServer } =
        await import("../store/servers.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");
      const { getAdapter: getAdapterDefault, getConfigPath } = await import("../config/index.js");
      const { confirm } = await import("../utils/confirm.js");

      const client = new RegistryClient();

      const deps: UpdateDeps = {
        getInstalledServers,
        getServer: (name, version) => client.getServer(name, version),
        addInstalledServer,
        removeInstalledServer,
        getAdapter: getAdapterDefault,
        getConfigPath,
        scanTier1,
        computeTrustScore,
        confirm,
        output: stdoutOutput,
      };

      await handleUpdate({ yes: opts.yes, json: opts.json }, deps).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });
}
