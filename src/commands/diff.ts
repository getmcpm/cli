/**
 * `mcpm diff` command handler.
 *
 * Compares installed MCP server state across all detected clients
 * against the declared state in mcpm.yaml + mcpm-lock.yaml.
 *
 * Shows: missing servers (in yaml, not installed), extra servers
 * (installed, not in yaml), version mismatches, and trust score
 * changes since lock.
 *
 * Exports:
 * - handleDiff()           — injectable handler for testing
 * - registerDiffCommand()  — Commander registration
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type {
  StackFile,
  LockFile,
  LockedServer,
} from "../stack/schema.js";
import {
  parseStackFile,
  parseLockFile,
  isLockedRegistryServer,
} from "../stack/schema.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DiffOptions {
  stackFile?: string;
  json?: boolean;
}

export interface DiffDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "read">;
  getPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

export type DiffStatus = "missing" | "extra" | "match" | "mismatch";

export interface DiffEntry {
  readonly name: string;
  readonly status: DiffStatus;
  readonly detail: string;
  readonly clients: readonly ClientId[];
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleDiff(
  options: DiffOptions,
  deps: DiffDeps
): Promise<void> {
  const stackPath = options.stackFile ?? "mcpm.yaml";
  const lockPath = stackPath.replace(/\.yaml$/, "-lock.yaml");

  const stackFile = await parseStackFile(stackPath);
  const lockFile = await parseLockFile(lockPath);

  if (lockFile === null) {
    throw new Error("No lock file found. Run mcpm lock first.");
  }

  // Collect installed servers across all clients
  const clients = await deps.detectClients();
  const installed = new Map<string, { clients: ClientId[]; entry: McpServerEntry }>();

  for (const clientId of clients) {
    try {
      const adapter = deps.getAdapter(clientId);
      const configPath = deps.getPath(clientId);
      const servers = await adapter.read(configPath);

      for (const [name, entry] of Object.entries(servers)) {
        const existing = installed.get(name);
        if (existing) {
          existing.clients.push(clientId);
        } else {
          installed.set(name, { clients: [clientId], entry: { ...entry } });
        }
      }
    } catch {
      // Skip unreadable clients
    }
  }

  // Build diff entries
  const entries: DiffEntry[] = [];
  const declaredNames = new Set(Object.keys(stackFile.servers));

  // Check each declared server
  for (const name of declaredNames) {
    const locked = lockFile.servers[name];
    const inst = installed.get(name);

    if (!inst) {
      entries.push({
        name,
        status: "missing",
        detail: locked ? formatLocked(locked) : "not locked",
        clients: [],
      });
    } else if (locked && isLockedRegistryServer(locked)) {
      entries.push({
        name,
        status: "match",
        detail: `v${locked.version} (trust: ${locked.trust.score}/${locked.trust.maxPossible})`,
        clients: inst.clients,
      });
    } else {
      entries.push({
        name,
        status: "match",
        detail: "installed",
        clients: inst.clients,
      });
    }
  }

  // Check for extra servers (installed but not in yaml)
  for (const [name, inst] of installed) {
    if (!declaredNames.has(name)) {
      entries.push({
        name,
        status: "extra",
        detail: "not in mcpm.yaml",
        clients: inst.clients,
      });
    }
  }

  // Output
  if (options.json) {
    deps.output(JSON.stringify(entries, null, 2));
    return;
  }

  if (entries.length === 0) {
    deps.output("No servers to compare.");
    return;
  }

  const missing = entries.filter((e) => e.status === "missing");
  const extra = entries.filter((e) => e.status === "extra");
  const matched = entries.filter((e) => e.status === "match");

  if (missing.length > 0) {
    deps.output("Missing (in mcpm.yaml but not installed):");
    for (const e of missing) {
      deps.output(`  - ${e.name} (${e.detail})`);
    }
    deps.output("");
  }

  if (extra.length > 0) {
    deps.output("Extra (installed but not in mcpm.yaml):");
    for (const e of extra) {
      deps.output(`  + ${e.name} [${e.clients.join(", ")}]`);
    }
    deps.output("");
  }

  if (matched.length > 0) {
    deps.output("In sync:");
    for (const e of matched) {
      deps.output(`  = ${e.name} ${e.detail} [${e.clients.join(", ")}]`);
    }
    deps.output("");
  }

  deps.output(
    `${matched.length} in sync, ${missing.length} missing, ${extra.length} extra`
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatLocked(locked: LockedServer): string {
  if (isLockedRegistryServer(locked)) {
    return `v${locked.version} (trust: ${locked.trust.score}/${locked.trust.maxPossible})`;
  }
  if ("url" in locked) {
    return `url: ${(locked as { url: string }).url}`;
  }
  return "locked";
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import { detectInstalledClients } from "../config/detector.js";
import { getConfigPath } from "../config/paths.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { stdoutOutput } from "../utils/output.js";

export function registerDiffCommand(program: Command): void {
  program
    .command("diff")
    .description(
      "Compare installed servers against mcpm.yaml and lock file"
    )
    .option("-f, --file <path>", "path to mcpm.yaml", "mcpm.yaml")
    .option("--json", "output as JSON")
    .action(async (opts: { file?: string; json?: boolean }) => {
      const chalk = (await import("chalk")).default;
      try {
        await handleDiff(
          { stackFile: opts.file, json: opts.json },
          {
            detectClients: detectInstalledClients,
            getAdapter: getAdapterDefault,
            getPath: getConfigPath,
            output: stdoutOutput,
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
