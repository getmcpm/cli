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
      const installedVersion = extractInstalledVersion(inst.entry, locked.identifier);
      if (installedVersion !== null && installedVersion !== locked.version) {
        entries.push({
          name,
          status: "mismatch",
          detail: `locked v${locked.version}, installed v${installedVersion}`,
          clients: inst.clients,
        });
      } else {
        const detail = `v${locked.version} (trust: ${locked.trust.score}/${locked.trust.maxPossible})`;
        entries.push({
          name,
          status: "match",
          detail: installedVersion === null ? `${detail} (version not verifiable)` : detail,
          clients: inst.clients,
        });
      }
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
  const mismatched = entries.filter((e) => e.status === "mismatch");
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

  if (mismatched.length > 0) {
    deps.output("Version mismatch (installed differs from lock):");
    for (const e of mismatched) {
      deps.output(`  ~ ${e.name} ${e.detail} [${e.clients.join(", ")}]`);
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
    `${matched.length} in sync, ${mismatched.length} mismatched, ${missing.length} missing, ${extra.length} extra`
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Best-effort recovery of the installed version from a client config entry.
 *
 * The installed `args` mirror what `resolveInstallEntry` wrote, so a version is
 * only recoverable when it was embedded in the package identifier / image:
 * - npm/pypi: an arg of the form `<identifier>@<version>` (npx/uvx style)
 * - oci:      an arg of the form `<image>:<tag>` (docker `run … image:tag`)
 *
 * Returns null when the version cannot be determined from config (the common
 * case for npm servers installed without a pinned version) — callers MUST NOT
 * treat null as a mismatch.
 *
 * Note: an OCI digest pin (`<image>@sha256:<hash>`) satisfies the OCI_IDENTIFIER_RE
 * constraint but is a content digest, not a version — it must never be read as one
 * (see the `sha256:` guard below).
 */
function extractInstalledVersion(
  entry: McpServerEntry,
  identifier: string
): string | null {
  const args = entry.args;
  if (!args || args.length === 0) return null;

  // npm/pypi: find the arg whose base equals the locked identifier and that
  // carries an `@<version>` suffix. Skip a leading `@` (scoped npm packages).
  for (const arg of args) {
    const atIdx = arg.lastIndexOf("@");
    if (atIdx > 0) {
      const base = arg.slice(0, atIdx);
      const version = arg.slice(atIdx + 1);
      // An OCI digest (`@sha256:…`) is not a version — never misread it as one.
      if (version.startsWith("sha256:")) return null;
      if (base === identifier && version.length > 0) return version;
    }
  }

  // oci: find the `<image>:<tag>` arg whose image equals the locked identifier
  // (or the locked identifier already includes its own tag → strip it to match).
  const lockedImage = identifier.includes(":")
    ? identifier.slice(0, identifier.indexOf(":"))
    : identifier;
  for (const arg of args) {
    const colonIdx = arg.lastIndexOf(":");
    if (colonIdx > 0) {
      const image = arg.slice(0, colonIdx);
      const tag = arg.slice(colonIdx + 1);
      // Reject path-like false positives (e.g. "/usr/bin"): tags have no slash.
      if (image === lockedImage && tag.length > 0 && !tag.includes("/")) {
        return tag;
      }
    }
  }

  return null;
}

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
