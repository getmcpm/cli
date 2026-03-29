/**
 * `mcpm doctor` command handler.
 *
 * Checks MCP setup health and reports issues:
 * - Which AI clients have config files
 * - Whether config files are valid JSON
 * - Which runtimes (npx, uvx, docker) are available
 * - Whether installed servers reference available runtimes
 *
 * Returns 0 for no critical issues, 1 for critical issues.
 * All external dependencies are injected for testability.
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { detectInstalledClients } from "../config/detector.js";
import type { getConfigPath } from "../config/paths.js";

// ---------------------------------------------------------------------------
// Deps interface
// ---------------------------------------------------------------------------

export interface DoctorDeps {
  detectClients: typeof detectInstalledClients;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: typeof getConfigPath;
  /** Returns true if the config file exists for this client. */
  checkConfigExists: (clientId: ClientId) => Promise<boolean>;
  /** Returns true if the given executable is available on PATH. */
  execCheck: (cmd: string) => Promise<boolean>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALL_CLIENTS: ClientId[] = ["claude-desktop", "cursor", "vscode", "windsurf"];
const RUNTIMES = ["npx", "uvx", "docker"] as const;

type Runtime = (typeof RUNTIMES)[number];

const CLIENT_LABELS: Record<ClientId, string> = {
  "claude-desktop": "Claude Desktop",
  cursor: "Cursor",
  vscode: "VS Code",
  windsurf: "Windsurf",
};

const RUNTIME_INSTALL_HINTS: Record<Runtime, string> = {
  npx: "install Node.js from https://nodejs.org",
  uvx: "install uv from https://docs.astral.sh/uv/",
  docker: "install Docker from https://docs.docker.com/get-docker/",
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm doctor`.
 * @returns Exit code: 0 = healthy, 1 = critical issues found.
 */
export async function doctorHandler(deps: DoctorDeps): Promise<number> {
  const {
    getAdapter,
    getConfigPath,
    checkConfigExists,
    execCheck,
    output,
  } = deps;

  const issues: string[] = [];

  // -------------------------------------------------------------------------
  // 1. Check each known client for a config file.
  // -------------------------------------------------------------------------

  output("");
  output("mcpm doctor");
  output("");

  // Map of clientId → { exists, servers?, malformed? }
  const clientResults: Record<
    ClientId,
    { exists: boolean; servers?: Record<string, McpServerEntry>; malformed?: boolean }
  > = {} as Record<ClientId, { exists: boolean; servers?: Record<string, McpServerEntry>; malformed?: boolean }>;

  const clientChecks = await Promise.all(
    ALL_CLIENTS.map(async (clientId) => {
      const exists = await checkConfigExists(clientId);
      if (!exists) {
        return { clientId, result: { exists: false } as { exists: boolean; servers?: Record<string, McpServerEntry>; malformed?: boolean }, issue: null as string | null };
      }
      const adapter = getAdapter(clientId);
      const configPath = getConfigPath(clientId);
      try {
        const servers = await adapter.listServers(configPath);
        return { clientId, result: { exists: true, servers }, issue: null as string | null };
      } catch {
        return {
          clientId,
          result: { exists: true, malformed: true } as { exists: boolean; servers?: Record<string, McpServerEntry>; malformed?: boolean },
          issue: `Config file for ${CLIENT_LABELS[clientId]} is malformed — fix the JSON syntax.`,
        };
      }
    })
  );

  for (const { clientId, result, issue } of clientChecks) {
    clientResults[clientId] = result;
    if (!result.exists) {
      output(`  ✗ ${CLIENT_LABELS[clientId]} — config not found`);
    } else if (result.malformed) {
      output(`  ✗ ${CLIENT_LABELS[clientId]} — config malformed (JSON parse error)`);
      if (issue) issues.push(issue);
    } else {
      const count = Object.keys(result.servers ?? {}).length;
      const serverWord = count === 1 ? "server" : "servers";
      output(`  ✓ ${CLIENT_LABELS[clientId]} — config found, ${count} ${serverWord}`);
    }
  }

  // -------------------------------------------------------------------------
  // 2. Check runtime availability.
  // -------------------------------------------------------------------------

  output("");
  output("Runtimes:");

  const runtimeChecks = await Promise.all(
    RUNTIMES.map(async (runtime) => {
      const available = await execCheck(runtime);
      return { runtime, available };
    })
  );

  const runtimeAvailable: Record<string, boolean> = {};
  for (const { runtime, available } of runtimeChecks) {
    runtimeAvailable[runtime] = available;
    if (available) {
      output(`  ✓ ${runtime} available`);
    } else {
      const hint = RUNTIME_INSTALL_HINTS[runtime];
      output(`  ✗ ${runtime} not found — ${hint}`);
    }
  }

  // -------------------------------------------------------------------------
  // 3. Cross-check: servers that require an unavailable runtime.
  // -------------------------------------------------------------------------

  for (const clientId of ALL_CLIENTS) {
    const result = clientResults[clientId];
    if (!result?.exists || result.malformed || !result.servers) {
      continue;
    }

    for (const [serverName, entry] of Object.entries(result.servers)) {
      if (!entry.command) {
        // HTTP server — no runtime needed.
        continue;
      }

      const cmd = entry.command;
      // Only flag known runtimes that we track.
      if (RUNTIMES.includes(cmd as Runtime) && !runtimeAvailable[cmd]) {
        issues.push(
          `Server '${serverName}' in ${CLIENT_LABELS[clientId]} uses '${cmd}' but ${cmd} is not installed.`
        );
      }
    }
  }

  // -------------------------------------------------------------------------
  // 4. Print issues and summary.
  // -------------------------------------------------------------------------

  if (issues.length > 0) {
    output("");
    output("Issues:");
    for (const issue of issues) {
      output(`  ⚠ ${issue}`);
    }
    output("");
    output("Critical issues found. Run the commands above to resolve them.");
    return 1;
  }

  output("");
  output("No critical issues found.");
  return 0;
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import chalk from "chalk";
import { access } from "fs/promises";
import { execFile } from "child_process";
import { detectInstalledClients as _detectClients } from "../config/detector.js";
import { getConfigPath as _getConfigPath, CLIENT_IDS } from "../config/paths.js";
import {
  ClaudeDesktopAdapter,
  CursorAdapter,
  VSCodeAdapter,
  WindsurfAdapter,
} from "../config/index.js";

function getAdapterDefault(clientId: ClientId): ConfigAdapter {
  switch (clientId) {
    case "claude-desktop":
      return new ClaudeDesktopAdapter();
    case "cursor":
      return new CursorAdapter();
    case "vscode":
      return new VSCodeAdapter();
    case "windsurf":
      return new WindsurfAdapter();
    default: {
      const _never: never = clientId;
      throw new Error(`Unknown clientId: ${String(_never)}`);
    }
  }
}

async function checkConfigExistsDefault(clientId: ClientId): Promise<boolean> {
  try {
    await access(_getConfigPath(clientId));
    return true;
  } catch {
    return false;
  }
}

function execCheckDefault(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const which = process.platform === "win32" ? "where" : "which";
    execFile(which, [cmd], (err) => {
      resolve(err === null);
    });
  });
}

function coloredOutput(text: string): void {
  if (text.startsWith("  ✓")) {
    console.log(chalk.green(text));
  } else if (text.startsWith("  ✗")) {
    console.log(chalk.red(text));
  } else if (text.startsWith("  ⚠")) {
    console.log(chalk.yellow(text));
  } else {
    console.log(text);
  }
}

export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor")
    .description("Check MCP setup health and report issues")
    .action(async () => {
      const deps: DoctorDeps = {
        detectClients: _detectClients,
        getAdapter: getAdapterDefault,
        getConfigPath: _getConfigPath,
        checkConfigExists: checkConfigExistsDefault,
        execCheck: execCheckDefault,
        output: coloredOutput,
      };

      const exitCode = await doctorHandler(deps);
      process.exit(exitCode);
    });
}
