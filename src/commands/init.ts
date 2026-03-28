/**
 * `mcpm init <pack>` command — install curated starter packs of MCP servers.
 *
 * Exports:
 * - handleInit() — pure handler with injectable deps for testing
 * - registerInitCommand() — registers the command on a Commander program
 * - PACKS — the curated pack definitions (exported for tests and introspection)
 *
 * Architecture:
 * - installServer is injectable so init does not implement the full install flow.
 * - If one server in a pack fails, installation continues with others.
 * - Reports final results: "Installed 2/3 servers from 'developer' pack. Failed: ..."
 */

import { Command } from "commander";
import chalk from "chalk";
import type { ClientId } from "../config/paths.js";

// ---------------------------------------------------------------------------
// Pack definitions
// ---------------------------------------------------------------------------

export interface PackDefinition {
  description: string;
  servers: string[];
}

/**
 * Curated starter packs — server names use real registry identifiers.
 * These will be updated to verified names once registry lookup confirms them.
 */
export const PACKS: Record<string, PackDefinition> = {
  developer: {
    description: "Essential developer tools — filesystem, git, and GitHub",
    servers: [
      "io.github.modelcontextprotocol/servers-filesystem",
      "io.github.modelcontextprotocol/servers-git",
      "io.github.modelcontextprotocol/servers-github",
    ],
  },
  data: {
    description: "Database tools — PostgreSQL and SQLite",
    servers: [
      "io.github.modelcontextprotocol/servers-postgres",
      "io.github.modelcontextprotocol/servers-sqlite",
    ],
  },
  web: {
    description: "Web browsing and fetching — HTTP fetch and Puppeteer browser automation",
    servers: [
      "io.github.modelcontextprotocol/servers-fetch",
      "io.github.modelcontextprotocol/servers-puppeteer",
    ],
  },
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InitOptions {
  yes?: boolean;
  client?: string;
}

export interface InstallResult {
  success: boolean;
  error?: string;
}

export interface InitDeps {
  installServer: (
    name: string,
    options: { yes: boolean; client?: string }
  ) => Promise<InstallResult>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm init [pack]`.
 */
export async function handleInit(
  packName: string | undefined,
  options: InitOptions,
  deps: InitDeps
): Promise<void> {
  const { installServer, output } = deps;

  // No pack name — list available packs
  if (packName === undefined) {
    output(chalk.bold("Available starter packs:\n"));
    for (const [name, pack] of Object.entries(PACKS)) {
      output(`  ${chalk.cyan(name.padEnd(12))} ${pack.description}`);
      output(`    Servers: ${pack.servers.join(", ")}`);
      output("");
    }
    output(`Usage: ${chalk.white("mcpm init <pack>")} (e.g. mcpm init developer)`);
    return;
  }

  // Validate pack name
  if (!Object.prototype.hasOwnProperty.call(PACKS, packName)) {
    const available = Object.keys(PACKS).join(", ");
    output(chalk.red(`Unknown pack '${packName}'. Available: ${available}`));
    return;
  }

  const pack = PACKS[packName];
  output(chalk.bold(`Installing '${packName}' pack: ${pack.description}\n`));

  // Install each server in the pack — continue on failure
  const succeeded: string[] = [];
  const failed: Array<{ name: string; error: string }> = [];

  for (const serverName of pack.servers) {
    output(`  Installing ${chalk.white(serverName)}...`);
    const result = await installServer(serverName, {
      yes: options.yes ?? false,
      client: options.client,
    });

    if (result.success) {
      succeeded.push(serverName);
      output(`  ${chalk.green("✓")} ${serverName}`);
    } else {
      failed.push({ name: serverName, error: result.error ?? "unknown error" });
      output(`  ${chalk.red("✗")} ${serverName}: ${result.error ?? "unknown error"}`);
    }
  }

  // Summary
  output("");
  const total = pack.servers.length;
  const successCount = succeeded.length;

  if (failed.length === 0) {
    output(
      chalk.green(
        `Installed ${successCount}/${total} servers from '${packName}' pack.`
      )
    );
  } else {
    const failedNames = failed.map((f) => f.name).join(", ");
    output(
      chalk.yellow(
        `Installed ${successCount}/${total} servers from '${packName}' pack. Failed: ${failedNames}`
      )
    );
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerInitCommand(program: Command): void {
  program
    .command("init [pack]")
    .description("Install a curated starter pack of MCP servers")
    .option("-y, --yes", "Skip all confirmation prompts")
    .option("-c, --client <id>", "Install only for this specific client")
    .action(async (pack: string | undefined, opts: { yes?: boolean; client?: string }) => {
      // Lazy import of install command to avoid circular dependency
      const { handleInstall, resolveInstallEntry } = await import("./install.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { detectInstalledClients } = await import("../config/detector.js");
      const { getConfigPath } = await import("../config/paths.js");
      const {
        ClaudeDesktopAdapter,
        CursorAdapter,
        VSCodeAdapter,
        WindsurfAdapter,
      } = await import("../config/index.js");
      const { addInstalledServer } = await import("../store/servers.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { checkScannerAvailable, scanTier2 } = await import("../scanner/tier2.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");

      const registryClient = new RegistryClient();

      function getAdapter(clientId: ClientId) {
        switch (clientId) {
          case "claude-desktop": return new ClaudeDesktopAdapter();
          case "cursor": return new CursorAdapter();
          case "vscode": return new VSCodeAdapter();
          case "windsurf": return new WindsurfAdapter();
          default: throw new Error(`Unknown clientId: ${String(clientId)}`);
        }
      }

      async function installServer(
        name: string,
        installOpts: { yes: boolean; client?: string }
      ): Promise<{ success: boolean; error?: string }> {
        try {
          await handleInstall(name, { yes: installOpts.yes, client: installOpts.client }, {
            registryClient,
            detectClients: detectInstalledClients,
            getAdapter,
            getConfigPath,
            resolveEntry: resolveInstallEntry,
            addToStore: addInstalledServer,
            promptEnvVars: async () => ({}),
            confirm: async () => true,
            scanTier1,
            checkScannerAvailable,
            scanTier2,
            computeTrustScore,
            output: (text) => process.stdout.write(text + "\n"),
          });
          return { success: true };
        } catch (err) {
          return { success: false, error: (err as Error).message };
        }
      }

      const deps: InitDeps = {
        installServer,
        output: (text) => process.stdout.write(text + "\n"),
      };

      await handleInit(pack, { yes: opts.yes, client: opts.client }, deps).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });
}
