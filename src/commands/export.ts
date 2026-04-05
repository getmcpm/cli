/**
 * `mcpm export` command handler.
 *
 * Reads installed MCP servers across all detected clients and produces
 * an mcpm.yaml stack file. Deduplicates by server name (first-seen-wins).
 * Env var keys are exported without values; secret status is inferred
 * from common naming patterns (TOKEN, KEY, SECRET, PASSWORD).
 *
 * Exports:
 * - handleExport()           — injectable handler for testing
 * - registerExportCommand()  — Commander registration
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { StackFile, StackEnvVar } from "../stack/schema.js";
import { serializeYaml } from "../stack/schema.js";

// ---------------------------------------------------------------------------
// Secret inference
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  /TOKEN/i,
  /KEY/i,
  /SECRET/i,
  /PASSWORD/i,
  /CREDENTIAL/i,
  /AUTH/i,
];

function inferSecret(envName: string): boolean {
  return SECRET_PATTERNS.some((p) => p.test(envName));
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ExportOptions {
  output?: string;
  json?: boolean;
}

export interface ExportDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "read">;
  getPath: (clientId: ClientId) => string;
  writeFile: (path: string, content: string) => Promise<void>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core handler for `mcpm export`.
 *
 * Reads installed servers across all detected clients, deduplicates by name
 * (first-seen-wins by client detection order), and produces mcpm.yaml.
 */
export async function handleExport(
  options: ExportOptions,
  deps: ExportDeps
): Promise<void> {
  const { detectClients, getAdapter, getPath, writeFile, output } = deps;

  const clients = await detectClients();
  const seen = new Set<string>();
  const servers: Record<string, { entry: McpServerEntry }> = {};

  for (const clientId of clients) {
    try {
      const adapter = getAdapter(clientId);
      const configPath = getPath(clientId);
      const installed = await adapter.read(configPath);

      for (const [name, entry] of Object.entries(installed)) {
        if (seen.has(name)) continue;
        seen.add(name);
        servers[name] = { entry: { ...entry } };
      }
    } catch {
      // Skip clients with unreadable configs
    }
  }

  const stackFile = buildStackFile(servers);
  const yaml = serializeYaml(stackFile);

  if (options.output) {
    await writeFile(options.output, yaml);
    output(`Exported ${Object.keys(servers).length} servers to ${options.output}`);
  } else {
    output(yaml);
  }
}

// ---------------------------------------------------------------------------
// Stack file builder
// ---------------------------------------------------------------------------

function buildStackFile(
  servers: Record<string, { entry: McpServerEntry }>
): StackFile {
  const stackServers: StackFile["servers"] = {};

  for (const [name, { entry }] of Object.entries(servers)) {
    if (entry.url) {
      // URL-based server
      stackServers[name] = {
        url: entry.url,
        ...(entry.env ? { env: buildEnvDeclarations(entry.env) } : {}),
      };
    } else {
      // Registry-based server (version unknown from config, use latest)
      stackServers[name] = {
        version: "latest",
        ...(entry.env ? { env: buildEnvDeclarations(entry.env) } : {}),
      };
    }
  }

  return {
    version: "1",
    servers: stackServers,
  };
}

function buildEnvDeclarations(
  env: Record<string, string>
): Record<string, StackEnvVar> {
  const declarations: Record<string, StackEnvVar> = {};

  for (const key of Object.keys(env)) {
    declarations[key] = {
      required: true,
      secret: inferSecret(key),
    };
  }

  return declarations;
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import { writeFile as fsWriteFile } from "fs/promises";
import { detectInstalledClients } from "../config/detector.js";
import { getConfigPath } from "../config/paths.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { stdoutOutput } from "../utils/output.js";

export function registerExportCommand(program: Command): void {
  program
    .command("export")
    .description("Export installed MCP servers as an mcpm.yaml stack file")
    .option("-o, --output <file>", "write to file instead of stdout")
    .action(async (opts: { output?: string }) => {
      const chalk = (await import("chalk")).default;
      try {
        await handleExport(
          { output: opts.output },
          {
            detectClients: detectInstalledClients,
            getAdapter: getAdapterDefault,
            getPath: getConfigPath,
            writeFile: (path, content) =>
              fsWriteFile(path, content, { encoding: "utf-8", mode: 0o600 }),
            output: stdoutOutput,
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
