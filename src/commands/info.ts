/**
 * info command — displays full details about a single MCP server.
 *
 * Exports:
 * - handleInfo() — pure handler function with injectable dependencies for testing
 * - registerInfo() — registers the command on a Commander program
 *
 * Architecture:
 * - NotFoundError is caught and displayed as a user-friendly message (no throw).
 * - All other errors propagate to the top-level error handler.
 * - No console.log — all output routed through deps.output() for testability.
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import type { RegistryClient } from "../registry/client.js";
import type { ServerEntry } from "../registry/types.js";
import type { EnvVar, Package, Remote } from "../registry/types.js";
import { NotFoundError } from "../registry/errors.js";
import { OFFICIAL_META_KEY } from "../utils/format-trust.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InfoOptions {
  json?: boolean;
}

export interface InfoDeps {
  registryClient: Pick<RegistryClient, "getServer">;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Formatting helpers — pure functions
// ---------------------------------------------------------------------------

function formatDate(isoString: string | undefined): string {
  if (!isoString) return "—";
  return isoString.slice(0, 10); // YYYY-MM-DD
}

function envVarRequired(ev: EnvVar): string {
  if (ev.isRequired === true) return chalk.red("required");
  return chalk.dim("optional");
}

function renderPackageSection(packages: Package[], lines: string[]): void {
  if (packages.length === 0) {
    lines.push(chalk.dim("  (no packages)"));
    return;
  }

  for (const pkg of packages) {
    lines.push(`  ${chalk.yellow(pkg.registryType)}  ${pkg.identifier}  ${chalk.dim(pkg.version ?? "")}`);

    if (pkg.environmentVariables.length > 0) {
      lines.push("");
      lines.push(chalk.cyan("  Environment Variables:"));

      for (const ev of pkg.environmentVariables) {
        const req = envVarRequired(ev);
        const desc = ev.description ? chalk.dim(` — ${ev.description}`) : "";
        lines.push(`    ${chalk.white(ev.name)}  [${req}]${desc}`);
      }
    }
  }
}

function renderRemotesSection(remotes: Remote[], lines: string[]): void {
  if (remotes.length === 0) return;

  lines.push("");
  lines.push(chalk.cyan("Remotes:"));

  for (const remote of remotes) {
    lines.push(`  ${chalk.yellow(remote.type)}  ${remote.url}`);
  }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core handler for `mcpm info <name>`.
 * NotFoundError is handled gracefully (prints message, no throw).
 * All other errors propagate to the caller.
 */
export async function handleInfo(
  name: string,
  options: InfoOptions,
  deps: InfoDeps
): Promise<void> {
  const { registryClient, output } = deps;

  const spinner = ora({ text: "Fetching...", isSilent: !process.stdout.isTTY }).start();

  let entry: ServerEntry;
  try {
    entry = await registryClient.getServer(name);
  } catch (err) {
    spinner.stop();
    if (err instanceof NotFoundError) {
      output(`Server '${name}' not found`);
      return;
    }
    throw err;
  }

  spinner.stop();

  const { server, _meta } = entry;
  const official = _meta[OFFICIAL_META_KEY];

  // --json flag: output the full ServerEntry as JSON.
  if (options.json === true) {
    const jsonData = {
      name: server.name,
      title: server.title ?? null,
      description: server.description ?? null,
      version: server.version,
      repository: server.repository ?? null,
      websiteUrl: server.websiteUrl ?? null,
      packages: server.packages,
      remotes: server.remotes ?? [],
      status: official.status ?? null,
      publishedAt: official.publishedAt ?? null,
      updatedAt: official.updatedAt ?? null,
      isLatest: official.isLatest ?? null,
    };
    output(JSON.stringify(jsonData, null, 2));
    return;
  }

  // Render full detail view.
  const divider = chalk.dim("─".repeat(60));
  const lines: string[] = [];

  lines.push(divider);
  lines.push(`${chalk.bold.white(server.name)}  ${chalk.dim(`v${server.version}`)}`);

  if (server.title) {
    lines.push(chalk.dim(server.title));
  }

  if (server.description) {
    lines.push("");
    lines.push(server.description);
  }

  lines.push("");

  // Metadata row
  lines.push(chalk.cyan("Status:       ") + (official.status ?? "—"));
  lines.push(chalk.cyan("Published:    ") + formatDate(official.publishedAt));

  if (server.repository) {
    lines.push(chalk.cyan("Repository:   ") + server.repository.url);
  }

  if (server.websiteUrl) {
    lines.push(chalk.cyan("Website:      ") + server.websiteUrl);
  }

  lines.push("");
  lines.push(chalk.cyan("Packages:"));
  renderPackageSection(server.packages, lines);

  renderRemotesSection(server.remotes ?? [], lines);

  lines.push("");
  lines.push(divider);
  lines.push(chalk.dim(`Install with: `) + chalk.white(`mcpm install ${name}`));
  lines.push(divider);

  output(lines.join("\n"));
}

// ---------------------------------------------------------------------------
// Command registration
// ---------------------------------------------------------------------------

/**
 * Registers the `info <name>` command on the given Commander program.
 */
export function registerInfo(program: Command): void {
  program
    .command("info <name>")
    .description("Show full details for an MCP server")
    .option("--json", "Output raw JSON instead of formatted display")
    .action(async (name: string, opts: { json?: boolean }) => {
      const { RegistryClient } = await import("../registry/client.js");
      const client = new RegistryClient();
      await handleInfo(
        name,
        { json: opts.json },
        { registryClient: client, output: (text) => process.stdout.write(text + "\n") }
      );
    });
}
