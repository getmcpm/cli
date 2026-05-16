/**
 * `mcpm guard` Commander subcommand group (v0.5.0).
 *
 * v0.5.0 surface: demo, enable, disable, status, run --inner.
 * Other commands (accept-drift, mute/unmute, pause, reset-integrity,
 * cleanup, list-signatures) land in subsequent build steps per the
 * v0.5.0 design doc.
 */

import { Command } from "commander";
import type { ClientId } from "../config/paths.js";
import { CLIENT_IDS } from "../config/paths.js";

function isClientId(value: string): value is ClientId {
  return (CLIENT_IDS as readonly string[]).includes(value);
}

export function registerGuardCommand(program: Command): void {
  const guard = program
    .command("guard")
    .description("Runtime defense for MCP traffic")
    .action(async () => {
      // Bare `mcpm guard` — print status if any wraps exist, otherwise help
      // (DX review CRITICAL #1.1). Defers to status when there's anything
      // to show, falls back to Commander's help otherwise.
      const { runStatusCommand } = await import("../guard/cli.js");
      await runStatusCommand({ write: (s) => process.stdout.write(s), helpFallback: () => guard.help() });
    });

  guard
    .command("demo")
    .description("Run a synthetic attack-block demo (scenario: prompt-injection)")
    .action(async () => {
      const { runDemo } = await import("../guard/demo/runner.js");
      runDemo("prompt-injection", { write: (s) => process.stdout.write(s) });
    });

  guard
    .command("enable")
    .description("Wrap detected client configs with the inspection relay")
    .option("--client <name>", "limit to one client (claude-desktop|cursor|vscode|windsurf)")
    .option("--server <name>", "limit to one server name")
    .option("--dry-run", "print the planned changes without writing")
    .action(async (rawOpts: { client?: string; server?: string; dryRun?: boolean }) => {
      const { runEnableCommand } = await import("../guard/cli.js");
      const opts = parseClientServer(rawOpts);
      await runEnableCommand({
        ...opts,
        dryRun: rawOpts.dryRun === true,
        write: (s) => process.stdout.write(s),
      });
    });

  guard
    .command("disable")
    .description("Unwrap detected client configs (restore original entries)")
    .option("--client <name>", "limit to one client (claude-desktop|cursor|vscode|windsurf)")
    .option("--server <name>", "limit to one server name")
    .action(async (rawOpts: { client?: string; server?: string }) => {
      const { runDisableCommand } = await import("../guard/cli.js");
      const opts = parseClientServer(rawOpts);
      await runDisableCommand({ ...opts, write: (s) => process.stdout.write(s) });
    });

  guard
    .command("status")
    .description("Show which clients + servers are currently wrapped")
    .action(async () => {
      const { runStatusCommand } = await import("../guard/cli.js");
      await runStatusCommand({ write: (s) => process.stdout.write(s) });
    });

  guard
    .command("run")
    .description("Internal: relay entry point invoked by wrapped configs (semver-exempt)")
    .option("--inner", "required marker; this command is not for direct user use")
    .option("--server-name <name>", "server name (set by enable)")
    .allowUnknownOption()
    .allowExcessArguments()
    .action(async (opts: { inner?: boolean; serverName?: string }, cmd: Command) => {
      // SECURITY F6: refuse direct user invocation without the --inner marker.
      if (opts.inner !== true) {
        process.stderr.write(
          "mcpm guard run: --inner flag required (internal command, do not invoke directly).\n",
        );
        process.exit(1);
      }
      // SECURITY F1: Commander already consumed --server-name; pull from `opts`.
      // cmd.args contains everything after `--` (the wrapped server's command + args).
      if (typeof opts.serverName !== "string" || opts.serverName.length === 0) {
        process.stderr.write("mcpm guard run --inner: missing --server-name <name>.\n");
        process.exit(1);
      }
      const [command, ...args] = cmd.args;
      if (!command) {
        process.stderr.write("mcpm guard run --inner: missing -- <command>.\n");
        process.exit(1);
      }
      const { runInner } = await import("../guard/run-inner.js");
      const code = await runInner({ serverName: opts.serverName, command, args });
      process.exit(code);
    });
}

function parseClientServer(rawOpts: { client?: string; server?: string }): {
  client?: ClientId;
  server?: string;
} {
  const out: { client?: ClientId; server?: string } = {};
  if (rawOpts.client !== undefined) {
    if (!isClientId(rawOpts.client)) {
      throw new Error(
        `Unknown client "${rawOpts.client}". Must be one of: ${CLIENT_IDS.join(", ")}`,
      );
    }
    out.client = rawOpts.client;
  }
  if (rawOpts.server !== undefined) out.server = rawOpts.server;
  return out;
}
