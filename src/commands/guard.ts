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
    .command("accept-drift <server>")
    .description("Re-pin a server's tool schemas after a legitimate upgrade")
    .option("--tool <name>", "scope to a single tool (default: all tools on the server)")
    .option("--new-hash <hash>", "exact sha256:... to pin (copy from block-message remediation)")
    .option("--remove", "delete the pin entry entirely instead of re-pinning")
    .option("--yes", "skip interactive confirm (for CI)")
    .action(async (
      server: string,
      opts: { tool?: string; newHash?: string; remove?: boolean; yes?: boolean },
    ) => {
      // SECURITY F7: enforce --yes by gating the destructive operation on
      // user input when no flag is supplied. CI gets --yes; humans get a
      // one-line confirmation showing exactly what will change.
      if (opts.yes !== true) {
        const target = opts.tool !== undefined ? `tool "${opts.tool}"` : "all tools";
        const verb = opts.remove === true ? "drop the pin entries for" : "re-pin";
        const what = opts.remove === true ? "" : ` to ${opts.newHash ?? "(missing --new-hash)"}`;
        process.stdout.write(
          `About to ${verb} "${server}" ${target}${what}.\n` +
            `Re-run with --yes to confirm.\n`,
        );
        process.exit(1);
      }
      const { acceptDriftCommand } = await import("../guard/drift.js");
      try {
        await acceptDriftCommand(server, {
          toolName: opts.tool,
          remove: opts.remove === true,
          newHash: opts.newHash,
        });
      } catch (err) {
        process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
        process.exit(1);
      }
      const action = opts.remove === true ? "removed" : `re-pinned to ${opts.newHash}`;
      const scope = opts.tool !== undefined ? ` tool "${opts.tool}"` : " (all tools)";
      process.stdout.write(`mcpm guard accept-drift: ${server}${scope} ${action}.\n`);
    });

  guard
    .command("reset-integrity")
    .description("Regenerate the pins.json integrity sidecar (use after manually editing pins.json)")
    .option("--yes", "skip the safety warning (for CI / automation)")
    .action(async (opts: { yes?: boolean }) => {
      if (opts.yes !== true) {
        process.stdout.write(
          "WARNING: This command trusts whatever is currently in ~/.mcpm/pins.json.\n" +
            "If pins.json was modified by an untrusted process, this will bypass drift\n" +
            "detection for every pinned tool. Review the file first:\n\n" +
            "  cat ~/.mcpm/pins.json\n\n" +
            "Then re-run with --yes to confirm.\n",
        );
        process.exit(1);
      }
      const { resetIntegrity } = await import("../guard/pins.js");
      await resetIntegrity();
      process.stdout.write("mcpm guard reset-integrity: pins.json.integrity refreshed.\n");
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
