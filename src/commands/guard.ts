/**
 * `mcpm guard` Commander subcommand group (v0.5.0).
 *
 * Full v0.5.0 surface: demo, enable, disable, status, accept-drift,
 * mute, unmute, pause, cleanup, list-signatures, reset-integrity, run --inner.
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
    .option(
      "--allow-unguarded",
      "permit URL/HTTP-transport servers to run WITHOUT runtime guard inspection " +
        "(no MITM relay exists for non-stdio transports); records consent so future runs stay quiet",
    )
    .action(
      async (rawOpts: {
        client?: string;
        server?: string;
        dryRun?: boolean;
        allowUnguarded?: boolean;
      }) => {
        const { runEnableCommand } = await import("../guard/cli.js");
        const opts = parseClientServer(rawOpts);
        await runEnableCommand({
          ...opts,
          dryRun: rawOpts.dryRun === true,
          allowUnguarded: rawOpts.allowUnguarded === true,
          write: (s) => process.stdout.write(s),
        });
      },
    );

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
      let changed: boolean;
      try {
        changed = await acceptDriftCommand(server, {
          toolName: opts.tool,
          remove: opts.remove === true,
          newHash: opts.newHash,
        });
      } catch (err) {
        process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
        process.exit(1);
      }
      const scope = opts.tool !== undefined ? ` tool "${opts.tool}"` : " (all tools)";
      if (!changed) {
        process.stdout.write(
          `mcpm guard accept-drift: no existing pin for ${server}${scope}; ` +
            `nothing to ${opts.remove === true ? "remove" : "re-pin"}.\n`,
        );
      } else {
        const action = opts.remove === true ? "removed" : `re-pinned to ${opts.newHash}`;
        process.stdout.write(`mcpm guard accept-drift: ${server}${scope} ${action}.\n`);
      }
    });

  guard
    .command("mute <signature-id>")
    .description("Disable a signature (action: ignore). Use --for to auto-expire.")
    .option("--for <duration>", "duration: 30s, 5m, 1h, 24h, 7d")
    .action(async (sigId: string, opts: { for?: string }) => {
      // SECURITY F7: refuse unknown signature ids so users don't typo and
      // silently get no mute. Shows valid ids on mismatch.
      const { OWASP_MCP_TOP_10 } = await import("../guard/signatures.js");
      const validIds = new Set(OWASP_MCP_TOP_10.map((s) => s.id));
      if (!validIds.has(sigId)) {
        process.stderr.write(
          `Unknown signature id "${sigId}". Valid ids:\n` +
            OWASP_MCP_TOP_10.map((s) => `  ${s.id}`).join("\n") +
            "\n",
        );
        process.exit(1);
      }
      const { readPolicy, writePolicy, setOverride, parseDuration, isoOffsetFromNow } = await import(
        "../guard/policy.js"
      );
      let expiresAt: string | undefined;
      try {
        expiresAt = opts.for !== undefined ? isoOffsetFromNow(parseDuration(opts.for)) : undefined;
      } catch (err) {
        process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
        process.exit(1);
      }
      const policy = await readPolicy();
      const next = setOverride(policy, sigId, "ignore", expiresAt);
      await writePolicy(next);
      const until = expiresAt !== undefined ? ` until ${expiresAt}` : " (permanent until unmute)";
      process.stdout.write(`mcpm guard mute: signature "${sigId}" muted${until}.\n`);
    });

  guard
    .command("unmute <signature-id>")
    .description("Re-enable a muted signature")
    .action(async (sigId: string) => {
      const { readPolicy, writePolicy, removeOverride } = await import("../guard/policy.js");
      const policy = await readPolicy();
      const next = removeOverride(policy, sigId);
      await writePolicy(next);
      process.stdout.write(`mcpm guard unmute: signature "${sigId}" override removed.\n`);
    });

  guard
    .command("pause")
    .description("Pause all guard inspection (relay continues forwarding without scanning)")
    .option("--for <duration>", "duration: 30s, 5m, 1h, 24h, 7d (default: 10m)")
    .option("--off", "lift any active pause")
    .action(async (opts: { for?: string; off?: boolean }) => {
      const { readPolicy, writePolicy, setPausedUntil, parseDuration, isoOffsetFromNow } =
        await import("../guard/policy.js");
      const policy = await readPolicy();
      if (opts.off === true) {
        await writePolicy(setPausedUntil(policy, null));
        process.stdout.write("mcpm guard pause: cleared.\n");
        return;
      }
      const ms = parseDuration(opts.for ?? "10m");
      const until = isoOffsetFromNow(ms);
      await writePolicy(setPausedUntil(policy, until));
      process.stdout.write(`mcpm guard pause: inspection paused until ${until}.\n`);
    });

  guard
    .command("cleanup")
    .description("Prune pin entries for uninstalled servers + orphan wrap entries")
    .option("--yes", "skip the dry-run prompt")
    .action(async (opts: { yes?: boolean }) => {
      const { runCleanupCommand } = await import("../guard/cli.js");
      await runCleanupCommand({ apply: opts.yes === true, write: (s) => process.stdout.write(s) });
    });

  guard
    .command("list-signatures")
    .description("Show installed signatures (OWASP MCP Top 10 coverage)")
    .option("--json", "emit machine-readable JSON")
    .action(async (opts: { json?: boolean }) => {
      const { OWASP_MCP_TOP_10 } = await import("../guard/signatures.js");
      if (opts.json === true) {
        process.stdout.write(JSON.stringify(OWASP_MCP_TOP_10.map((s) => ({
          id: s.id,
          category: s.category,
          severity: s.severity,
          target: s.target,
          description: s.description,
        })), null, 2) + "\n");
        return;
      }
      process.stdout.write(`mcpm guard signatures (vendored, ${OWASP_MCP_TOP_10.length} total):\n\n`);
      for (const s of OWASP_MCP_TOP_10) {
        process.stdout.write(`  ${s.id}\n`);
        process.stdout.write(`    category : ${s.category}\n`);
        process.stdout.write(`    severity : ${s.severity}\n`);
        process.stdout.write(`    target   : ${s.target}\n`);
        process.stdout.write(`    details  : ${s.description}\n\n`);
      }
    });

  guard
    .command("reset-integrity")
    .description("Regenerate the pins.json or guard-policy.yaml integrity sidecar")
    .option("--policy", "reset the guard-policy.yaml sidecar instead of pins.json")
    .option("--yes", "skip the safety warning (for CI / automation)")
    .action(async (opts: { policy?: boolean; yes?: boolean }) => {
      const target = opts.policy === true ? "~/.mcpm/guard-policy.yaml" : "~/.mcpm/pins.json";
      if (opts.yes !== true) {
        process.stdout.write(
          `WARNING: This command trusts whatever is currently in ${target}.\n` +
            `If the file was modified by an untrusted process, this will bypass\n` +
            `${opts.policy === true ? "policy" : "drift"} enforcement. Review the file first:\n\n` +
            `  cat ${target}\n\n` +
            `Then re-run with --yes to confirm.\n`,
        );
        process.exit(1);
      }
      if (opts.policy === true) {
        const { resetPolicyIntegrity } = await import("../guard/policy.js");
        const did = await resetPolicyIntegrity();
        process.stdout.write(
          did
            ? "mcpm guard reset-integrity: guard-policy.yaml.integrity refreshed.\n"
            : "mcpm guard reset-integrity: no guard-policy.yaml found — nothing to refresh.\n",
        );
      } else {
        const { resetIntegrity } = await import("../guard/pins.js");
        const did = await resetIntegrity();
        process.stdout.write(
          did
            ? "mcpm guard reset-integrity: pins.json.integrity refreshed.\n"
            : "mcpm guard reset-integrity: no pins.json found — nothing to refresh.\n",
        );
      }
    });

  guard
    .command("run")
    .description("Internal: relay entry point invoked by wrapped configs (semver-exempt)")
    .option("--inner", "required marker; this command is not for direct user use")
    .option("--server-name <name>", "server name (set by enable)")
    .option("--declared-env <csv>", "comma-separated declared env key names (set by enable)")
    .option("--orig-hash <hex>", "integrity hash of the original entry (set by enable)")
    .allowUnknownOption()
    .allowExcessArguments()
    .action(
      async (
        opts: { inner?: boolean; serverName?: string; declaredEnv?: string; origHash?: string },
        cmd: Command,
      ) => {
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
        // Issue #20: declared env key names are embedded in the wrap marker by
        // `enable`; run-inner uses them to forward ONLY a safe baseline + the
        // server's declared vars to the wrapped child (not the relay's full env).
        const declaredEnvKeys =
          typeof opts.declaredEnv === "string" && opts.declaredEnv.length > 0
            ? opts.declaredEnv.split(",")
            : [];
        const { runInner } = await import("../guard/run-inner.js");
        const code = await runInner({
          serverName: opts.serverName,
          command,
          args,
          declaredEnvKeys,
          // Issue #29: forward the marker's --orig-hash so run-inner can verify
          // wrap-marker integrity at spawn (previously parsed here but dropped).
          origHash: opts.origHash,
        });
        process.exit(code);
      },
    );
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
