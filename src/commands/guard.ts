/**
 * `mcpm guard` Commander subcommand group (v0.5.0).
 *
 * v0.5.0 surface: `mcpm guard demo` (synthetic prompt-injection scenario).
 * Other commands (`enable`, `disable`, `status`, `accept-drift`, `mute`,
 * `unmute`, `pause`, `reset-integrity`, `cleanup`, `list-signatures`)
 * land in subsequent build steps per the v0.5.0 design doc.
 */

import { Command } from "commander";

export function registerGuardCommand(program: Command): void {
  const guard = program
    .command("guard")
    .description("Runtime defense for MCP traffic (v0.5.0 — demo only)");

  guard
    .command("demo")
    .description("Run a synthetic attack-block demo (scenario: prompt-injection)")
    .action(async () => {
      const { runDemo } = await import("../guard/demo/runner.js");
      runDemo("prompt-injection", { write: (s) => process.stdout.write(s) });
    });
}
