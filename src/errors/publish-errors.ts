/**
 * Typed error codes + message templates for mcpm publish.
 * Pattern: mcpm <command>: <problem>.\n  Cause: <why>\n  Fix: <what to do>
 */

// Strip ANSI escape sequences and control characters from scanner messages
// before interpolating into user-facing error output.
const stripAnsi = (s: string) => s.replace(/[\x00-\x1F\x7F]|\x1B\[[0-9;]*m/g, "");

export const PublishErrors = {
  manifestNotFound(): Error {
    return new Error(
      [
        "mcpm publish: No .mcpm-publish.yaml found in this directory.",
        "  Cause: The publish manifest has not been created yet.",
        "  Fix:   Run 'mcpm publish scaffold' to create one, then re-run 'mcpm publish'.",
      ].join("\n")
    );
  },

  /** Pass blocking findings — callers pre-filter. Includes exfil-arg mediums (issue #24). */
  trustGateBlocked(
    findings: Array<{ severity: "critical" | "high" | "medium" | "low"; message: string }>
  ): Error {
    const list = findings
      .map((f) => `    [${f.severity.toUpperCase()}] ${stripAnsi(f.message)}`)
      .join("\n");
    return new Error(
      [
        "mcpm publish: Security findings block submission.",
        "  Cause: The server has critical/high findings, or data-exfiltration-shaped arguments.",
        "  Fix:   Resolve the findings below, then re-run 'mcpm publish check':",
        list,
      ].join("\n")
    );
  },

  registryApiUnavailable(): Error {
    return new Error(
      [
        "mcpm publish: The official registry publish API is not yet available.",
        "  Cause: registry.modelcontextprotocol.io does not yet accept CLI submissions.",
        "  Fix:   Watch https://github.com/getmcpm/cli for updates when publishing opens.",
      ].join("\n")
    );
  },

  tokenRequired(): Error {
    return new Error(
      [
        "mcpm publish: GitHub authentication required.",
        "  Cause: No GitHub token found in environment.",
        "  Fix:   Set GITHUB_TOKEN (or MCPM_TOKEN) in your environment:",
        "           export GITHUB_TOKEN=ghp_...",
        "         To create a token: https://github.com/settings/personal-access-tokens/new",
      ].join("\n")
    );
  },
} as const;
