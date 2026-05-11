/**
 * Typed error codes + message templates for mcpm publish.
 * Pattern: mcpm <command>: <problem>.\n  Cause: <why>\n  Fix: <what to do>
 */

// Strip ANSI escape sequences and control characters from scanner messages
// before interpolating into user-facing error output.
const stripAnsi = (s: string) => s.replace(/[\x00-\x1F\x7F]|\x1B\[[0-9;]*m/g, "");

export class PublishError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "PublishError";
  }
}

export const PublishErrors = {
  manifestNotFound(): PublishError {
    return new PublishError(
      "MANIFEST_NOT_FOUND",
      [
        "mcpm publish: No .mcpm-publish.yaml found in this directory.",
        "  Cause: The publish manifest has not been created yet.",
        "  Fix:   Run 'mcpm publish scaffold' to create one, then re-run 'mcpm publish'.",
      ].join("\n")
    );
  },

  /** Pass only critical/high findings — callers pre-filter. */
  trustGateBlocked(findings: Array<{ severity: "critical" | "high"; message: string }>): PublishError {
    const list = findings
      .map((f) => `    [${f.severity.toUpperCase()}] ${stripAnsi(f.message)}`)
      .join("\n");
    return new PublishError(
      "TRUST_GATE_BLOCKED",
      [
        "mcpm publish: Security findings block submission.",
        "  Cause: The server has critical or high severity findings.",
        "  Fix:   Resolve the findings below, then re-run 'mcpm publish check':",
        list,
      ].join("\n")
    );
  },

  registryApiUnavailable(): PublishError {
    return new PublishError(
      "REGISTRY_API_UNAVAILABLE",
      [
        "mcpm publish: The official registry publish API is not yet available.",
        "  Cause: registry.modelcontextprotocol.io does not yet accept CLI submissions.",
        "  Fix:   Watch https://github.com/getmcpm/cli for updates when publishing opens.",
      ].join("\n")
    );
  },

  tokenRequired(): PublishError {
    return new PublishError(
      "TOKEN_REQUIRED",
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
