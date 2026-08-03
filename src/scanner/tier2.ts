/**
 * Tier-2 scanner — optional external-scanner seam.
 *
 * Runs a scanner the USER has already installed, named explicitly via the
 * MCPM_EXTERNAL_SCANNER environment variable. Off by default. Gracefully
 * degrades to empty findings if the scanner is unconfigured, unavailable, or
 * emits output we cannot parse. All I/O is injectable via execImpl for testing.
 *
 * SECURITY — why this is an opt-in command and not an auto-fetched package:
 * this module used to invoke `npx @invariantlabs/mcp-scan`. That package does
 * not exist on npm (404) and the whole `@invariantlabs` scope is unregistered,
 * so tier-2 could never actually run — and worse, anyone who claimed the scope
 * would have had mcpm download and execute their code on every `mcpm audit`.
 * A scanner that fetches unowned names at audit time is the very supply-chain
 * shape mcpm exists to flag. So: mcpm never fetches a scanner. It runs a
 * command that is already on the machine, and refuses package-fetching runners
 * outright (see FETCHING_RUNNERS) so the vector cannot be reintroduced through
 * configuration.
 *
 * Invariant Labs' mcp-scan itself is distributed on PyPI (and since 2026-03 is
 * a redirect package for `snyk-agent-scan`), never on npm. Wiring that tool's
 * real CLI — it scans client config files, not registry server names — is
 * tracked as follow-up work, not silently assumed here.
 */

import type { Finding } from "./tier1.js";

// ---------------------------------------------------------------------------
// Scanner command resolution
// ---------------------------------------------------------------------------

/** Environment variable naming the external scanner executable. */
export const SCANNER_ENV_VAR = "MCPM_EXTERNAL_SCANNER";

/**
 * Runners that resolve a package from a remote registry and execute it in one
 * step. Permitting any of these would mean mcpm executes code it never
 * resolved, under a name it does not own — the exact failure this module was
 * fixed for. Matched on the basename, case-insensitively, minus a Windows
 * executable suffix. Shells are included because with mcpm's fixed argument
 * vector they can only be a wrapper hiding such a fetch.
 */
const FETCHING_RUNNERS: ReadonlySet<string> = new Set([
  // JS/TS
  "npx", "pnpx", "bunx", "dlx", "npm", "pnpm", "yarn", "bun", "deno",
  // Python
  "uvx", "uv", "pipx", "pip", "pip3",
  // Containers
  "docker", "podman",
  // Shells
  "sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh",
]);

const WINDOWS_EXEC_SUFFIX = /\.(exe|cmd|bat|ps1)$/i;

/** Outcome of resolving the configured external scanner. */
export type ScannerResolution =
  /** Not configured — tier 2 is off. This is the default. */
  | { status: "disabled" }
  /** Configured and structurally acceptable. Existence is checked separately. */
  | { status: "ready"; command: string }
  /** Configured but refused; `reason` is safe to show the user. */
  | { status: "rejected"; reason: string };

/**
 * Resolve the external scanner command from the environment.
 *
 * Pure: performs no I/O and never spawns anything. Structural validation only
 * — whether the command exists on PATH is answered by checkScannerAvailable().
 */
export function resolveScannerCommand(
  env: NodeJS.ProcessEnv = process.env,
): ScannerResolution {
  const raw = env[SCANNER_ENV_VAR];
  if (raw === undefined || raw.trim() === "") return { status: "disabled" };

  const command = raw.trim();

  // A command line, not an executable. Rejected rather than treated as a
  // (nonexistent) filename, so `MCPM_EXTERNAL_SCANNER="npx some-pkg"` cannot
  // slip a fetching runner past the basename check below.
  if (/\s/.test(command)) {
    return {
      status: "rejected",
      reason: `${SCANNER_ENV_VAR} must name a single executable, not a command line with arguments`,
    };
  }

  const basename = (command.split(/[/\\]/).pop() ?? command)
    .toLowerCase()
    .replace(WINDOWS_EXEC_SUFFIX, "");

  if (FETCHING_RUNNERS.has(basename)) {
    return {
      status: "rejected",
      reason:
        `${SCANNER_ENV_VAR} must not be a package runner or shell ("${basename}"). ` +
        "mcpm will not fetch and execute a scanner at audit time — install the " +
        "scanner first, then point this variable at the installed executable.",
    };
  }

  return { status: "ready", command };
}

// ---------------------------------------------------------------------------
// Server name validation
// ---------------------------------------------------------------------------

/**
 * Allowlist pattern for MCP server names passed to mcp-scan.
 * Matches patterns like "io.github.owner/repo-name".
 */
const SERVER_NAME_RE =
  /^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]\/[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$/;

/**
 * Validate a server name before passing it to the external scanner.
 * Throws if the name doesn't match the expected pattern.
 */
export function validateServerName(serverName: string): void {
  if (!SERVER_NAME_RE.test(serverName)) {
    throw new Error(
      `Rejected potentially malicious server name for scanner: "${serverName}"`
    );
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ExecResult {
  stdout: string;
  exitCode: number;
}

export type ExecImpl = (cmd: string, args: string[]) => Promise<ExecResult>;

export interface Tier2Options {
  execImpl?: ExecImpl;
  /** Environment to resolve the scanner command from. Defaults to process.env. */
  env?: NodeJS.ProcessEnv;
}

/** Shape of a single finding as returned by mcp-scan JSON output. */
interface McpScanFinding {
  severity?: string;
  description?: string;
  location?: string;
}

/** Shape of the mcp-scan JSON output we expect. */
interface McpScanOutput {
  findings?: McpScanFinding[];
}

// ---------------------------------------------------------------------------
// Default exec implementation (real child process — not used in tests)
// ---------------------------------------------------------------------------

async function defaultExec(cmd: string, args: string[]): Promise<ExecResult> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const execFileAsync = promisify(execFile);

  try {
    const { stdout } = await execFileAsync(cmd, args, {
      encoding: "utf8",
      timeout: 30_000,
    });
    return { stdout: stdout ?? "", exitCode: 0 };
  } catch (err: unknown) {
    const execErr = err as { stdout?: string; code?: number | string };
    return {
      stdout: execErr.stdout ?? "",
      exitCode: typeof execErr.code === "number" ? execErr.code : 1,
    };
  }
}

// ---------------------------------------------------------------------------
// Severity normalisation
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<string, Finding["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

function normaliseSeverity(raw: string | undefined): Finding["severity"] {
  // Issue #24: fail safe. An unknown/novel severity from the external scanner
  // (e.g. a new critical category) must NOT be silently downgraded to a
  // non-blocking level. Map anything unrecognised to "high" so the trust gate
  // treats it as blocking rather than letting it pass.
  return SEVERITY_MAP[raw?.toLowerCase() ?? ""] ?? "high";
}

// ---------------------------------------------------------------------------
// Diagnostic finding for scanner failures
// ---------------------------------------------------------------------------

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * A low-severity diagnostic surfaced when the external scanner could not be run
 * or its output could not be understood. This distinguishes "scanner failed /
 * not installed" from "scanner ran clean" (which returns []), without blocking
 * the install (low severity only deducts a small amount from the trust score).
 */
function scannerErrorFinding(message: string): Finding {
  return {
    severity: "low",
    type: "scanner-error",
    message,
    location: "external scan",
    source: "external",
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check whether an external scanner is configured AND runnable.
 *
 * Returns false — without spawning anything — when MCPM_EXTERNAL_SCANNER is
 * unset or refused, so the default install performs no subprocess work here.
 * Otherwise returns true if `<command> --version` exits 0. Gracefully returns
 * false on any error.
 */
export async function checkScannerAvailable(options?: Tier2Options): Promise<boolean> {
  const resolved = resolveScannerCommand(options?.env);
  if (resolved.status !== "ready") return false;

  const exec = options?.execImpl ?? defaultExec;
  try {
    const result = await exec(resolved.command, ["--version"]);
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

/**
 * Run the tier-2 external scanner against a server name.
 * Returns a new Finding[] (never mutates state).
 *
 * Behaviour:
 * - A non-zero exit with parseable JSON on stdout is still parsed — some
 *   scanners signal "issues found" via a non-zero exit code while still
 *   emitting valid findings JSON. Discarding it conflated "found issues" with
 *   "ran clean".
 * - A genuine failure (empty stdout, or stdout that doesn't parse) surfaces a
 *   single low-severity "scanner-error" diagnostic finding instead of a silent
 *   empty list, so "scanner failed / not installed" is distinguishable from
 *   "scanner ran clean" downstream.
 * - A clean run with an empty findings array returns [].
 *
 * All findings produced here are tagged source: "external" so the trust score
 * deducts them from the external sub-score only.
 */
export async function scanTier2(serverName: string, options?: Tier2Options): Promise<Finding[]> {
  const exec = options?.execImpl ?? defaultExec;

  // Step 1: validate server name to prevent injection
  validateServerName(serverName);

  // Step 2: resolve the configured scanner. Callers are responsible for
  // checking availability via checkScannerAvailable() first; re-resolving here
  // means a misconfiguration surfaces as a diagnostic rather than an
  // accidental spawn of whatever the environment happens to name.
  const resolved = resolveScannerCommand(options?.env);
  if (resolved.status === "disabled") {
    return [
      scannerErrorFinding(
        `external scanner is not configured (set ${SCANNER_ENV_VAR} to an installed scanner executable)`,
      ),
    ];
  }
  if (resolved.status === "rejected") {
    return [scannerErrorFinding(resolved.reason)];
  }

  // Step 3: run the scan
  let result: ExecResult;
  try {
    result = await exec(resolved.command, ["--json", serverName]);
  } catch (err: unknown) {
    return [scannerErrorFinding(`external scanner did not run: ${errorMessage(err)}`)];
  }

  const stdout = result.stdout;

  // Step 4: a non-zero exit with no output is a real failure. With output we
  // still attempt to parse — a scanner may exit non-zero precisely because it
  // found issues, while emitting valid findings JSON.
  if (!stdout || !stdout.trim()) {
    if (result.exitCode !== 0) {
      return [scannerErrorFinding(`external scanner failed (exit code ${result.exitCode})`)];
    }
    return [];
  }

  // Step 5: parse output
  let parsed: McpScanOutput;
  try {
    parsed = JSON.parse(stdout) as McpScanOutput;
  } catch {
    return [scannerErrorFinding("external scanner output could not be parsed as JSON")];
  }

  if (!Array.isArray(parsed.findings)) {
    return [scannerErrorFinding("external scanner output had no findings array")];
  }

  // Step 6: map to Finding[] immutably
  return parsed.findings.map((f): Finding => ({
    severity: normaliseSeverity(f.severity),
    type: "prompt-injection", // mcp-scan focuses on prompt injection / tool poisoning
    message: f.description ?? "External scanner finding",
    location: f.location ?? "external scan",
    source: "external",
  }));
}
