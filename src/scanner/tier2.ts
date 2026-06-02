/**
 * Tier-2 scanner — optional external MCP-Scan wrapper.
 *
 * Checks if @invariantlabs/mcp-scan is available via npx, then runs it.
 * Gracefully degrades to empty findings if scanner is unavailable or output
 * cannot be parsed. All I/O is injectable via execImpl for testing.
 */

import type { Finding } from "./tier1.js";

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
 * Check whether the mcp-scan CLI is available.
 * Returns true if `npx @invariantlabs/mcp-scan --version` exits 0.
 * Gracefully returns false on any error.
 */
export async function checkScannerAvailable(options?: Tier2Options): Promise<boolean> {
  const exec = options?.execImpl ?? defaultExec;
  try {
    const result = await exec("npx", ["@invariantlabs/mcp-scan", "--version"]);
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

  // NOTE: Callers are responsible for checking availability via checkScannerAvailable()
  // before calling this function. The internal availability check was removed to avoid
  // redundant npx --version calls on every scan.

  // Step 2: run the scan
  let result: ExecResult;
  try {
    result = await exec("npx", ["@invariantlabs/mcp-scan", "--json", serverName]);
  } catch (err: unknown) {
    return [scannerErrorFinding(`external scanner did not run: ${errorMessage(err)}`)];
  }

  const stdout = result.stdout;

  // Step 3: a non-zero exit with no output is a real failure. With output we
  // still attempt to parse — a scanner may exit non-zero precisely because it
  // found issues, while emitting valid findings JSON.
  if (!stdout || !stdout.trim()) {
    if (result.exitCode !== 0) {
      return [scannerErrorFinding(`external scanner failed (exit code ${result.exitCode})`)];
    }
    return [];
  }

  // Step 4: parse output
  let parsed: McpScanOutput;
  try {
    parsed = JSON.parse(stdout) as McpScanOutput;
  } catch {
    return [scannerErrorFinding("external scanner output could not be parsed as JSON")];
  }

  if (!Array.isArray(parsed.findings)) {
    return [scannerErrorFinding("external scanner output had no findings array")];
  }

  // Step 5: map to Finding[] immutably
  return parsed.findings.map((f): Finding => ({
    severity: normaliseSeverity(f.severity),
    type: "prompt-injection", // mcp-scan focuses on prompt injection / tool poisoning
    message: f.description ?? "External scanner finding",
    location: f.location ?? "external scan",
    source: "external",
  }));
}
