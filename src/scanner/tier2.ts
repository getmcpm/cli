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
 * (see FETCHING_RUNNERS) so a pasted `npx …` recipe — or a future mcpm default
 * drifting back toward one — cannot quietly re-create the vector. That refusal
 * is a footgun guard, NOT an attacker boundary: whoever sets this variable can
 * usually set PATH or drop a file too. The load-bearing changes are that the
 * unowned package name is gone and that an unset variable spawns nothing.
 *
 * Invariant Labs' mcp-scan itself is distributed on PyPI (and since 2026-03 is
 * a redirect package for `snyk-agent-scan`), never on npm.
 *
 * 2026-08-31: `snyk-agent-scan` was evaluated as a candidate for this seam
 * (backlog #32) and does NOT fit — confirmed against its README/CLI/JSON-output
 * docs, not assumed. Two independent mismatches, either one disqualifying:
 * (1) its CLI (`snyk-agent-scan scan [CONFIG_FILE...]`) auto-discovers and
 * scans installed agent CONFIG FILES, with no mode to hand it a single
 * not-yet-installed registry coordinate the way `scanTier2` calls scanners
 * here; for MCP entries it actively CONNECTS TO AND STARTS the stdio server
 * from the config to retrieve live tool descriptions, which conflicts with
 * mcpm's install-then-verify design at the two call sites (install/lock) where
 * this runs before the user has committed to installing. (2) it requires a
 * Snyk account + `SNYK_TOKEN` and sends component data to Snyk's Analysis API
 * by default — not the local-only posture "a scanner you already installed"
 * implies. Its JSON output is also path-keyed and nested
 * (`{path: {servers:[...], issues:[...]}}`), not the flat `{findings:[...]}`
 * this module parses — moot given the input mismatch. See the CLAUDE.md
 * 2026-08-31 decision row for the full evaluation. No known candidate meets
 * this seam's bar today (bare-identifier input, fully local, flat findings
 * output); this file's contract is the target shape, not something to bend.
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
  // JS/TS — including the -cli entrypoints these shims resolve to, since
  // /usr/bin/npx is a symlink to npm's npx-cli.js and naming that file
  // directly would otherwise sail past a shim-name-only check.
  "npx", "npx-cli", "pnpx", "bunx", "dlx",
  "npm", "npm-cli", "pnpm", "yarn", "bun", "deno", "corepack",
  // Python
  "uvx", "uv", "pipx", "pip", "pip3",
  // Containers
  "docker", "podman",
  // Shells
  "sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh",
]);

/** Executable and script suffixes stripped before the denylist comparison. */
const EXEC_SUFFIX = /\.(exe|cmd|bat|ps1|js|cjs|mjs)$/i;

/** Outcome of resolving the configured external scanner. */
export type ScannerResolution =
  /** Not configured — tier 2 is off. This is the default. */
  | { status: "disabled" }
  /** Configured and structurally acceptable. Existence is checked separately. */
  | { status: "ready"; command: string }
  /** Configured but refused; `reason` is safe to show the user. */
  | { status: "rejected"; reason: string };

/**
 * The denylisted runner name a path refers to, or undefined if it names none.
 *
 * Compares the basename with directories, case, and an executable/script suffix
 * removed. A path ending in a separator yields an empty basename and matches
 * nothing; such a value is left to fail at spawn time (ENOTDIR/ENOENT) rather
 * than being reported as a package runner it does not name.
 */
export function refusedRunnerName(commandPath: string): string | undefined {
  const basename = (commandPath.split(/[/\\]/).pop() ?? "")
    .toLowerCase()
    .replace(EXEC_SUFFIX, "");
  if (basename === "") return undefined;
  return FETCHING_RUNNERS.has(basename) ? basename : undefined;
}

function refusalReason(name: string): string {
  return (
    `${SCANNER_ENV_VAR} must not be a package runner or shell ("${name}"). ` +
    "mcpm will not fetch and execute a scanner at audit time — install the " +
    "scanner first, then point this variable at the installed executable."
  );
}

/**
 * Report a refused configuration once per process.
 *
 * Deduplicated because checkScannerAvailable runs per command and, in `mcpm
 * up`, per server — repeating the same misconfiguration line for every entry
 * would bury it. Injectable so tests never write to the real stderr.
 */
const warnedReasons = new Set<string>();
function warnOnce(reason: string, options?: Tier2Options): void {
  const emit = options?.onWarn ?? ((m: string) => process.stderr.write(`${m}\n`));
  if (warnedReasons.has(reason)) return;
  warnedReasons.add(reason);
  emit(reason);
}

/** Test seam: clear the once-per-process warning memo. */
export function resetScannerWarnings(): void {
  warnedReasons.clear();
}

/**
 * Resolve the external scanner command from the environment.
 *
 * Pure: performs no I/O and never spawns anything. Structural checks only.
 * Whether the command exists, and whether it is a SYMLINK to a denylisted
 * runner, is settled by checkScannerAvailable(), which can touch the disk.
 *
 * Scope, stated honestly: this denylist is a footgun guard, not an attacker
 * boundary. Anyone who can set this variable can usually also set PATH or drop
 * a file, in which case naming any binary at all is equivalent. What it does
 * buy is that a user pasting an `npx …` recipe, or a future mcpm default
 * drifting back toward one, is refused instead of quietly re-creating the
 * fetch-and-execute vector this seam was rebuilt to remove.
 */
export function resolveScannerCommand(
  env: NodeJS.ProcessEnv = process.env,
): ScannerResolution {
  const raw = env[SCANNER_ENV_VAR];
  if (raw === undefined || raw.trim() === "") return { status: "disabled" };

  const command = raw.trim();

  // Whitespace is NOT rejected, and the first token is NOT inspected. Both were
  // tried and both were wrong. A blanket whitespace rejection closes the seam on
  // Windows, whose install paths live under `C:\Program Files\…`; inspecting the
  // first token then refuses `/opt/npm scanner/bin/mcp-scan` as "npm", which is
  // the same false rejection wearing a smaller hat. There is no way to tell a
  // path-containing-a-space from a command line without touching the disk.
  //
  // Nothing is lost by allowing it: execFile never splits on whitespace, so
  // `MCPM_EXTERNAL_SCANNER="npx some-pkg"` is looked up as one literal filename,
  // does not exist, and fails to spawn — which checkScannerAvailable reports as a
  // could-not-run warning, so the user is told rather than left guessing.
  const refused = refusedRunnerName(command);
  if (refused !== undefined) return { status: "rejected", reason: refusalReason(refused) };

  return { status: "ready", command };
}

// ---------------------------------------------------------------------------
// Server name validation
// ---------------------------------------------------------------------------

/**
 * Allowlist pattern for MCP server names passed to the external scanner.
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
  /** Sink for misconfiguration warnings. Defaults to stderr. */
  onWarn?: (message: string) => void;
}

/** Shape of a single finding in the external scanner's JSON output. */
interface ExternalScanFinding {
  severity?: string;
  description?: string;
  location?: string;
}

/** Shape of the external scanner JSON output we expect. */
interface ExternalScanOutput {
  findings?: ExternalScanFinding[];
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
  if (resolved.status === "disabled") return false;
  if (resolved.status === "rejected") {
    // A refused value is a misconfiguration, not an absent scanner. Say so once
    // rather than falling back silently — otherwise the user is told "set
    // MCPM_EXTERNAL_SCANNER for deeper analysis" about the variable they just
    // set, with no hint that mcpm rejected it. stderr, so the MCP stdio
    // protocol channel on stdout is untouched.
    warnOnce(resolved.reason, options);
    return false;
  }

  // Follow symlinks before trusting the name. `/usr/bin/npx` is a symlink to
  // npm's `npx-cli.js`, so a link named `mcp-scan` pointing at a package runner
  // would pass a purely lexical check. Only meaningful for a value carrying a
  // path separator — a bare name is left to PATH, which this does not search.
  if (/[/\\]/.test(resolved.command)) {
    try {
      const { realpath } = await import("node:fs/promises");
      const target = await realpath(resolved.command);
      const refused = refusedRunnerName(target);
      if (refused !== undefined) {
        warnOnce(refusalReason(refused), options);
        return false;
      }
    } catch {
      // Unresolvable path — let the spawn below produce the real error.
    }
  }

  const exec = options?.execImpl ?? defaultExec;
  let ok = false;
  try {
    const result = await exec(resolved.command, ["--version"]);
    ok = result.exitCode === 0;
  } catch {
    ok = false;
  }
  if (!ok) {
    // Configured but unrunnable — a typo, a moved binary, or a command line such
    // as "my-scanner --flag" that names no real file. Without this the user is
    // told to set the variable they already set.
    warnOnce(
      `${SCANNER_ENV_VAR} is set to "${resolved.command}" but it could not be run — ` +
        "external scanning is disabled. Check the path, or unset the variable.",
      options,
    );
  }
  return ok;
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
    // Exit 0 with no output used to be read as "ran clean" and silently earned
    // the full external bucket. That was safe when the scanner was one known
    // tool; it is not now that MCPM_EXTERNAL_SCANNER names an arbitrary
    // executable, because silence is the signature of a binary that is not a
    // scanner at all (`/bin/true` exits 0 and says nothing). Treated as a
    // failed scan, which computeTrustScore reads as "no corroboration" and
    // drops the bucket rather than crediting 20/20.
    return [
      scannerErrorFinding(
        "external scanner exited 0 but produced no output — cannot confirm a scan ran",
      ),
    ];
  }

  // Step 5: parse output
  let parsed: ExternalScanOutput;
  try {
    parsed = JSON.parse(stdout) as ExternalScanOutput;
  } catch {
    return [scannerErrorFinding("external scanner output could not be parsed as JSON")];
  }

  if (!Array.isArray(parsed.findings)) {
    return [scannerErrorFinding("external scanner output had no findings array")];
  }

  // Step 6: map to Finding[] immutably.
  //
  // Scanner stdout is untrusted — an arbitrary user-named executable whose text
  // reaches `mcpm why`'s human renderer, a sink that was dead only because
  // availability was always false. It is sanitized at the RENDER site, not here:
  // sanitizeForTerminal also truncates to 256 chars, and `audit --json` /
  // `--sarif` feed machine consumers that must stay byte-faithful (the v0.20.0
  // decision — sanitize on human-render branches, JSON verbatim).
  return parsed.findings.map((f): Finding => ({
    severity: normaliseSeverity(f.severity),
    // NOTE: every finding is typed prompt-injection regardless of what the
    // scanner actually reported, which mis-files e.g. a CVE under the
    // prompt-injection SARIF rule. Pre-existing, newly reachable — TODOS #32.
    type: "prompt-injection",
    message: f.description ?? "External scanner finding",
    location: f.location ?? "external scan",
    source: "external",
  }));
}
