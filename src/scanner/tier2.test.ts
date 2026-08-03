/**
 * Tests for src/scanner/tier2.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - execImpl is always a vi.fn() — NO real child processes.
 * - Tests cover: parse failure, partial output, empty output, findings returned,
 *   graceful degradation.
 * - Callers are responsible for calling checkScannerAvailable() before scanTier2().
 *   scanTier2() no longer calls checkScannerAvailable() internally.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  SCANNER_ENV_VAR,
  checkScannerAvailable,
  resetScannerWarnings,
  resolveScannerCommand,
  scanTier2,
  validateServerName,
} from "./tier2.js";

// Tier 2 is off unless the user names an installed scanner. Most tests below
// exercise the wrapper logic, so they opt in to a configured scanner; the
// unconfigured path has its own dedicated blocks.
beforeEach(() => {
  vi.stubEnv(SCANNER_ENV_VAR, "mcp-scan");
  resetScannerWarnings();
});
afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// resolveScannerCommand — the security boundary
// ---------------------------------------------------------------------------

describe("resolveScannerCommand", () => {
  it("is disabled when the variable is unset", () => {
    expect(resolveScannerCommand({})).toEqual({ status: "disabled" });
  });

  it("is disabled when the variable is empty or whitespace", () => {
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: "" })).toEqual({ status: "disabled" });
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: "   " })).toEqual({ status: "disabled" });
  });

  it("accepts a bare executable name and an absolute path", () => {
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: "snyk-agent-scan" })).toEqual({
      status: "ready",
      command: "snyk-agent-scan",
    });
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: "/opt/tools/my-scanner" })).toEqual({
      status: "ready",
      command: "/opt/tools/my-scanner",
    });
  });

  it("trims surrounding whitespace", () => {
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: "  mcp-scan  " })).toEqual({
      status: "ready",
      command: "mcp-scan",
    });
  });

  // The regression this module was fixed for: mcpm must never fetch-and-execute
  // a scanner package at audit time. `npx @invariantlabs/mcp-scan` 404s and the
  // scope is unregistered, so squatting it would have been arbitrary code
  // execution on every `mcpm audit`. Configuration must not reopen that door.
  it.each([
    "npx", "pnpx", "bunx", "dlx", "npm", "pnpm", "yarn", "bun", "deno",
    "uvx", "uv", "pipx", "pip", "pip3",
    "docker", "podman",
    "sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh",
  ])("refuses the package runner / shell %s", (runner) => {
    const result = resolveScannerCommand({ [SCANNER_ENV_VAR]: runner });
    expect(result.status).toBe("rejected");
  });

  // Each case asserts the REASON, not just the status: a case that is rejected
  // for an unrelated reason would otherwise "pass" without ever exercising the
  // path/case/suffix logic it is named for.
  it.each([
    ["/usr/local/bin/npx", "npx"],
    ["NPX", "npx"],
    ["Npx.EXE", "npx"],
    ["C:\\Program Files\\nodejs\\npx.cmd", "npx"],
    ["/opt/homebrew/bin/pnpm", "pnpm"],
  ])("refuses %s by path, case, and executable suffix", (value, expected) => {
    const result = resolveScannerCommand({ [SCANNER_ENV_VAR]: value });
    expect(result.status, value).toBe("rejected");
    if (result.status === "rejected") expect(result.reason).toContain(`"${expected}"`);
  });

  // The real npx on this machine is a symlink to npm's npx-cli.js. Naming that
  // script directly sails past a shim-name-only denylist, so the -cli
  // entrypoints are denied by name too.
  it.each([
    "/opt/node22/lib/node_modules/npm/bin/npx-cli.js",
    "/usr/lib/node_modules/npm/bin/npm-cli.js",
    "/usr/local/lib/node_modules/pnpm/bin/pnpm.cjs",
  ])("refuses the runner entrypoint script %s", (value) => {
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: value }).status, value).toBe("rejected");
  });

  // Whitespace handling has two failure modes and this pins both. Rejecting any
  // value with a space closes the seam on Windows; inspecting only the first
  // token then refuses "/opt/npm scanner/bin/mcp-scan" as "npm". Real install
  // paths must resolve, including ones whose leading component names a runner.
  it.each([
    "C:\\Program Files\\Snyk\\snyk-agent-scan.exe",
    "/Applications/My Scanner.app/Contents/MacOS/scan",
    "/opt/npm scanner/bin/mcp-scan",
    "/usr/local/uv tools/scan",
  ])("accepts a legitimate path containing spaces: %s", (value) => {
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: value })).toEqual({
      status: "ready",
      command: value,
    });
  });

  // A pasted "npx <pkg>" is allowed through as a literal filename rather than
  // refused. That is safe — execFile does not split on whitespace, so it names
  // one nonexistent file — and checkScannerAvailable reports it as unrunnable.
  it("treats a command line as a filename, not an argument vector", () => {
    expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: "npx @invariantlabs/mcp-scan" })).toEqual({
      status: "ready",
      command: "npx @invariantlabs/mcp-scan",
    });
  });
});

// ---------------------------------------------------------------------------
// checkScannerAvailable
// ---------------------------------------------------------------------------

describe("checkScannerAvailable", () => {
  it("returns true when exec succeeds with exit code 0", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "mcp-scan 0.1.0", exitCode: 0 });
    const result = await checkScannerAvailable({ execImpl });
    expect(result).toBe(true);
  });

  it("returns false when exec fails with non-zero exit code", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "", exitCode: 1 });
    const result = await checkScannerAvailable({ execImpl });
    expect(result).toBe(false);
  });

  it("returns false when exec rejects (tool not found)", async () => {
    const execImpl = vi.fn().mockRejectedValue(new Error("command not found: npx"));
    const result = await checkScannerAvailable({ execImpl });
    expect(result).toBe(false);
  });

  it("calls the configured executable with --version", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "0.1.0", exitCode: 0 });
    await checkScannerAvailable({ execImpl, env: { [SCANNER_ENV_VAR]: "snyk-agent-scan" } });
    expect(execImpl).toHaveBeenCalledOnce();
    const [cmd, args] = execImpl.mock.calls[0] as [string, string[]];
    expect(cmd).toBe("snyk-agent-scan");
    expect(args).toEqual(["--version"]);
  });

  it("returns false WITHOUT spawning anything when unconfigured (the default)", async () => {
    const execImpl = vi.fn();
    expect(await checkScannerAvailable({ execImpl, env: {} })).toBe(false);
    expect(execImpl).not.toHaveBeenCalled();
  });

  it("returns false WITHOUT spawning anything when the command is refused", async () => {
    const execImpl = vi.fn();
    const onWarn = vi.fn();
    expect(
      await checkScannerAvailable({ execImpl, onWarn, env: { [SCANNER_ENV_VAR]: "npx" } }),
    ).toBe(false);
    expect(execImpl).not.toHaveBeenCalled();
  });

  // A refused value must not look identical to "no scanner installed" — the
  // user would be told to set the variable they just set, with no hint mcpm
  // rejected it.
  it("warns when a configured scanner is refused, and only once", async () => {
    const execImpl = vi.fn();
    const onWarn = vi.fn();
    const opts = { execImpl, onWarn, env: { [SCANNER_ENV_VAR]: "npx" } };
    await checkScannerAvailable(opts);
    await checkScannerAvailable(opts);
    expect(onWarn).toHaveBeenCalledTimes(1);
    expect(onWarn.mock.calls[0][0]).toContain(SCANNER_ENV_VAR);
    expect(onWarn.mock.calls[0][0]).toContain('"npx"');
  });

  it("stays silent when simply unconfigured — that is not a misconfiguration", async () => {
    const onWarn = vi.fn();
    await checkScannerAvailable({ execImpl: vi.fn(), onWarn, env: {} });
    expect(onWarn).not.toHaveBeenCalled();
  });

  // A configured-but-unrunnable scanner (typo, moved binary, or a pasted
  // command line) must say so. Otherwise the user is told to set the variable
  // they already set.
  it.each([
    ["a typo'd path", "/usr/local/bin/mcp-scam"],
    ["a pasted command line", "npx @invariantlabs/mcp-scan"],
  ])("warns when the configured scanner cannot be run (%s)", async (_label, value) => {
    const execImpl = vi.fn().mockRejectedValue(new Error("ENOENT"));
    const onWarn = vi.fn();
    expect(
      await checkScannerAvailable({ execImpl, onWarn, env: { [SCANNER_ENV_VAR]: value } }),
    ).toBe(false);
    expect(onWarn).toHaveBeenCalledOnce();
    expect(onWarn.mock.calls[0][0]).toContain("could not be run");
  });

  it("stays silent when the scanner runs fine", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "1.0.0", exitCode: 0 });
    const onWarn = vi.fn();
    expect(await checkScannerAvailable({ execImpl, onWarn })).toBe(true);
    expect(onWarn).not.toHaveBeenCalled();
  });

  // Follows symlinks: /usr/bin/npx is itself a symlink to npm's npx-cli.js, so a
  // link named innocuously would pass a purely lexical check. Built entirely
  // inside a temp dir — pointing at a real npm install would make the test
  // depend on where node happens to live on the runner.
  it("refuses a symlink whose target is a package runner", async () => {
    const { mkdtemp, symlink, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const path = await import("node:path");
    const dir = await mkdtemp(path.join(tmpdir(), "mcpm-scanner-"));
    const target = path.join(dir, "npx-cli.js");
    await writeFile(target, "#!/usr/bin/env node\n", { mode: 0o755 });
    const link = path.join(dir, "mcp-scan");
    await symlink(target, link);

    const execImpl = vi.fn();
    const onWarn = vi.fn();
    expect(
      await checkScannerAvailable({ execImpl, onWarn, env: { [SCANNER_ENV_VAR]: link } }),
    ).toBe(false);
    expect(execImpl).not.toHaveBeenCalled();
    expect(onWarn).toHaveBeenCalledOnce();
  });

  // The other half of that behaviour: an unresolvable path must not be treated
  // as REFUSED. It falls through to the spawn, and the failure is reported as
  // "could not be run" rather than as a package-runner accusation.
  it("does not refuse a command whose path cannot be resolved", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "", exitCode: 127 });
    const onWarn = vi.fn();
    expect(
      await checkScannerAvailable({
        execImpl,
        onWarn,
        env: { [SCANNER_ENV_VAR]: "/nonexistent/dir/my-scanner" },
      }),
    ).toBe(false);
    expect(execImpl).toHaveBeenCalledOnce();
    expect(onWarn).toHaveBeenCalledOnce();
    expect(onWarn.mock.calls[0][0]).toContain("could not be run");
    expect(onWarn.mock.calls[0][0]).not.toContain("package runner");
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — graceful degradation when scan call itself fails
// (callers are responsible for checking availability before calling scanTier2)
// ---------------------------------------------------------------------------

describe("scanTier2 — scan call fails: surfaces a diagnostic, not a silent empty list", () => {
  it("surfaces a low-severity scanner-error finding when the scan exec rejects (e.g. process killed)", async () => {
    const execImpl = vi.fn().mockRejectedValue(new Error("command not found"));
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].severity).toBe("low");
    expect(findings[0].source).toBe("external");
  });

  it("surfaces a scanner-error finding when scan exits non-zero with empty output", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "", exitCode: 1 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].severity).toBe("low");
    expect(findings[0].message).toMatch(/exit code 1/);
  });

  it("parses findings even when the scanner exits non-zero (issues-found exit codes)", async () => {
    // A scanner may exit non-zero precisely because it found issues, while still
    // emitting valid findings JSON. That must not be discarded.
    const output = JSON.stringify({
      findings: [{ severity: "high", description: "tool poisoning", location: "tool: x" }],
    });
    const execImpl = vi.fn().mockResolvedValue({ stdout: output, exitCode: 3 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("prompt-injection");
    expect(findings[0].severity).toBe("high");
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — scanner available, parses output
// ---------------------------------------------------------------------------

describe("scanTier2 — scanner available, clean server", () => {
  it("returns empty findings when mcp-scan reports no issues", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: JSON.stringify({ findings: [] }), exitCode: 0 }); // scan
    const findings = await scanTier2("io.github.acme/clean-server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("calls the configured scanner with the server name", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: JSON.stringify({ findings: [] }), exitCode: 0 });
    await scanTier2("io.github.acme/my-server", { execImpl });
    expect(execImpl).toHaveBeenCalledTimes(1);
    const [cmd, args] = execImpl.mock.calls[0] as [string, string[]];
    expect(cmd).toBe("mcp-scan");
    expect(args).toEqual(["--json", "io.github.acme/my-server"]);
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — unconfigured / refused scanner never spawns
// ---------------------------------------------------------------------------

describe("scanTier2 — scanner not configured or refused", () => {
  it("returns a diagnostic without spawning when unconfigured", async () => {
    const execImpl = vi.fn();
    const findings = await scanTier2("io.github.acme/server", { execImpl, env: {} });
    expect(execImpl).not.toHaveBeenCalled();
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].severity).toBe("low");
    expect(findings[0].message).toContain(SCANNER_ENV_VAR);
  });

  it("returns a diagnostic without spawning when a package runner is configured", async () => {
    const execImpl = vi.fn();
    const findings = await scanTier2("io.github.acme/server", {
      execImpl,
      env: { [SCANNER_ENV_VAR]: "npx" },
    });
    expect(execImpl).not.toHaveBeenCalled();
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].message).toMatch(/package runner or shell/i);
  });
});

describe("scanTier2 — scanner available, findings returned", () => {
  const mcpScanOutput = JSON.stringify({
    findings: [
      {
        severity: "high",
        description: "Tool description contains exfil pattern",
        location: "tool: read_file",
      },
      {
        severity: "critical",
        description: "Hardcoded API key detected",
        location: "tool: setup",
      },
    ],
  });

  it("returns findings mapped to Finding objects", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: mcpScanOutput, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/bad-server", { execImpl });
    expect(findings.length).toBeGreaterThan(0);
  });

  it("each finding has required fields", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: mcpScanOutput, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/bad-server", { execImpl });
    for (const f of findings) {
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("type");
      expect(f).toHaveProperty("message");
      expect(f).toHaveProperty("location");
    }
  });

  it("tags external-scanner findings with source: 'external'", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: mcpScanOutput, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/bad-server", { execImpl });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.source === "external")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — severity normalisation fails safe (issue #24)
// ---------------------------------------------------------------------------

describe("scanTier2 — unknown severity fails safe to high", () => {
  it("maps an unknown/novel severity string to 'high', not a non-blocking level", async () => {
    const output = JSON.stringify({
      findings: [
        { severity: "catastrophic", description: "novel scanner category", location: "tool: x" },
      ],
    });
    const execImpl = vi.fn().mockResolvedValueOnce({ stdout: output, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    // Pre-fix this was "medium" (non-blocking); fail-safe maps it to "high".
    expect(findings[0].severity).toBe("high");
  });

  it("maps a missing severity to 'high'", async () => {
    const output = JSON.stringify({
      findings: [{ description: "no severity field", location: "tool: y" }],
    });
    const execImpl = vi.fn().mockResolvedValueOnce({ stdout: output, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings[0].severity).toBe("high");
  });

  it("still maps known severities correctly", async () => {
    const output = JSON.stringify({
      findings: [
        { severity: "LOW", description: "minor", location: "tool: z" },
        { severity: "Critical", description: "bad", location: "tool: w" },
      ],
    });
    const execImpl = vi.fn().mockResolvedValueOnce({ stdout: output, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings[0].severity).toBe("low");
    expect(findings[1].severity).toBe("critical");
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — unparseable output (graceful degradation)
// ---------------------------------------------------------------------------

describe("scanTier2 — unparseable / non-clean output surfaces a diagnostic", () => {
  it("surfaces a scanner-error finding when output is not valid JSON", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "not json at all!!!", exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].message).toMatch(/could not be parsed/i);
  });

  it("treats exit 0 with no output as a FAILED scan, not a clean one", async () => {
    // Silence used to be read as "ran clean", which silently earned the full
    // 20-point external bucket. With an arbitrary user-named executable,
    // silence is the signature of a binary that is not a scanner (`/bin/true`).
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "", exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].message).toMatch(/no output/i);
  });

  it("surfaces a scanner-error finding when JSON has no findings array", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: JSON.stringify({ results: [] }), exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
  });

  it("surfaces a scanner-error finding when scan exits non-zero with unparseable output", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "error: something failed", exitCode: 2 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
  });

  it("surfaces a scanner-error finding when scan call itself throws", async () => {
    const execImpl = vi
      .fn()
      .mockRejectedValueOnce(new Error("process killed"));
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].type).toBe("scanner-error");
    expect(findings[0].message).toMatch(/process killed/);
  });
});

// ---------------------------------------------------------------------------
// Immutability
// ---------------------------------------------------------------------------

describe("scanTier2 — immutability", () => {
  it("returns a new array on each call", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValue({ stdout: JSON.stringify({ findings: [] }), exitCode: 0 });
    const a = await scanTier2("io.github.acme/server", { execImpl });
    const b = await scanTier2("io.github.acme/server", { execImpl });
    expect(a).not.toBe(b);
  });
});

// ---------------------------------------------------------------------------
// validateServerName — security: reject malicious server names
// ---------------------------------------------------------------------------

describe("validateServerName", () => {
  it("accepts valid server name with owner/repo pattern", () => {
    expect(() => validateServerName("io.github.acme/my-server")).not.toThrow();
  });

  it("accepts server name with dots and dashes", () => {
    expect(() => validateServerName("io.github.owner/repo-name.v2")).not.toThrow();
  });

  it("rejects server names with shell metacharacters", () => {
    expect(() => validateServerName("owner/repo; rm -rf /")).toThrow(/malicious/i);
  });

  it("rejects server names with backticks", () => {
    expect(() => validateServerName("owner/`whoami`")).toThrow(/malicious/i);
  });

  it("rejects server names with no slash", () => {
    expect(() => validateServerName("no-slash-at-all")).toThrow(/malicious/i);
  });

  it("rejects server names starting with a dot", () => {
    expect(() => validateServerName(".hidden/repo")).toThrow(/malicious/i);
  });

  it("rejects empty string", () => {
    expect(() => validateServerName("")).toThrow(/malicious/i);
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — server name validation is called before exec
// ---------------------------------------------------------------------------

describe("scanTier2 — server name validation", () => {
  it("throws for a malicious server name without calling exec", async () => {
    const execImpl = vi.fn();
    await expect(
      scanTier2("owner/repo; rm -rf /", { execImpl })
    ).rejects.toThrow(/malicious/i);
    expect(execImpl).not.toHaveBeenCalled();
  });
});
