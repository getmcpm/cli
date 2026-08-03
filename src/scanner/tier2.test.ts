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
  resolveScannerCommand,
  scanTier2,
  validateServerName,
} from "./tier2.js";

// Tier 2 is off unless the user names an installed scanner. Most tests below
// exercise the wrapper logic, so they opt in to a configured scanner; the
// unconfigured path has its own dedicated blocks.
beforeEach(() => {
  vi.stubEnv(SCANNER_ENV_VAR, "mcp-scan");
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

  it("refuses a fetching runner given by path, case, or Windows suffix", () => {
    for (const value of ["/usr/local/bin/npx", "NPX", "C:\\Program Files\\nodejs\\npx.cmd", "Npx.EXE"]) {
      expect(resolveScannerCommand({ [SCANNER_ENV_VAR]: value }).status, value).toBe("rejected");
    }
  });

  it("refuses a command line, so a runner cannot hide behind arguments", () => {
    const result = resolveScannerCommand({ [SCANNER_ENV_VAR]: "npx @invariantlabs/mcp-scan" });
    expect(result.status).toBe("rejected");
    if (result.status === "rejected") expect(result.reason).toMatch(/single executable/i);
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
    expect(
      await checkScannerAvailable({ execImpl, env: { [SCANNER_ENV_VAR]: "npx" } }),
    ).toBe(false);
    expect(execImpl).not.toHaveBeenCalled();
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

  it("returns empty findings when output is empty string and exit code is 0 (ran clean)", async () => {
    // Exit 0 + empty output is the one ambiguous case we treat as "clean" so a
    // scanner that prints nothing on success doesn't generate a false diagnostic.
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "", exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
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
