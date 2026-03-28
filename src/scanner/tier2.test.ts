/**
 * Tests for src/scanner/tier2.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - execImpl is always a vi.fn() — NO real child processes.
 * - Tests cover: scanner available, scanner not available, parse failure,
 *   partial output, empty output, findings returned, graceful degradation.
 */

import { describe, it, expect, vi } from "vitest";
import { checkScannerAvailable, scanTier2 } from "./tier2.js";

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

  it("calls exec with the correct command and args", async () => {
    const execImpl = vi.fn().mockResolvedValue({ stdout: "0.1.0", exitCode: 0 });
    await checkScannerAvailable({ execImpl });
    expect(execImpl).toHaveBeenCalledOnce();
    const [cmd, args] = execImpl.mock.calls[0] as [string, string[]];
    expect(cmd).toBe("npx");
    expect(args).toContain("@invariantlabs/mcp-scan");
    expect(args).toContain("--version");
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — scanner not available
// ---------------------------------------------------------------------------

describe("scanTier2 — scanner not available", () => {
  it("returns empty findings when exec rejects (not installed)", async () => {
    const execImpl = vi.fn().mockRejectedValue(new Error("command not found"));
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("returns empty findings when --version returns non-zero", async () => {
    // First call is --version check (fails), should short-circuit
    const execImpl = vi.fn().mockResolvedValue({ stdout: "", exitCode: 1 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — scanner available, parses output
// ---------------------------------------------------------------------------

describe("scanTier2 — scanner available, clean server", () => {
  it("returns empty findings when mcp-scan reports no issues", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 }) // --version
      .mockResolvedValueOnce({ stdout: JSON.stringify({ findings: [] }), exitCode: 0 }); // scan
    const findings = await scanTier2("io.github.acme/clean-server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("calls mcp-scan with the server name", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: JSON.stringify({ findings: [] }), exitCode: 0 });
    await scanTier2("io.github.acme/my-server", { execImpl });
    expect(execImpl).toHaveBeenCalledTimes(2);
    const [, args] = execImpl.mock.calls[1] as [string, string[]];
    expect(args.join(" ")).toContain("io.github.acme/my-server");
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
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: mcpScanOutput, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/bad-server", { execImpl });
    expect(findings.length).toBeGreaterThan(0);
  });

  it("each finding has required fields", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: mcpScanOutput, exitCode: 0 });
    const findings = await scanTier2("io.github.acme/bad-server", { execImpl });
    for (const f of findings) {
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("type");
      expect(f).toHaveProperty("message");
      expect(f).toHaveProperty("location");
    }
  });
});

// ---------------------------------------------------------------------------
// scanTier2 — unparseable output (graceful degradation)
// ---------------------------------------------------------------------------

describe("scanTier2 — unparseable output", () => {
  it("returns empty findings when output is not valid JSON", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: "not json at all!!!", exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("returns empty findings when output is empty string", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: "", exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("returns empty findings when JSON has no findings field", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: JSON.stringify({ results: [] }), exitCode: 0 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("returns empty findings when scan exits non-zero", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockResolvedValueOnce({ stdout: "error: something failed", exitCode: 2 });
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });

  it("returns empty findings when scan call itself throws", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValueOnce({ stdout: "mcp-scan 0.1.0", exitCode: 0 })
      .mockRejectedValueOnce(new Error("process killed"));
    const findings = await scanTier2("io.github.acme/server", { execImpl });
    expect(findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Immutability
// ---------------------------------------------------------------------------

describe("scanTier2 — immutability", () => {
  it("returns a new array on each call", async () => {
    const execImpl = vi
      .fn()
      .mockResolvedValue({ stdout: "mcp-scan 0.1.0", exitCode: 0 });
    const a = await scanTier2("io.github.acme/server", { execImpl });
    // New mock for second call
    execImpl.mockResolvedValue({ stdout: "mcp-scan 0.1.0", exitCode: 0 });
    const b = await scanTier2("io.github.acme/server", { execImpl });
    expect(a).not.toBe(b);
  });
});
