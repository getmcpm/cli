/**
 * Tests for src/commands/publish — written FIRST per TDD (Red → Green).
 *
 * Covers: check (dry-run), trust gate, missing manifest guard,
 * 404 registry fallback message, token from env only, --registry flag.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Finding } from "../../scanner/tier1.js";
import { RegistryError } from "../../registry/errors.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MANIFEST = {
  name: "io.github.test/my-server",
  description: "A test MCP server",
  homepage: "https://github.com/test/my-server",
  tags: ["test"],
  package: {
    registryType: "npm" as const,
    identifier: "@test/my-server",
  },
};

// ---------------------------------------------------------------------------
// Tests: handlePublishCheck (dry-run)
// ---------------------------------------------------------------------------

describe("handlePublishCheck", () => {
  let output: string[];
  let scanTier1: ReturnType<typeof vi.fn>;
  let computeTrustScore: ReturnType<typeof vi.fn>;
  let readManifest: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    output = [];
    scanTier1 = vi.fn().mockReturnValue([]);
    computeTrustScore = vi.fn().mockReturnValue({ score: 85, level: "green", breakdown: {} });
    readManifest = vi.fn().mockResolvedValue(MANIFEST);
  });

  async function runCheck(opts: { registryUrl?: string } = {}) {
    const { handlePublishCheck } = await import("../../commands/publish/check.js");
    await handlePublishCheck(opts, {
      readManifest,
      scanTier1,
      computeTrustScore,
      output: (t) => output.push(t),
    });
  }

  it("shows trust score and manifest fields in dry-run output", async () => {
    await runCheck();
    const text = output.join("");
    expect(text).toContain("85");
    expect(text).toContain("io.github.test/my-server");
  });

  it("blocks when critical/high finding present regardless of score", async () => {
    const criticalFinding: Finding = {
      type: "secret",
      severity: "critical",
      message: "Hardcoded API key",
      location: "src/index.ts:5",
    };
    scanTier1.mockReturnValue([criticalFinding]);
    computeTrustScore.mockReturnValue({ score: 85, level: "green", breakdown: {} });

    await expect(runCheck()).rejects.toThrow(/critical|high|blocked/i);
  });

  it("shows 'ready to publish' when score is clean and no critical findings", async () => {
    await runCheck();
    expect(output.join("")).toMatch(/ready|publish/i);
  });

  it("throws with manifest-not-found message when manifest is missing", async () => {
    readManifest.mockResolvedValue(null);
    await expect(runCheck()).rejects.toThrow(/mcpm-publish\.yaml|scaffold/i);
  });
});

// ---------------------------------------------------------------------------
// Tests: assertTrustGate — medium / exfil-arg blocking (issue #24)
// ---------------------------------------------------------------------------

describe("assertTrustGate — medium-severity blind spot (issue #24)", () => {
  async function gate(findings: Finding[]): Promise<void> {
    const { assertTrustGate } = await import("../../commands/publish/check.js");
    assertTrustGate(findings);
  }

  function exfilArg(name: string): Finding {
    return {
      type: "exfil-args",
      severity: "medium",
      message: `Argument "${name}" resembles an exfiltration destination parameter`,
      location: `argument: ${name}`,
    };
  }

  it("blocks on a single exfil-arg medium finding (pre-fix: passed)", async () => {
    await expect(gate([exfilArg("webhook")])).rejects.toThrow(/block|exfil/i);
  });

  it("blocks when multiple exfil-arg findings are present", async () => {
    await expect(
      gate([exfilArg("url"), exfilArg("endpoint"), exfilArg("send_to")])
    ).rejects.toThrow(/block/i);
  });

  it("blocks on 3+ medium findings even when none are exfil-args", async () => {
    const med = (i: number): Finding => ({
      type: "secrets",
      severity: "medium",
      message: `medium finding ${i}`,
      location: `loc ${i}`,
    });
    await expect(gate([med(1), med(2), med(3)])).rejects.toThrow(/block/i);
  });

  it("does not block on a single non-exfil medium finding", async () => {
    const med: Finding = {
      type: "secrets",
      severity: "medium",
      message: "one medium",
      location: "loc",
    };
    await expect(gate([med])).resolves.toBeUndefined();
  });

  it("does not block on clean findings", async () => {
    await expect(gate([])).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Tests: handlePublishSubmit
// ---------------------------------------------------------------------------

describe("handlePublishSubmit", () => {
  let output: string[];
  let readManifest: ReturnType<typeof vi.fn>;
  let submitToRegistry: ReturnType<typeof vi.fn>;
  let getToken: ReturnType<typeof vi.fn>;
  let scanTier1: ReturnType<typeof vi.fn>;
  let computeTrustScore: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    output = [];
    readManifest = vi.fn().mockResolvedValue(MANIFEST);
    submitToRegistry = vi.fn().mockResolvedValue({ url: "https://registry.example.com/servers/my-server" });
    getToken = vi.fn().mockReturnValue("ghp_test_token");
    scanTier1 = vi.fn().mockReturnValue([]);
    computeTrustScore = vi.fn().mockReturnValue({ score: 85, level: "green", breakdown: {} });
  });

  async function runSubmit(opts: { registryUrl?: string } = {}) {
    const { handlePublishSubmit } = await import("../../commands/publish/submit.js");
    await handlePublishSubmit(opts, {
      readManifest,
      scanTier1,
      computeTrustScore,
      submitToRegistry,
      getToken,
      output: (t) => output.push(t),
    });
  }

  it("shows registry URL after successful submission", async () => {
    await runSubmit();
    expect(output.join("")).toContain("registry.example.com");
  });

  it("shows 'API not yet available' when registry returns 404", async () => {
    submitToRegistry.mockRejectedValue(new RegistryError("Registry API returned 404", 404));
    await runSubmit();
    expect(output.join("")).toMatch(/not yet available|waitlist|endpoint/i);
  });

  it("throws when no token is available", async () => {
    getToken.mockReturnValue(null);
    await expect(runSubmit()).rejects.toThrow(/GITHUB_TOKEN|token|authentication/i);
  });

  it("blocks submission when critical findings are present", async () => {
    scanTier1.mockReturnValue([
      { type: "secret", severity: "critical", message: "Key leak", location: "x" } satisfies Finding,
    ]);
    await expect(runSubmit()).rejects.toThrow(/critical|high|blocked/i);
  });

  it("does not call computeTrustScore during submit (trust gate is findings-only)", async () => {
    await runSubmit();
    expect(computeTrustScore).not.toHaveBeenCalled();
  });
});
