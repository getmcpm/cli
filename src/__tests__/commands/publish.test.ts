/**
 * Tests for src/commands/publish — written FIRST per TDD (Red → Green).
 *
 * Covers: check (dry-run, --json body), trust gate, missing manifest guard,
 * token exchange (GITHUB_TOKEN and --github-oidc), and that a registry 404
 * is now a real thrown error (fix/publish-live-registry — the endpoint is
 * real; a 404 no longer means "not yet available").
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "../../scanner/tier1.js";
import { RegistryError } from "../../registry/errors.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// version + transport are set explicitly so tests don't depend on reading a
// real package.json from process.cwd() (resolveVersion's fallback).
const MANIFEST = {
  name: "io.github.test/my-server",
  description: "A test MCP server",
  homepage: "https://github.com/test/my-server",
  tags: ["test"],
  package: {
    registryType: "npm" as const,
    identifier: "@test/my-server",
  },
  version: "1.0.0",
  transport: { type: "stdio" as const },
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

  async function runCheck(opts: { registryUrl?: string; json?: boolean } = {}) {
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

  // F4 fallout pinned: the real scanTier1 now emits one low "install-script"
  // launcher finding for every npm manifest, so the dry-run score drops by 2
  // (static 38/40) without tripping the trust gate.
  it("dry-run with the real scanTier1 shows the low launcher finding and the -2 score (gate untripped)", async () => {
    const { handlePublishCheck } = await import("../../commands/publish/check.js");
    const { scanTier1 } = await import("../../scanner/tier1.js");
    const { computeTrustScore } = await import("../../scanner/trust-score.js");
    const lines: string[] = [];
    const ctsSpy = vi.fn(computeTrustScore);

    await handlePublishCheck({}, {
      readManifest,
      scanTier1,
      computeTrustScore: ctsSpy,
      output: (t) => lines.push(t),
    });

    const text = lines.join("");
    expect(text).toMatch(/ready to publish/i);
    // health 15 + static (40 - 2) + external 0 + meta 0 = 53
    expect(text).toContain("53/100");

    const findings = ctsSpy.mock.calls[0][0].findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "low", type: "install-script" });
    expect(findings[0].message).toContain("This launcher runs install scripts:");
  });

  // --json must emit exactly the POST /v0.1/publish body — one parseable
  // JSON value, nothing else — so it can be piped straight into
  // `curl -d @- .../v0.1/validate` (see the live-validation step in the PR).
  it("--json emits exactly one parseable JSON body: the ServerJSON that would be POSTed", async () => {
    await runCheck({ json: true });
    expect(output).toHaveLength(1);
    const body = JSON.parse(output[0]) as {
      $schema: string;
      name: string;
      description: string;
      version: string;
      packages: Array<{ registryType: string; identifier: string; transport: { type: string } }>;
    };
    expect(body.$schema).toMatch(/^https:\/\/static\.modelcontextprotocol\.io\/schemas\//);
    expect(body.name).toBe(MANIFEST.name);
    expect(body.version).toBe("1.0.0");
    expect(body.packages[0]).toMatchObject({
      registryType: "npm",
      identifier: "@test/my-server",
      transport: { type: "stdio" },
    });
  });

  it("--json still enforces the trust gate (blocks before emitting a body)", async () => {
    scanTier1.mockReturnValue([
      { type: "secret", severity: "critical", message: "Key leak", location: "x" } satisfies Finding,
    ]);
    await expect(runCheck({ json: true })).rejects.toThrow(/critical|high|blocked/i);
    expect(output).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: handlePublishCheck + the real readManifest (backlog #85)
// ---------------------------------------------------------------------------

describe("handlePublishCheck — real readManifest surfaces the description cap", () => {
  it("rejects with a readable message (not a raw ZodError dump) when description exceeds 100 chars", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcpm-publish-check-"));
    try {
      writeFileSync(
        join(dir, ".mcpm-publish.yaml"),
        [
          "name: io.github.test/my-server",
          `description: ${"a".repeat(150)}`,
          "package:",
          "  registryType: npm",
          '  identifier: "@test/my-server"',
          "",
        ].join("\n")
      );

      const { readManifest } = await import("../../commands/publish/manifest.js");
      const { handlePublishCheck } = await import("../../commands/publish/check.js");

      const err = (await handlePublishCheck(
        {},
        {
          readManifest: () => readManifest(dir),
          scanTier1: vi.fn().mockReturnValue([]),
          computeTrustScore: vi.fn(),
          output: () => {},
        }
      ).catch((e: Error) => e)) as Error;

      expect(err.message).toContain("yours is 150");
      // Framing, not just the text: `.parse()`'s raw ZodError dump EMBEDS the
      // same custom message, so asserting the message alone passes against the
      // very dump this test's name says it excludes.
      expect(err.message).toContain("Invalid .mcpm-publish.yaml:\n  description: ");
      expect(err.message).not.toMatch(/"code":\s*"too_big"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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

  // F4 decision pinned (see the assertTrustGate doc comment in check.ts): the
  // low launcher-class finding can never reach the medium aggregation; medium
  // install-script findings (publisher-remediable dangerous flags) DO count.
  it("ignores the single low install-script launcher finding but blocks on three medium install-script findings", async () => {
    const low: Finding = {
      type: "install-script",
      severity: "low",
      message:
        'This launcher runs install scripts: "@test/my-server" is launched via "npx -y", which executes npm lifecycle scripts on first run',
      location: "package: @test/my-server",
    };
    await expect(gate([low])).resolves.toBeUndefined();

    const med = (arg: string, prefix: string): Finding => ({
      type: "install-script",
      severity: "medium",
      message: `Declared runtime argument "${arg}" matches the dangerous Node.js launch flag "${prefix}"`,
      location: `runtime argument: ${arg}`,
    });
    await expect(
      gate([med("--eval=x", "--eval"), med("--require=y", "--require"), med("--loader=z", "--loader")])
    ).rejects.toThrow(/block/i);
  });
});

// ---------------------------------------------------------------------------
// Tests: handlePublishSubmit
// ---------------------------------------------------------------------------

describe("handlePublishSubmit", () => {
  let output: string[];
  let readManifest: ReturnType<typeof vi.fn>;
  let submitToRegistry: ReturnType<typeof vi.fn>;
  let exchangeGitHubToken: ReturnType<typeof vi.fn>;
  let exchangeGitHubOidcToken: ReturnType<typeof vi.fn>;
  let fetchActionsOidcToken: ReturnType<typeof vi.fn>;
  let audienceFromRegistryUrl: ReturnType<typeof vi.fn>;
  let getToken: ReturnType<typeof vi.fn>;
  let scanTier1: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    output = [];
    readManifest = vi.fn().mockResolvedValue(MANIFEST);
    submitToRegistry = vi.fn().mockResolvedValue({ url: "https://registry.example.com/servers/my-server" });
    exchangeGitHubToken = vi.fn().mockResolvedValue({ registryToken: "registry-jwt", expiresAt: 999 });
    exchangeGitHubOidcToken = vi.fn().mockResolvedValue({ registryToken: "registry-jwt-oidc", expiresAt: 999 });
    fetchActionsOidcToken = vi.fn().mockResolvedValue("actions-oidc-jwt");
    audienceFromRegistryUrl = vi.fn().mockReturnValue("https://registry.modelcontextprotocol.io");
    getToken = vi.fn().mockReturnValue("ghp_test_token");
    scanTier1 = vi.fn().mockReturnValue([]);
  });

  async function runSubmit(opts: { registryUrl?: string; githubOidc?: boolean } = {}) {
    const { handlePublishSubmit } = await import("../../commands/publish/submit.js");
    await handlePublishSubmit(opts, {
      readManifest,
      scanTier1,
      submitToRegistry,
      exchangeGitHubToken,
      exchangeGitHubOidcToken,
      fetchActionsOidcToken,
      audienceFromRegistryUrl,
      getToken,
      output: (t) => output.push(t),
    });
  }

  it("shows registry URL after successful submission", async () => {
    await runSubmit();
    expect(output.join("")).toContain("registry.example.com");
  });

  it("exchanges the GitHub token for a registry token, then submits with the EXCHANGED token — never the raw GitHub token", async () => {
    await runSubmit();
    expect(exchangeGitHubToken).toHaveBeenCalledWith(expect.any(String), "ghp_test_token");
    expect(submitToRegistry).toHaveBeenCalledWith(expect.anything(), "registry-jwt", expect.any(String));
  });

  // The registry's publish endpoint is real (POST /v0.1/publish) — a 404 here
  // is a genuine failure (bad --registry, endpoint moved), not "not yet
  // available". Reverting the fix (restoring the old catch-and-print-exit-0
  // special case) turns this back into a silent success and fails this test.
  it("throws (does not silently print 'not yet available' and exit 0) when the registry 404s", async () => {
    submitToRegistry.mockRejectedValue(new RegistryError("Registry API returned 404", 404));
    await expect(runSubmit()).rejects.toThrow(RegistryError);
    expect(output.join("")).not.toMatch(/not yet available/i);
  });

  it("throws when no token is available, without attempting a token exchange", async () => {
    getToken.mockReturnValue(null);
    await expect(runSubmit()).rejects.toThrow(/GITHUB_TOKEN|token|authentication/i);
    expect(exchangeGitHubToken).not.toHaveBeenCalled();
  });

  it("blocks submission when critical findings are present, before any token exchange or submit", async () => {
    scanTier1.mockReturnValue([
      { type: "secret", severity: "critical", message: "Key leak", location: "x" } satisfies Finding,
    ]);
    await expect(runSubmit()).rejects.toThrow(/critical|high|blocked/i);
    expect(exchangeGitHubToken).not.toHaveBeenCalled();
    expect(submitToRegistry).not.toHaveBeenCalled();
  });

  describe("--github-oidc", () => {
    it("mints an Actions OIDC token and exchanges it, instead of reading GITHUB_TOKEN/MCPM_TOKEN", async () => {
      await runSubmit({ githubOidc: true });
      expect(getToken).not.toHaveBeenCalled();
      expect(audienceFromRegistryUrl).toHaveBeenCalledWith("https://registry.modelcontextprotocol.io");
      expect(fetchActionsOidcToken).toHaveBeenCalledWith(
        "https://registry.modelcontextprotocol.io",
        expect.anything()
      );
      expect(exchangeGitHubOidcToken).toHaveBeenCalledWith(expect.any(String), "actions-oidc-jwt");
      expect(submitToRegistry).toHaveBeenCalledWith(expect.anything(), "registry-jwt-oidc", expect.any(String));
    });

    it("propagates a clear error when minting the OIDC token fails (e.g. no id-token: write)", async () => {
      fetchActionsOidcToken.mockRejectedValue(new Error("mcpm publish --github-oidc: ... id-token: write ..."));
      await expect(runSubmit({ githubOidc: true })).rejects.toThrow(/id-token: write/);
      expect(exchangeGitHubOidcToken).not.toHaveBeenCalled();
      expect(submitToRegistry).not.toHaveBeenCalled();
    });
  });
});
