/**
 * D3 tests: the SARIF 2.1.0 mapper (src/output/sarif.ts).
 *
 * Pure function — asserts the shape GitHub code-scanning ingests: one rule per
 * Finding.type, one result per finding, severity→level mapping, file-level
 * anchoring to mcpm.yaml (NO fabricated line numbers), and stable fingerprints.
 */

import { describe, it, expect } from "vitest";
import { buildSarif, type SarifServer } from "../../output/sarif.js";
import type { Finding } from "../../scanner/tier1.js";

function finding(type: Finding["type"], severity: Finding["severity"], message = "msg"): Finding {
  return { type, severity, message, location: "server" };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function run(log: ReturnType<typeof buildSarif>): any {
  return (log.runs as any[])[0];
}

describe("buildSarif", () => {
  it("emits a valid SARIF 2.1.0 envelope with one run and the mcpm driver", () => {
    const log = buildSarif([], "0.19.0");
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toMatch(/sarif-2\.1\.0/);
    expect(log.runs).toHaveLength(1);
    expect(run(log).tool.driver.name).toBe("mcpm");
    expect(run(log).tool.driver.version).toBe("0.19.0");
  });

  it("declares a rule per Finding.type even when there are no findings", () => {
    const ids = run(buildSarif([], "0.19.0")).tool.driver.rules.map((r: { id: string }) => r.id);
    // The 8 real finding types, all namespaced mcpm/<type>.
    expect(ids).toEqual(
      expect.arrayContaining([
        "mcpm/secrets",
        "mcpm/prompt-injection",
        "mcpm/typosquatting",
        "mcpm/exfil-args",
        "mcpm/scanner-error",
        "mcpm/release-cooldown",
        "mcpm/install-script",
        "mcpm/registry-status",
      ])
    );
    expect(ids).toHaveLength(8);
  });

  it("maps each finding to a result: ruleId, level, server in message, file-level location", () => {
    const servers: SarifServer[] = [
      { name: "srv-a", findings: [finding("secrets", "critical", "leaked key")] },
    ];
    const results = run(buildSarif(servers, "0.19.0")).results;
    expect(results).toHaveLength(1);
    const r = results[0];
    expect(r.ruleId).toBe("mcpm/secrets");
    expect(r.level).toBe("error"); // critical → error
    expect(r.message.text).toBe("leaked key (server: srv-a)");
    // File-level anchor to mcpm.yaml — NO region / line number (would be fabricated).
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe("mcpm.yaml");
    expect(r.locations[0].physicalLocation.region).toBeUndefined();
    expect(r.locations[0].logicalLocations[0].name).toBe("srv-a");
  });

  it("maps severity → SARIF level (critical/high=error, medium=warning, low=note)", () => {
    const servers: SarifServer[] = [
      {
        name: "s",
        findings: [
          finding("secrets", "critical"),
          finding("prompt-injection", "high"),
          finding("release-cooldown", "medium"),
          finding("install-script", "low"),
        ],
      },
    ];
    const levels = run(buildSarif(servers, "0.19.0")).results.map((r: { level: string }) => r.level);
    expect(levels).toEqual(["error", "error", "warning", "note"]);
  });

  it("gives each result a stable, distinct fingerprint (server:type:hash of message)", () => {
    const servers: SarifServer[] = [
      { name: "s", findings: [finding("secrets", "high", "one"), finding("secrets", "high", "two")] },
    ];
    const results = run(buildSarif(servers, "0.19.0")).results;
    const fps = results.map((r: { partialFingerprints: { mcpmFinding: string } }) => r.partialFingerprints.mcpmFinding);
    expect(fps[0]).toMatch(/^s:secrets:[0-9a-f]{12}$/);
    expect(fps[0]).not.toBe(fps[1]); // different messages → different fingerprints
    // Deterministic across builds.
    expect(buildSarif(servers, "0.19.0")).toEqual(buildSarif(servers, "0.19.0"));
  });

  it("flattens findings across multiple servers", () => {
    const servers: SarifServer[] = [
      { name: "a", findings: [finding("secrets", "high")] },
      { name: "b", findings: [] },
      { name: "c", findings: [finding("typosquatting", "medium"), finding("exfil-args", "critical")] },
    ];
    const results = run(buildSarif(servers, "0.19.0")).results;
    expect(results).toHaveLength(3);
    expect(results.map((r: { ruleId: string }) => r.ruleId)).toEqual([
      "mcpm/secrets",
      "mcpm/typosquatting",
      "mcpm/exfil-args",
    ]);
  });
});
