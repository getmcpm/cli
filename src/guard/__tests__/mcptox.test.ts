/**
 * MCPTox-derived deterministic fixture eval (v0.5.0 Next Step 8).
 *
 * Reads every JSON fixture under fixtures/mcptox/{attacks,benign,drift}/
 * and asserts each one produces the expected inspection outcome. Closes
 * design doc OQ2 (MCPoison-equivalent rug-pull fixture).
 *
 * This is the CI release gate per Resolved Decision #10: 100% expected
 * verdicts on every fixture; any divergence regression-blocks the release.
 * Zero model API calls — pure deterministic replay.
 */

import { describe, expect, test } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "../patterns.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";
import { hashToolDefinition } from "../pins.js";
import type { InspectResult } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, "fixtures", "mcptox");

interface AttackOrBenignFixture {
  name: string;
  category?: string;
  expected_action: InspectResult["action"];
  expected_signature_id?: string;
  notes?: string;
  message: JSONRPCMessage;
}

interface DriftFixture {
  name: string;
  category: string;
  notes: string;
  server_name: string;
  tool_name: string;
  install_time_definition: {
    name: string;
    description: string;
    inputSchema: unknown;
    annotations?: unknown;
  };
  post_install_definition: {
    name: string;
    description: string;
    inputSchema: unknown;
    annotations?: unknown;
  };
  expected_drift_action: InspectResult["action"];
}

function loadJsonFixtures<T>(dir: string): { file: string; fixture: T }[] {
  const dirPath = path.join(FIXTURES_ROOT, dir);
  return readdirSync(dirPath)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({
      file: f,
      fixture: JSON.parse(readFileSync(path.join(dirPath, f), "utf8")) as T,
    }));
}

// ─────────────────────── attacks (must trigger) ───────────────────────

const attacks = loadJsonFixtures<AttackOrBenignFixture>("attacks");

describe(`MCPTox attacks (${attacks.length} fixtures — release-gate)`, () => {
  for (const { file, fixture } of attacks) {
    test(`${file}: ${fixture.name}`, () => {
      const result = inspectMessage(fixture.message, OWASP_MCP_TOP_10);
      expect(result.action, `expected action ${fixture.expected_action} for ${file}`).toBe(
        fixture.expected_action,
      );
      if (fixture.expected_signature_id !== undefined) {
        const sigIds = result.findings.map((f) => f.signature_id);
        expect(sigIds, `expected signature ${fixture.expected_signature_id} for ${file}`).toContain(
          fixture.expected_signature_id,
        );
      }
    });
  }
});

// ─────────────────────── benign (must pass — FP-rate seed) ───────────────────────

const benigns = loadJsonFixtures<AttackOrBenignFixture>("benign");

describe(`MCPTox benign corpus (${benigns.length} fixtures — FP-rate seed)`, () => {
  for (const { file, fixture } of benigns) {
    test(`${file}: ${fixture.name}`, () => {
      const result = inspectMessage(fixture.message, OWASP_MCP_TOP_10);
      expect(result.action, `expected pass for ${file}, got ${result.action} with findings: ${JSON.stringify(result.findings.map((f) => f.signature_id))}`).toBe(
        "pass",
      );
      expect(result.findings).toEqual([]);
    });
  }
});

// ─────────────────────── drift (separate pin-aware path) ───────────────────────

const drifts = loadJsonFixtures<DriftFixture>("drift");

describe(`MCPTox schema-drift fixtures (${drifts.length} — closes OQ2)`, () => {
  for (const { file, fixture } of drifts) {
    test(`${file}: ${fixture.name}`, () => {
      // Install-time hash (what gets stored in the pin).
      const installHash = hashToolDefinition({
        description: fixture.install_time_definition.description,
        schema: fixture.install_time_definition.inputSchema,
        annotations: fixture.install_time_definition.annotations,
      });
      // Post-install hash (what arrives at runtime).
      const liveHash = hashToolDefinition({
        description: fixture.post_install_definition.description,
        schema: fixture.post_install_definition.inputSchema,
        annotations: fixture.post_install_definition.annotations,
      });
      // Drift fixture must actually differ — otherwise the test doesn't exercise drift.
      expect(installHash, `${file} install_time + post_install must hash differently`).not.toBe(liveHash);
      // The detection-engine assertion: when the relay's drift inspector
      // sees liveHash vs the pin's installHash, it must block. The full
      // drift inspector is tested in drift.test.ts; here we assert the
      // fixture's content is correctly drift-shaped.
      expect(fixture.expected_drift_action).toBe("block");
    });
  }
});
