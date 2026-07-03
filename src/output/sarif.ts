/**
 * SARIF 2.1.0 mapper for `mcpm audit --sarif` (D3).
 *
 * Pure: turns audit findings into a SARIF log that GitHub code-scanning ingests
 * (`github/codeql-action/upload-sarif`). Findings anchor file-level to `mcpm.yaml`
 * — audit scans the INSTALLED server set, which has no source line to point at, so
 * a fabricated line number would be a lie. One SARIF rule per real `Finding.type`.
 */

import crypto from "crypto";
import type { Finding } from "../scanner/tier1.js";

/** The repo artifact findings are anchored to (file-level, no line numbers). */
const ARTIFACT_URI = "mcpm.yaml";
const INFO_URI = "https://github.com/getmcpm/cli";

export interface SarifServer {
  name: string;
  findings: Finding[];
}

/** Rule metadata per finding type — TS-exhaustive, so a new type must be added here. */
const RULES: Record<Finding["type"], { name: string; description: string }> = {
  secrets: {
    name: "Hardcoded secret",
    description: "A credential/secret pattern was detected in the server's metadata.",
  },
  "prompt-injection": {
    name: "Prompt injection",
    description: "Prompt-injection patterns were found in the server's description or metadata.",
  },
  typosquatting: {
    name: "Typosquatting",
    description: "The server name closely resembles a known popular server (possible typosquat).",
  },
  "exfil-args": {
    name: "Exfil-shaped argument",
    description: "An argument schema is shaped to exfiltrate model context (e.g. underscore-wrapped sigils).",
  },
  "scanner-error": {
    name: "Scanner error",
    description: "An external scanner failed to run against this server.",
  },
  "release-cooldown": {
    name: "Release cooldown",
    description: "The package was published very recently — inside the rug-pull cooldown window.",
  },
  "install-script": {
    name: "Install script",
    description: "The package declares an install/postinstall script shape that runs on install.",
  },
  "registry-status": {
    name: "Registry status",
    description: "The registry marks this server as deprecated or deleted.",
  },
};

/** SARIF result level. critical/high → error, medium → warning, low → note. */
function sarifLevel(severity: Finding["severity"]): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function ruleId(type: Finding["type"]): string {
  return `mcpm/${type}`;
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: unknown[];
}

/**
 * Build a SARIF 2.1.0 log from audit findings.
 * @param servers audited servers with their findings
 * @param version mcpm version string for the tool driver
 */
export function buildSarif(servers: SarifServer[], version: string): SarifLog {
  const rules = (Object.keys(RULES) as Finding["type"][]).map((type) => ({
    id: ruleId(type),
    name: RULES[type].name,
    shortDescription: { text: RULES[type].name },
    fullDescription: { text: RULES[type].description },
    helpUri: INFO_URI,
    defaultConfiguration: { level: "warning" },
  }));

  const results = servers.flatMap((server) =>
    server.findings.map((f, i) => ({
      ruleId: ruleId(f.type),
      level: sarifLevel(f.severity),
      message: { text: `${f.message} (server: ${server.name})` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: ARTIFACT_URI },
          },
          logicalLocations: [{ name: server.name, kind: "namespace" }],
        },
      ],
      // Stable across runs so GitHub tracks the same alert: server + type + message.
      partialFingerprints: {
        mcpmFinding: `${server.name}:${f.type}:${fingerprint(f.message)}`,
      },
    }))
  );

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcpm",
            informationUri: INFO_URI,
            version,
            rules,
          },
        },
        results,
      },
    ],
  };
}

function fingerprint(message: string): string {
  return crypto.createHash("sha256").update(message).digest("hex").slice(0, 12);
}
