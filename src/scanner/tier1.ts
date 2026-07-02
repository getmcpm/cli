/**
 * Tier-1 scanner — runs on every install, pure metadata analysis.
 *
 * No network, no filesystem access. Pure function: ServerEntry → Finding[].
 * Delegates pattern detection to patterns.ts.
 */

import type { ServerEntry } from "../registry/types.js";
import { argumentTokens } from "../registry/argument-tokens.js";
import {
  detectSecrets,
  detectPromptInjection,
  detectTyposquatting,
  detectExfilArgs,
  detectInstallScriptShape,
  type ArgSchema,
} from "./patterns.js";
import { assessServerStatus } from "./registry-status.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface Finding {
  severity: "critical" | "high" | "medium" | "low";
  type:
    | "secrets"
    | "prompt-injection"
    | "typosquatting"
    | "exfil-args"
    | "scanner-error"
    | "release-cooldown" // NEW — emitted only by assessReleaseAge (needs a clock; never by scanTier1)
    | "install-script" // NEW — emitted by scanTier1 via detectInstallScriptShape (deterministic)
    | "registry-status"; // NEW — emitted by scanTier1 when the registry marks the server deprecated/deleted
  message: string;
  location: string;
  /**
   * Which scan bucket produced this finding. Static-scan (tier-1) findings
   * leave `source` undefined and are treated as static; tier-2
   * external-scanner findings set "external". The trust score deducts each
   * finding from exactly one bucket based on this tag, so an external scanner
   * being present no longer double-counts findings against both the static and
   * external sub-scores. (Health-check results are a boolean `passed`, not
   * Finding objects, so they never carry a `source`.)
   */
  source?: "static" | "external";
}

// ---------------------------------------------------------------------------
// Known popular MCP server names (for typosquatting detection)
// ---------------------------------------------------------------------------

const KNOWN_POPULAR_SERVERS: readonly string[] = [
  "io.github.modelcontextprotocol/servers-filesystem",
  "io.github.modelcontextprotocol/servers-github",
  "io.github.modelcontextprotocol/servers-postgres",
  "io.github.modelcontextprotocol/servers-slack",
  "io.github.modelcontextprotocol/servers-memory",
  "io.github.modelcontextprotocol/servers-brave-search",
  "io.github.modelcontextprotocol/servers-google-maps",
  "io.github.modelcontextprotocol/servers-fetch",
  "io.github.modelcontextprotocol/servers-git",
  "io.github.modelcontextprotocol/servers-sqlite",
  "io.github.modelcontextprotocol/servers-everything",
  "io.github.modelcontextprotocol/servers-puppeteer",
  "io.github.modelcontextprotocol/servers-gdrive",
  "io.github.modelcontextprotocol/servers-sentry",
  "io.github.modelcontextprotocol/servers-aws-kb-retrieval",
];

// ---------------------------------------------------------------------------
// scanTier1
// ---------------------------------------------------------------------------

/**
 * Scan a ServerEntry using only its metadata (no network, no filesystem).
 * Returns a new Finding[] — never mutates the input.
 */
export function scanTier1(entry: ServerEntry): Finding[] {
  const { server } = entry;
  const allFindings: Finding[] = [];

  // --- 1. Scan server description and title for secrets and prompt injection ---
  for (const text of [server.description, server.title].filter(Boolean)) {
    allFindings.push(...detectSecrets(text!));
    allFindings.push(...detectPromptInjection(text!));
  }

  // --- 1b. Scan remote header descriptions for injection ---
  for (const remote of server.remotes ?? []) {
    for (const header of remote.headers ?? []) {
      if (header.description) {
        allFindings.push(...detectPromptInjection(header.description));
      }
    }
  }

  // --- 1c. Scan runtimeArguments for injection ---
  // Scan every security-relevant token (name + value + valueHint), not just
  // value — so injection text hidden in a named arg's `name` or a positional
  // `valueHint` is no longer a blindspot.
  for (const pkg of server.packages) {
    for (const arg of pkg.runtimeArguments ?? []) {
      for (const token of argumentTokens(arg)) {
        allFindings.push(...detectPromptInjection(token));
      }
    }
  }

  // --- 2. Scan package env vars for secrets and exfil args ---
  for (const pkg of server.packages) {
    // Convert EnvVar[] to ArgSchema[] for detectExfilArgs
    const args: ArgSchema[] = pkg.environmentVariables.map((ev) => ({
      name: ev.name,
      description: ev.description,
      isSecret: ev.isSecret,
    }));
    allFindings.push(...detectExfilArgs(args));

    // Also scan env var descriptions for secrets
    for (const ev of pkg.environmentVariables) {
      if (ev.description) {
        allFindings.push(...detectSecrets(ev.description));
      }
    }
  }

  // --- 2b. Install-script launch-shape awareness (F4) ---
  for (const pkg of server.packages) {
    allFindings.push(...detectInstallScriptShape(pkg));
  }

  // --- 3. Typosquatting check on package name ---
  allFindings.push(...detectTyposquatting(server.name, KNOWN_POPULAR_SERVERS));

  // --- 4. Registry lifecycle status (E9a): surface a deprecated/deleted
  // listing as an advisory finding. install/up additionally fail closed on
  // "deleted" via their own gates; audit relies on this finding to WARN. ---
  const statusFinding = assessServerStatus(entry).finding;
  if (statusFinding) {
    allFindings.push(statusFinding);
  }

  return allFindings;
}
