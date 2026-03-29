/**
 * Tier-1 scanner — runs on every install, pure metadata analysis.
 *
 * No network, no filesystem access. Pure function: ServerEntry → Finding[].
 * Delegates pattern detection to patterns.ts.
 */

import type { ServerEntry } from "../registry/types.js";
import {
  detectSecrets,
  detectPromptInjection,
  detectTyposquatting,
  detectExfilArgs,
  type ArgSchema,
} from "./patterns.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface Finding {
  severity: "critical" | "high" | "medium" | "low";
  type: "secrets" | "prompt-injection" | "typosquatting" | "exfil-args";
  message: string;
  location: string;
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
  for (const pkg of server.packages) {
    for (const arg of pkg.runtimeArguments ?? []) {
      allFindings.push(...detectPromptInjection(arg));
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

  // --- 3. Typosquatting check on package name ---
  allFindings.push(...detectTyposquatting(server.name, KNOWN_POPULAR_SERVERS));

  return allFindings;
}
