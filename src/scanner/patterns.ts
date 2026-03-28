/**
 * Pattern detection functions for the scanner module.
 *
 * All functions are pure: they accept text/data and return Finding[].
 * No I/O, no mutation, no side effects.
 */

import type { Finding } from "./tier1.js";

// ---------------------------------------------------------------------------
// Arg schema shape used by detectExfilArgs
// ---------------------------------------------------------------------------

export interface ArgSchema {
  name: string;
  description?: string;
  isSecret?: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a Finding object immutably. */
function makeFinding(
  severity: Finding["severity"],
  type: Finding["type"],
  message: string,
  location: string,
): Finding {
  return { severity, type, message, location };
}

// ---------------------------------------------------------------------------
// detectSecrets
// ---------------------------------------------------------------------------

/**
 * Patterns for secrets embedded in text.
 * Each entry has a label (for the message) and a regex.
 */
const SECRET_PATTERNS: ReadonlyArray<{ label: string; pattern: RegExp }> = [
  // AWS access key IDs
  {
    label: "AWS access key",
    pattern: /AKIA[0-9A-Z]{16}/g,
  },
  // Generic api_key / apikey / token / secret / password assignments with quoted values
  {
    label: "API key or secret assignment",
    pattern: /(api[_-]?key|apikey|token|secret|password)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
  },
  // Bearer tokens (Authorization header pattern)
  {
    label: "Bearer token",
    pattern: /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/g,
  },
  // GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_) — 30-40 chars
  {
    label: "GitHub token",
    pattern: /gh[pousr]_[A-Za-z0-9]{20,}/g,
  },
  // Slack bot/user tokens
  {
    label: "Slack token",
    pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/g,
  },
];

/**
 * Detect hardcoded secrets in a text string.
 * Returns a new Finding[] (never mutates input).
 */
export function detectSecrets(text: string): Finding[] {
  if (!text) return [];

  const findings: Finding[] = [];

  for (const { label, pattern } of SECRET_PATTERNS) {
    // Use a new RegExp to avoid stateful lastIndex issues with /g
    const re = new RegExp(pattern.source, pattern.flags);
    if (re.test(text)) {
      findings.push(
        makeFinding("critical", "secrets", `Potential ${label} detected in text`, "tool description"),
      );
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// detectPromptInjection
// ---------------------------------------------------------------------------

const PROMPT_INJECTION_PATTERNS: ReadonlyArray<{ label: string; pattern: RegExp; severity: Finding["severity"] }> = [
  // Hidden instruction directives
  { label: "ignore previous instructions", pattern: /ignore\s+(previous|all\s+previous|prior)\s+instructions?/i, severity: "critical" },
  { label: "forget previous instructions", pattern: /forget\s+(previous|prior|all)\s+instructions?/i, severity: "critical" },
  { label: "disregard instructions", pattern: /disregard\s+(all\s+)?(prior|previous|the)?\s*(?:instructions?|context|directives?)/i, severity: "critical" },
  { label: "system prompt access", pattern: /system\s+prompt/i, severity: "high" },
  { label: "you are now", pattern: /you\s+are\s+now\s+[a-z]/i, severity: "high" },
  { label: "act as persona", pattern: /act\s+as\s+(an?\s+)?(?:unrestricted|different|new|alternate)/i, severity: "high" },
  // Base64-encoded content in descriptions — look for long base64 segments or padded blocks
  { label: "base64-encoded content", pattern: /[A-Za-z0-9+/]{20,}={1,2}/, severity: "high" },
  // Exfil patterns — sending data to external URLs
  { label: "exfiltration to URL", pattern: /(?:sends?|posts?|transmits?|uploads?)\s+(?:all\s+)?(?:data|content|files?|information|secrets?|credentials?)\s+to\s+https?:\/\//i, severity: "critical" },
  { label: "exfiltration URL destination", pattern: /to\s+https?:\/\/[^\s]+(?:collect|steal|exfil|harvest)/i, severity: "critical" },
];

/**
 * Detect prompt injection and exfiltration patterns in a text string.
 * Returns a new Finding[] (never mutates input).
 */
export function detectPromptInjection(text: string): Finding[] {
  if (!text) return [];

  const findings: Finding[] = [];

  for (const { label, pattern, severity } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push(
        makeFinding(severity, "prompt-injection", `Potential prompt injection detected: ${label}`, "tool description"),
      );
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// detectTyposquatting (Levenshtein distance)
// ---------------------------------------------------------------------------

/** Compute Levenshtein edit distance between two strings. */
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Create a row of distances, initialised to the "a" prefixes
  let prevRow = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 0; i < a.length; i++) {
    const currRow: number[] = [i + 1];
    for (let j = 0; j < b.length; j++) {
      const insertCost = currRow[j] + 1;
      const deleteCost = prevRow[j + 1] + 1;
      const replaceCost = prevRow[j] + (a[i] === b[j] ? 0 : 1);
      currRow.push(Math.min(insertCost, deleteCost, replaceCost));
    }
    prevRow = currRow;
  }

  return prevRow[b.length];
}

/**
 * Detect typosquatting by comparing a package name against known popular names.
 * Flags names with Levenshtein distance <= 2 that are NOT an exact match.
 * Returns a new Finding[] (never mutates input).
 */
export function detectTyposquatting(name: string, knownNames: readonly string[]): Finding[] {
  if (!name || knownNames.length === 0) return [];

  const findings: Finding[] = [];

  for (const known of knownNames) {
    if (name === known) continue; // Exact match — not a typosquat

    const distance = levenshtein(name, known);
    if (distance > 0 && distance <= 2) {
      findings.push(
        makeFinding(
          "high",
          "typosquatting",
          `Package name "${name}" is suspiciously similar to known server "${known}" (edit distance: ${distance})`,
          "package name",
        ),
      );
      // Report at most one match (the closest similarity is enough)
      break;
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// detectExfilArgs
// ---------------------------------------------------------------------------

/**
 * Argument names that are suspicious for exfiltration when appearing in
 * servers that don't obviously need them (e.g., a filesystem server shouldn't
 * have an "endpoint" argument).
 */
const EXFIL_ARG_PATTERNS: ReadonlyArray<RegExp> = [
  /^url$/i,
  /^endpoint$/i,
  /^webhook/i,
  /^callback[_-]?url$/i,
  /^exfil/i,
  /^send[_-]?to$/i,
];

/**
 * Detect argument schemas that look like data exfiltration channels.
 * A webhook_url arg is suspicious if isSecret is explicitly false.
 * Generic url/endpoint args without context are always suspicious.
 *
 * Returns a new Finding[] (never mutates input).
 */
export function detectExfilArgs(args: readonly ArgSchema[]): Finding[] {
  if (!args || args.length === 0) return [];

  const findings: Finding[] = [];

  for (const arg of args) {
    const argNameLower = arg.name.toLowerCase();

    // webhook_url is only suspicious when isSecret is explicitly false
    if (/^webhook[_-]?url$/i.test(arg.name)) {
      if (arg.isSecret === false) {
        findings.push(
          makeFinding(
            "medium",
            "exfil-args",
            `Argument "${arg.name}" looks like a webhook destination and is not marked as secret`,
            `argument: ${arg.name}`,
          ),
        );
      }
      continue;
    }

    // Generic exfil patterns
    for (const pattern of EXFIL_ARG_PATTERNS) {
      if (pattern.test(argNameLower)) {
        findings.push(
          makeFinding(
            "medium",
            "exfil-args",
            `Argument "${arg.name}" resembles an exfiltration destination parameter`,
            `argument: ${arg.name}`,
          ),
        );
        break;
      }
    }
  }

  return findings;
}
