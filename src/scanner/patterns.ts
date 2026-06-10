/**
 * Pattern detection functions for the scanner module.
 *
 * All functions are pure: they accept text/data and return Finding[].
 * No I/O, no mutation, no side effects.
 */

import type { Finding } from "./tier1.js";
import { normalizeForMatch } from "../guard/patterns.js";

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
  // OpenAI API keys (legacy sk- and project sk-proj- prefix)
  {
    label: "OpenAI API key",
    pattern: /sk-(proj-)?[A-Za-z0-9]{40,}/g,
  },
  // Anthropic API keys
  {
    label: "Anthropic API key",
    pattern: /sk-ant-[A-Za-z0-9\-_]{80,}/g,
  },
  // Google API keys
  {
    label: "Google API key",
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
  },
  // npm automation/publish tokens
  {
    label: "npm token",
    pattern: /npm_[A-Za-z0-9]{36}/g,
  },
];

/**
 * Detect hardcoded secrets in a text string.
 * Applies the guard's full normalization pipeline (NFKC + evasion-character
 * strip + cross-script confusable fold) to defeat Unicode homoglyph evasion —
 * e.g. an AWS key written with a Cyrillic "А" (U+0410) instead of Latin "A".
 * Bare NFKC does not fold confusables, so such keys evaded the regexes. (#30)
 * Returns a new Finding[] (never mutates input).
 */
export function detectSecrets(text: string): Finding[] {
  if (!text) return [];
  text = normalizeForMatch(text);

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
  // Base64-encoded content in descriptions — threshold raised to 40 chars to reduce false positives
  { label: "base64-encoded content", pattern: /[A-Za-z0-9+/]{40,}={1,2}/, severity: "high" },
  // Zero-width / invisible characters and bidirectional overrides used for obfuscation
  { label: "zero-width characters (obfuscation)", pattern: /[\u200B\u200C\u200D\uFEFF\u00AD\u202A-\u202F\u2028\u2029]/, severity: "high" },
  // Exfil patterns — sending data to external URLs
  { label: "exfiltration to URL", pattern: /(?:sends?|posts?|transmits?|uploads?)\s+(?:all\s+)?(?:data|content|files?|information|secrets?|credentials?)\s+to\s+https?:\/\//i, severity: "critical" },
  { label: "exfiltration URL destination", pattern: /to\s+https?:\/\/[^\s]+(?:collect|steal|exfil|harvest)/i, severity: "critical" },
];

// The zero-width / invisible-character signature is the one pattern that must
// run against the RAW text: normalizeForMatch() strips exactly these characters
// (its PATTERN_BREAKERS class), so matching it post-normalization would always
// miss. Every other signature runs against the folded text so a cross-script
// homoglyph (e.g. Cyrillic "о" U+043E in "ignоre previous instructions") can no
// longer slip past the ASCII-anchored regexes. (security #30)
const ZERO_WIDTH_LABEL = "zero-width characters (obfuscation)";

/**
 * Detect prompt injection and exfiltration patterns in a text string.
 * Applies the guard's full normalization pipeline (NFKC + evasion-character
 * strip + cross-script confusable fold) so a homoglyph-obfuscated injection
 * phrase is caught. The zero-width-character signature is exempt: it is matched
 * against the raw text because normalization deliberately strips the very
 * characters it looks for.
 * Returns a new Finding[] (never mutates input).
 */
export function detectPromptInjection(text: string): Finding[] {
  if (!text) return [];
  const normalized = normalizeForMatch(text);

  const findings: Finding[] = [];

  for (const { label, pattern, severity } of PROMPT_INJECTION_PATTERNS) {
    const haystack = label === ZERO_WIDTH_LABEL ? text : normalized;
    if (pattern.test(haystack)) {
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

  // The package namespace is case-insensitive, so compare case-folded. Otherwise
  // a case-mixed typosquat (e.g. "Servers-Github") inflates the edit distance and
  // evades detection, and a pure-casing difference would register as a spurious
  // edit. Original casing is preserved in the finding message.
  const nameLower = name.toLowerCase();

  const findings: Finding[] = [];

  for (const known of knownNames) {
    const knownLower = known.toLowerCase();
    if (nameLower === knownLower) continue; // Exact match (case-insensitive) — not a typosquat

    const distance = levenshtein(nameLower, knownLower);
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

    // webhook_url is suspicious unless explicitly marked secret. isSecret is
    // optional, so its default (undefined) means "not marked secret" and must
    // be flagged — checking `=== false` let a webhook_url with isSecret omitted
    // slip through entirely.
    if (/^webhook[_-]?url$/i.test(arg.name)) {
      if (arg.isSecret !== true) {
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

// ---------------------------------------------------------------------------
// detectInstallScriptShape
// ---------------------------------------------------------------------------

/**
 * Node.js flags that enable arbitrary code execution.
 * These are rejected regardless of format (bare or with value).
 * This blocklist catches known-dangerous flags; the SAFE_ARG_PATTERNS
 * allowlist in src/commands/install.ts (validateRuntimeArgs) catches
 * unknown/malformed arguments at resolve time.
 */
export const DANGEROUS_FLAG_PREFIXES: readonly string[] = [
  "--eval", "-e",
  "--require", "-r",
  "--import",
  "--loader",
  "--experimental-loader",
  "--inspect",
  "--inspect-brk",
  "--experimental-policy",
  "--experimental-network-imports",
  "--input-type",
];

/**
 * Structural input for detectInstallScriptShape (mirrors ArgSchema's
 * local-shape pattern above) — ServerEntry packages are assignable.
 */
export interface PackageShapeInput {
  registryType: string;
  identifier: string;
  runtimeArguments?: ReadonlyArray<string | { type: string; value: string }>;
}

/**
 * Deterministic launch-shape awareness (metadata-only; honors the
 * no-source-scan decision).
 *
 * - registryType "npm" → ONE low "install-script" finding per package
 *   (npm-gated: only `npx -y` auto-runs lifecycle scripts on first run; uvx
 *   and docker-run do not). Low = a property of the launcher class, true for
 *   the whole npm ecosystem — awareness, not anomaly.
 * - For EVERY registryType (matching validateRuntimeArgs' resolve-time
 *   coverage in install.ts — a pypi/oci package declaring --eval-class args
 *   hard-throws at install and gets the same audit visibility in why/lock/up):
 *   each runtimeArgument matching a DANGEROUS_FLAG_PREFIXES entry yields a
 *   medium "install-script" finding naming the matched prefix. Medium, not
 *   high: validateRuntimeArgs already hard-throws at resolve time; this is the
 *   why/audit visibility signal, and high would zero the registryMeta bucket
 *   via the trust-score cap rule.
 * - oci: docker-run-without---rm is unsatisfiable from registry metadata —
 *   resolveInstallEntry (install.ts) always injects --rm into mcpm-built
 *   launchers; revisit if launch shapes ever come from declared metadata.
 *
 * Returns a new Finding[] (never mutates input).
 */
export function detectInstallScriptShape(pkg: PackageShapeInput): Finding[] {
  const findings: Finding[] = [];

  if (pkg.registryType === "npm") {
    findings.push(
      makeFinding(
        "low",
        "install-script",
        `This launcher runs install scripts: "${pkg.identifier}" is launched via "npx -y", which executes npm lifecycle scripts on first run`,
        `package: ${pkg.identifier}`,
      ),
    );
  }

  for (const rawArg of pkg.runtimeArguments ?? []) {
    const arg = typeof rawArg === "string" ? rawArg : rawArg.value;
    // First-match prefix is interpolated into the message — list order makes
    // this safe ("--inspect-brk" neither equals "--inspect" nor starts with
    // "--inspect=", so it is always named as itself).
    const prefix = DANGEROUS_FLAG_PREFIXES.find(
      (p) => arg === p || arg.startsWith(`${p}=`),
    );
    if (prefix !== undefined) {
      findings.push(
        makeFinding(
          "medium",
          "install-script",
          `Declared runtime argument "${arg}" matches the dangerous Node.js launch flag "${prefix}"`,
          `runtime argument: ${arg}`,
        ),
      );
    }
  }

  return findings;
}
