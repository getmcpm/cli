/**
 * .env file parser — reads KEY=VALUE pairs from a file.
 *
 * Supports:
 * - KEY=VALUE pairs (one per line)
 * - # comments (full-line and inline)
 * - Empty lines (skipped)
 * - Quoted values ("value" or 'value')
 * - Malformed lines (skipped with warning)
 *
 * Does NOT support:
 * - Variable interpolation ($VAR or ${VAR})
 * - Multi-line values
 * - Export prefix (export KEY=VALUE)
 */

import { readFile } from "fs/promises";
import { isEnoent } from "../utils/fs.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Valid env var key: starts with letter or underscore, alphanumeric + underscore only. */
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Keys that would pollute Object.prototype if assigned as own properties. */
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "__defineGetter__", "__defineSetter__"]);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EnvParseResult {
  readonly vars: Readonly<Record<string, string>>;
  readonly warnings: readonly string[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a .env file into a key-value record.
 *
 * Returns an empty result if the file does not exist (not an error).
 * Malformed lines are skipped with warnings, never crash.
 */
export async function parseEnvFile(filePath: string): Promise<EnvParseResult> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch (err) {
    if (isEnoent(err)) {
      return { vars: {}, warnings: [] };
    }
    throw err;
  }

  return parseEnvString(raw);
}

/**
 * Parse a .env-formatted string into key-value pairs.
 * Exported for testing without filesystem access.
 */
export function parseEnvString(content: string): EnvParseResult {
  const vars: Record<string, string> = {};
  const warnings: string[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const raw = lines[i];
    const trimmed = raw.trim();

    if (trimmed === "" || trimmed.startsWith("#")) {
      continue;
    }

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      warnings.push(`Line ${lineNum}: skipped malformed line (no = sign)`);
      continue;
    }

    const key = trimmed.slice(0, eqIndex).trim();
    if (key === "") {
      warnings.push(`Line ${lineNum}: skipped line with empty key`);
      continue;
    }

    // Validate key against safe pattern and blocklist (prevents prototype poisoning)
    if (!ENV_KEY_RE.test(key) || UNSAFE_KEYS.has(key)) {
      warnings.push(
        `Line ${lineNum}: skipped invalid key "${key}"`
      );
      continue;
    }

    let value = trimmed.slice(eqIndex + 1).trim();

    // Require space before # for inline comments (dotenv standard)
    if (!value.startsWith('"') && !value.startsWith("'")) {
      const commentIndex = value.indexOf(" #");
      if (commentIndex !== -1) {
        value = value.slice(0, commentIndex).trim();
      }
    }

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    vars[key] = value;
  }

  return { vars, warnings };
}

