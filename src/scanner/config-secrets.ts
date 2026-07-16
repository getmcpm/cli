/**
 * Plaintext-secret scan over client MCP config (F9 · PR1).
 *
 * mcpm ships an encrypted secret store + OS keychain, but a server's env/header
 * values are routinely pasted in plaintext (24k+ such leaks documented in the
 * wild). This read-only scan flags them so `doctor` can nudge the user toward
 * `mcpm secrets` / keychain mode.
 *
 * REDACTION CONTRACT: a finding carries the KEY name and a LABEL only — NEVER the
 * matched value. Values already stored as `mcpm:keychain:` placeholders are
 * skipped (they are the safe state, not a leak).
 *
 * Two detectors:
 *  1. value-shape — the sweep-hardened `detectSecretLabels` patterns (AWS /
 *     GitHub / OpenAI / … keys). Near-zero false positives.
 *  2. secret-named key — a tight key-name heuristic for generic passwords/tokens
 *     no value-regex matches, gated by strong non-secret-qualifier (URL/ID/NAME/…)
 *     and non-secret-value (reference/URL/path/flag) exclusions + a benign corpus.
 *
 * Pure: no I/O. The caller (doctor) supplies the already-read config.
 */

import type { McpServerEntry } from "../config/adapters/index.js";
import { detectSecretLabels } from "./patterns.js";
import { parsePlaceholder } from "../store/keychain.js";

export interface ConfigSecretFinding {
  /** Server name as it appears in the client config. */
  server: string;
  /** Which value map the secret sits in. */
  field: "env" | "header";
  /** The env var / header NAME. Never the value. */
  key: string;
  /** What was matched (e.g. "AWS access key"). Never the value. */
  label: string;
}

/** Label for a key-heuristic hit (detector 2). Value-free by construction. */
const GENERIC_LABEL = "secret-named key holds a plaintext value";

// Secret-indicating whole words. Matched against the key normalized to
// upper-case with '-'→'_' (so `X-API-Key` reads as `X_API_KEY`). Bare `KEY` is
// deliberately NOT a word (PUBLIC_KEY / KEY_ID / SORT_KEY are not secrets) — only
// the listed `*_KEY` compounds count.
const SECRET_KEY_RE =
  /(?:^|_)(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|PAT|APIKEY|AUTHORIZATION|CREDENTIALS?|(?:API|ACCESS|PRIVATE|SECRET|SESSION|SIGNING|ENCRYPTION)_KEY)(?:_|$)/;

// Tokens that mean the field is a descriptor of a secret, not the secret itself
// (an id, url, name, endpoint, …). Any one vetoes a key-name match, so
// `TOKEN_URL` / `AWS_ACCESS_KEY_ID` / `SECRET_NAME` / `PUBLIC_KEY` do not fire.
// KNOWN GAP (advisory tool, accepted): the veto matches a qualifier ANYWHERE in the
// key, so `ID_TOKEN` (where `ID` is the credential TYPE, not a descriptor) is missed.
// A suffix-anchored fix would newly false-POSITIVE on `MAPBOX_PUBLIC_TOKEN`; since a
// false negative in an advisory scan is acceptable but a false positive is not, we
// keep the anywhere-match.
const NON_SECRET_QUALIFIER_RE =
  /(?:^|_)(?:URL|URI|ENDPOINT|HOST|PORT|ID|NAME|PATH|FILE|DIR|ENABLED|DISABLED|TYPE|MODE|REGION|TIMEOUT|VERSION|PUBLIC|FORMAT|HEADER|PREFIX|SUFFIX|COUNT|SIZE|TTL|EXPIRY|EXPIRES|ISSUER|AUDIENCE|ALGORITHM|ALG|SCOPE|METHOD)(?:_|$)/;

function normalizeKey(key: string): string {
  return key.toUpperCase().replace(/-/g, "_");
}

function keyLooksSecret(key: string): boolean {
  const k = normalizeKey(key);
  return SECRET_KEY_RE.test(k) && !NON_SECRET_QUALIFIER_RE.test(k);
}

/** True when the value is plausibly a real plaintext secret (not a ref/URL/flag). */
function valueLooksPlaintextSecret(value: string): boolean {
  const v = value.trim();
  if (v.length < 6) return false; // too short to be a credential
  if (parsePlaceholder(value) !== null) return false; // mcpm keychain placeholder
  // Reference, not a literal secret. `${...}` is matched ANYWHERE (not just leading):
  // `Bearer ${input:key}` / `Bearer ${env:VAR}` is VS Code / Cursor / Claude Code's
  // documented header idiom — the recommended SAFE state. Detector 1 already ran on
  // the raw value, so a shaped credential embedded alongside a ref is still caught.
  if (/\$\{[^}]*\}/.test(v)) return false; // ${VAR} template (embedded or leading)
  if (/^\$[A-Za-z_]/.test(v)) return false; // leading $VAR reference
  if (/^%[A-Za-z_][A-Za-z0-9_]*%([\\/].*)?$/.test(v)) return false; // %VAR% ref or %VAR%-rooted path
  // A URI of ANY scheme: real endpoints AND secret-manager references that are the
  // safe state — op:// (1Password), vault:// (Vault). ACCEPTED FALSE-NEGATIVE: a URI
  // that itself CARRIES a credential (connection-string userinfo postgres://u:p@host,
  // or a query-param secret like otpauth://…?secret=SEED) is excluded too. Detector 1
  // still catches any prefix-shaped credential embedded in the value, and the bare
  // (non-URI) secret form is still caught by detector 2. Zero-FP is the hard invariant;
  // re-catching these would need query-param parsing that risks FPs on real endpoints.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return false;
  // Filesystem path — POSIX (~ . /) or Windows (drive-letter, UNC).
  if (/^[~./]/.test(v) || /^[A-Za-z]:[\\/]/.test(v) || /^\\\\/.test(v)) return false;
  if (/^(true|false|\d+)$/i.test(v)) return false; // boolean / plain number
  return true;
}

function scanMap(
  server: string,
  field: "env" | "header",
  map: Record<string, string> | undefined
): ConfigSecretFinding[] {
  if (!map) return [];
  const out: ConfigSecretFinding[] = [];
  for (const [key, value] of Object.entries(map)) {
    if (typeof value !== "string") continue;
    if (parsePlaceholder(value) !== null) continue; // already stored safely — not a leak
    const labels = detectSecretLabels(value);
    if (labels.length > 0) {
      // Value-shape is the more specific, higher-confidence signal — ONE finding per
      // (field, key) even when several patterns match (e.g. a Bearer-wrapped ghp_
      // token hits both), so the --report count is not inflated. Skip the heuristic.
      out.push({ server, field, key, label: labels.join(", ") });
      continue;
    }
    if (keyLooksSecret(key) && valueLooksPlaintextSecret(value)) {
      out.push({ server, field, key, label: GENERIC_LABEL });
    }
  }
  return out;
}

/** Scan one server's env + headers for plaintext secrets. */
export function scanServerConfigSecrets(
  server: string,
  entry: McpServerEntry
): ConfigSecretFinding[] {
  return [...scanMap(server, "env", entry.env), ...scanMap(server, "header", entry.headers)];
}

/** Scan every server in a client's config. */
export function scanConfigSecrets(
  servers: Record<string, McpServerEntry>
): ConfigSecretFinding[] {
  return Object.entries(servers).flatMap(([name, entry]) => scanServerConfigSecrets(name, entry));
}
