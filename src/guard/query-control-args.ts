/**
 * TODOS #51 — structural query-control-syntax detector for `tools/call`
 * argument values whose KEY implies a bare data-source resource name (a
 * table, column, database, schema, or resource id), not a query fragment.
 *
 * Real, disclosed HIGH-severity CVE: CVE-2026-33980 (pab1it0/adx-mcp-server) —
 * `get_table_schema` / `sample_table_data` / `get_table_details` f-string-
 * interpolate a `table_name` argument directly into a KQL query with no
 * escaping. The advisory's own PoC (`sensitive_data | project Secret,
 * Password | take 100 //`) uses pipe re-scoping plus a `//` comment to
 * exfiltrate columns; a sibling PoC uses a newline + `.drop table` to
 * destructively drop tables. These three tools are marketed as "safe"
 * read-only metadata inspectors (unlike the server's raw `execute_query`
 * tool), so an MCP client may auto-approve them without confirmation — the
 * injection bypasses the client's trust boundary entirely.
 *
 * Same key-first design as #50's detectShellMetacharArgs (and shares its
 * walker, tool-call-args-walk.ts): `tool_call_args` carries no schema context
 * at call time, so a blanket value-only regex over every tool_call_args
 * string would false-positive on any query-builder tool whose arguments are
 * MEANT to carry query syntax (a `query`/`filter`/`kql` field). Only testing
 * the value when the key's canonical form names a schema/resource noun
 * (table/column/field/collection/database/schema/index/view/dataset) or a
 * generic scalar-id suffix (id/identifier/uuid/slug) scopes this to the
 * shape both CVE PoCs need. `name` alone is DELIBERATELY EXCLUDED (same
 * reasoning as #50) — a bare display-name field is not in scope here.
 *
 * KNOWN GAP (TODOS #55, same as #50): this detector matches against
 * `normalizeForMatch(value)` alone, which strips rather than decodes
 * Unicode TAG-block / base64 concealment. Not fixed here.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectFinding, InspectResult } from "./types.js";
import { normalizeForMatch, truncate, worstAction } from "./patterns.js";
import { canonicalizeKey } from "./key-canon.js";
import { stringArgLeaves, toolCallArguments } from "./tool-call-args-walk.js";

export const QUERY_CONTROL_ARG_SIGNATURE_ID = "query-control-syntax-in-identifier-arg";

const PASS: InspectResult = { action: "pass", findings: [] };

/**
 * A resource NOUN appearing anywhere in the canonicalized key's token list
 * puts it in scope — this matches `table_name`/`tableName` (tokens
 * ["table","name"]) without matching a bare `customer_name`/`user_name`
 * (tokens ["customer"/"user","name"], neither a resource noun), which would
 * reopen #50's excluded "display name" FP class.
 */
const RESOURCE_NOUN_TOKENS: ReadonlySet<string> = new Set([
  "table",
  "column",
  "field",
  "collection",
  "database",
  "schema",
  "index",
  "view",
  "dataset",
]);

/** A bare scalar-id LAST token also puts a key in scope (e.g. `resource_id`). */
const GENERIC_IDENTIFIER_SUFFIXES: ReadonlySet<string> = new Set(["id", "identifier", "uuid", "slug"]);

export function isQueryScopedArgKey(rawKey: string): boolean {
  const tokens = canonicalizeKey(rawKey).split("_").filter(Boolean);
  if (tokens.some((t) => RESOURCE_NOUN_TOKENS.has(t))) return true;
  const last = tokens.at(-1);
  return last !== undefined && GENERIC_IDENTIFIER_SUFFIXES.has(last);
}

// Query-language control syntax that has no legitimate reason to appear in a
// bare table/column/database name — as opposed to a query/filter field,
// which is meant to carry this syntax and is out of scope (key-gated above).
//
// A bare pipe or a bare `.` is DELIBERATELY NOT matched: real namespaced
// identifiers legitimately use both (`Security.SigninLogs`, a dotted schema
// path) — the TODO's own documented FP risk. Requiring the pipe be followed
// by an actual query verb, and the `.` be followed by `drop`, scopes this to
// syntax that is doing something rather than merely present.
//
// The line-comment tokens (`--`, `//`) need the SAME care: a bare, unanchored
// match false-blocked on real inputs the review caught before ship —
// `database: "mongodb://localhost:27017/mydb"` / `"https://acct.blob.core..."`
// (a URI scheme's `//` has no whitespace before it) and
// `database: "analytics--eu-west"` (a version/region suffix has no
// whitespace before its `--`). A real trailing comment in an injected query
// fragment always follows a query token with a space (the CVE PoC's own
// "... | take 100 //"), so anchoring the comment marker to
// "whitespace-or-start immediately before it" keeps the injection shape
// while clearing both FP classes; that PoC still blocks regardless via the
// pipe+verb pattern above, so this scoping doesn't weaken detection of the
// motivating CVE. Residual risk, accepted: a computed-expression value like
// `column_name: "price * 1.1 -- includes VAT"` still matches (space before
// `--`) — narrower than the CVE-2026-33980 shape needs, out of scope here.
const QUERY_CONTROL_PATTERNS: readonly RegExp[] = [
  /\|\s*(project|take|where|summarize|extend|distinct|limit|top|sort|join|union|delete|drop)\b/i, // pipe re-scoping (KQL/Splunk-shaped)
  /;\s*(drop|delete|truncate|alter|create|insert|update)\b/i, // statement separator + DDL/DML
  /\.\s*drop\b/i, // KQL management command (`.drop table ...`)
  /(?:^|\s)--/, // SQL-style line comment (not a bare mid-token double-hyphen)
  /(?:^|\s)\/\//, // KQL/C-style line comment (not a URI scheme's `://`)
];

const REMEDIATION =
  "A tool call argument named like a bare table, column, database, schema, or resource " +
  "identifier contains query-control syntax: a pipe followed by a query verb (project, " +
  "take, where, ...), a statement separator followed by a DDL/DML keyword, a `.drop` " +
  "management command, or a line-comment token (--, //). CVE-2026-33980 (adx-mcp-server) " +
  "reaches data exfiltration and destructive table drops through exactly this shape — a " +
  "tool marketed as a safe read-only metadata inspector interpolates the argument " +
  "unescaped into a live query. The call was blocked. If this tool legitimately accepts " +
  "query syntax in this field, mute via `mcpm guard mute query-control-syntax-in-identifier-arg`.";

function matchesQueryControlSyntax(value: string): boolean {
  const normalized = normalizeForMatch(value);
  return QUERY_CONTROL_PATTERNS.some((re) => re.test(normalized));
}

function makeFinding(toolName: string, key: string, value: string): InspectFinding {
  return {
    signature_id: QUERY_CONTROL_ARG_SIGNATURE_ID,
    category: "MCP-QUERY-INJECTION",
    severity: "critical",
    target: "tool_call_args", // block-capable carrier (NOT in WARN_ONLY_TARGETS)
    matched_text_excerpt: truncate(`argument "${key}" of tool "${toolName}": ${value}`),
    remediation: REMEDIATION,
  };
}

/**
 * Inspect a `tools/call` request for query-control syntax in a
 * resource-identifier-shaped argument. A no-op (pass) on every other frame
 * shape.
 */
export function detectQueryControlArgs(msg: JSONRPCMessage): InspectResult {
  const call = toolCallArguments(msg);
  if (call === null) return PASS;

  const findings: InspectFinding[] = [];
  for (const { key, value } of stringArgLeaves(call.args)) {
    if (isQueryScopedArgKey(key) && matchesQueryControlSyntax(value)) {
      findings.push(makeFinding(call.toolName, key, value));
    }
  }
  if (findings.length === 0) return PASS;

  return { action: worstAction(findings), findings };
}
