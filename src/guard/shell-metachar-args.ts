/**
 * TODOS #50 — structural shell-metacharacter detector for `tools/call`
 * argument values whose KEY implies a bare identifier or filesystem path.
 *
 * Two real, disclosed HIGH-severity CVEs splice a `tools/call` argument value
 * unescaped into a shell string via `exec()`: CVE-2025-53818
 * (Sunwood-ai-labs/github-kanban-mcp-server, `add_comment`'s `issue_number`)
 * and CVE-2026-25546 (Coding-Solo/godot-mcp, `create_scene`'s `projectPath`).
 * Both PoCs score `pass` against the shipped catalog — the only tool_call_args
 * signature (`owasp-mcp-7-path-exfil-in-args`) matches sensitive PATH
 * REFERENCES, which is orthogonal to shell-metacharacter SYNTAX.
 *
 * The content-regex pipeline walks string VALUES only (`stringLeaves` yields
 * `Object.values`, discarding the key), so it structurally cannot tell "a
 * shell-command argument that legitimately contains `;`/`|`/`&`" (an
 * execute_command-style tool) from "a bare identifier that should never
 * contain them" (an issue number, a project path) — a blanket value-only
 * regex over every tool_call_args string would false-positive on every
 * shell/exec-style MCP tool, whose arguments are MEANT to carry that syntax.
 *
 * This detector instead walks the KEY first, like F5's detectExfilParams, and
 * only tests the VALUE when the key's canonical last token names a scalar
 * identifier/path (id/number/num/path/slug/uuid/identifier/namespace) — the
 * exact shape of both CVEs' vulnerable parameters. `name` is DELIBERATELY
 * EXCLUDED from this initial allowlist: display/company/file names are
 * natural-language-ish and can legitimately carry punctuation this detector's
 * value patterns would flag (e.g. "Smith & Jones"), which the narrower
 * suffixes here are not exposed to. Revisit `name` alongside TODOS #51/#52,
 * which need the same key-classification with a benign-corpus pass first.
 *
 * KNOWN GAP (documented, not fixed here — TODOS #40 already flags the general
 * class): this detector matches against `normalizeForMatch(value)` alone,
 * which STRIPS Unicode TAG-block characters (PATTERN_BREAKERS) rather than
 * decoding and re-scanning them the way `inspectMessage`'s tag/base64
 * decode-and-rescan passes do for the regular signature catalog. A shell-
 * metacharacter payload concealed via TAG-block "ASCII smuggling" or base64
 * inside an identifier-shaped argument value evades this detector. Closing it
 * needs the same decode-and-rescan machinery `inspectMessage` uses (a
 * multi-round-hardened piece of infrastructure — see the TAG-concealment
 * history in CLAUDE.md), applied to a bespoke key+value walker rather than a
 * signature/pattern list; out of scope for this slice. Filed as TODOS #55.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectFinding, InspectResult } from "./types.js";
import { normalizeForMatch, truncate, worstAction } from "./patterns.js";
import { canonicalizeKey } from "./key-canon.js";
import { stringArgLeaves, toolCallArguments } from "./tool-call-args-walk.js";

export const SHELL_METACHAR_ARG_SIGNATURE_ID = "shell-metachar-in-identifier-arg";

const PASS: InspectResult = { action: "pass", findings: [] };

/**
 * Canonical LAST token allowlist for a scalar identifier/path/number field.
 * `id`/`uuid`/`identifier`/`slug`/`namespace`/`number`/`num` are conventionally
 * single-token values with no legitimate reason to carry shell syntax; `path`
 * is included because a real filesystem path never legitimately contains
 * `;`/backtick/`&&`/an unescaped `|` on any OS, even though it may contain
 * spaces.
 */
const IDENTIFIER_KEY_SUFFIXES: ReadonlySet<string> = new Set([
  "id",
  "number",
  "num",
  "path",
  "slug",
  "uuid",
  "identifier",
  "namespace",
]);

export function isIdentifierLikeArgKey(rawKey: string): boolean {
  const tokens = canonicalizeKey(rawKey).split("_").filter(Boolean);
  const last = tokens.at(-1);
  return last !== undefined && IDENTIFIER_KEY_SUFFIXES.has(last);
}

// Shell metacharacter / command-substitution syntax that has no legitimate
// reason to appear in a bare identifier or filesystem path value.
//
// A standalone background `&` is DELIBERATELY NOT matched: real shells don't
// require whitespace around it (`cmd1&cmd2` is valid), so a whitespace-gated
// pattern is trivially evadable, but an unconditional bare-`&` match would
// false-positive on real path/namespace values containing a literal
// ampersand (e.g. "R&D/report.pdf") — a live risk this detector's two
// motivating CVEs don't even need (neither PoC uses `&`). Revisit with a
// benign-corpus pass if evidence justifies it (review: TODOS #50).
//
// `||` needs no separate alternative: any string containing it already
// contains a single `|`, which the bare-pipe pattern below already matches.
const SHELL_METACHAR_PATTERNS: readonly RegExp[] = [
  /\$\(/, // $(...) command substitution
  /`/, // backtick command substitution
  /;/, // statement separator
  /&&/, // command chaining (AND)
  /\|/, // pipe — also covers `||` (a run of two pipes contains one)
];

const REMEDIATION =
  "A tool call argument named like a bare identifier or filesystem path (an id, number, " +
  "path, slug, uuid, or namespace field) contains shell-metacharacter or " +
  "command-substitution syntax ($(...), a backtick, ;, &&, or a pipe). " +
  "Two real, disclosed CVEs (github-kanban-mcp-server CVE-2025-53818, godot-mcp " +
  "CVE-2026-25546) reach command injection through exactly this shape — the value is " +
  "spliced unescaped into a shell command. The call was blocked. If this tool " +
  "legitimately accepts shell syntax in this field, mute via " +
  "`mcpm guard mute shell-metachar-in-identifier-arg`.";

function matchesShellMetachar(value: string): boolean {
  const normalized = normalizeForMatch(value);
  return SHELL_METACHAR_PATTERNS.some((re) => re.test(normalized));
}

function makeFinding(toolName: string, key: string, value: string): InspectFinding {
  return {
    signature_id: SHELL_METACHAR_ARG_SIGNATURE_ID,
    category: "MCP-COMMAND-INJECTION",
    severity: "critical",
    target: "tool_call_args", // block-capable carrier (NOT in WARN_ONLY_TARGETS)
    matched_text_excerpt: truncate(`argument "${key}" of tool "${toolName}": ${value}`),
    remediation: REMEDIATION,
  };
}

/**
 * Inspect a `tools/call` request for shell-metacharacter syntax in an
 * identifier-shaped argument. A no-op (pass) on every other frame shape.
 */
export function detectShellMetacharArgs(msg: JSONRPCMessage): InspectResult {
  const call = toolCallArguments(msg);
  if (call === null) return PASS;

  const findings: InspectFinding[] = [];
  for (const { key, value } of stringArgLeaves(call.args)) {
    if (isIdentifierLikeArgKey(key) && matchesShellMetachar(value)) {
      findings.push(makeFinding(call.toolName, key, value));
    }
  }
  if (findings.length === 0) return PASS;

  return { action: worstAction(findings), findings };
}
