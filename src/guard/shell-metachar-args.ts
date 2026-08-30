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
 * TODOS #55 (closed here): a value passed to `matchesShellMetachar` alone
 * only sees `normalizeForMatch(value)`, which STRIPS Unicode TAG-block
 * characters (PATTERN_BREAKERS) rather than decoding them — so a payload
 * concealed via TAG-block "ASCII smuggling" was erased, not revealed, and
 * this detector never got the tag-decode-and-rescan pass `inspectMessage`
 * runs for the regular signature catalog on every carrier including
 * `tool_call_args`. Fixed by reusing `inspectTagEncoded` directly (one
 * synthetic `Signature` wrapping this detector's own pattern list) rather
 * than re-deriving its multi-round-hardened decode/mask/concealment-surplus
 * logic (TODOS #31/#34) — see `detectShellMetacharArgs` below.
 *
 * base64 decode-and-rescan is deliberately NOT added: the regular catalog
 * doesn't run it on `tool_call_args` either (`DECODE_TARGETS` in patterns.ts
 * excludes it — F10 Detector-B's threat model is a server encoding a payload
 * into its OWN response, not an argument value), so omitting it here is
 * parity with the catalog, not a gap.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectFinding, InspectResult, Signature } from "./types.js";
import { inspectTagEncoded, normalizeForMatch, truncate, worstAction } from "./patterns.js";
import { canonicalizeKey } from "./key-canon.js";
import { stringArgLeaves, toolCallArguments } from "./tool-call-args-walk.js";

export const SHELL_METACHAR_ARG_SIGNATURE_ID = "shell-metachar-in-identifier-arg";

const PASS: InspectResult = { action: "pass", findings: [] };

/**
 * Canonical LAST token allowlist for a scalar identifier/path/number field.
 * `id`/`uuid`/`identifier`/`slug`/`namespace`/`number`/`num` are conventionally
 * single-token values with no legitimate reason to carry shell syntax; `path`
 * is included because a real filesystem path never legitimately contains
 * `;`/backtick/`&&` on any OS, even though it may contain spaces — and it is
 * required, since CVE-2026-25546's vulnerable parameter is `projectPath`.
 *
 * NOTE the bound on that reasoning, learned by measurement (TODOS #56): it
 * holds for FILESYSTEM paths, but a `path`-suffixed ARGUMENT is also routinely
 * a URL or API path, which legitimately carries a raw `|` in a query string.
 * That is why the pipe pattern is gone; do not re-derive "a path can't contain
 * X" from filesystem semantics alone when adding a pattern here.
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
// A bare pipe is DROPPED for the SAME three reasons as `&` above, each
// measured pre-release rather than argued (TODOS #56):
//   1. Gating it is evadable — `cmd1|cmd2` needs no whitespace either.
//   2. Ungated, it false-positives on real values: a URL query string under a
//      `path`-suffixed key routinely carries a raw pipe (`?family=Roboto|Open+Sans`
//      — Google Fonts — plus `?fields=id|name`, `?sort=created|desc`), and this
//      is a block-capable carrier, so all three were HARD-BLOCKED on the live relay.
//   3. Neither motivating CVE needs it: CVE-2025-53818's PoC carries `;` and
//      CVE-2026-25546's carries a backtick, so both still block. Deleting the
//      pattern left all 150 guard tests green — it was never load-bearing, and
//      nothing pinned it.
// The cost is a real but narrower blind spot: a pipe-ONLY injection
// (`issue_number: "1|curl attacker"`) with no other metacharacter now passes.
// Restoring it needs a benign-corpus pass first — filed as TODOS #56, not
// dropped silently.
const SHELL_METACHAR_PATTERNS: readonly RegExp[] = [
  /\$\(/, // $(...) command substitution
  /`/, // backtick command substitution
  /;/, // statement separator
  /&&/, // command chaining (AND)
];

const REMEDIATION =
  "A tool call argument named like a bare identifier or filesystem path (an id, number, " +
  "path, slug, uuid, or namespace field) contains shell-metacharacter or " +
  "command-substitution syntax ($(...), a backtick, ;, or &&). " +
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

// Wraps this detector's own pattern list as a Signature so `inspectTagEncoded`
// can be reused verbatim (TODOS #55) instead of re-deriving its decode/mask/
// concealment-surplus logic. `description` is unused outside the catalog
// proper; `id` is what dedup and event logging key on.
const SIGNATURE: Signature = {
  id: SHELL_METACHAR_ARG_SIGNATURE_ID,
  category: "MCP-COMMAND-INJECTION",
  severity: "critical",
  description: SHELL_METACHAR_ARG_SIGNATURE_ID,
  target: "tool_call_args",
  patterns: SHELL_METACHAR_PATTERNS,
  remediation: REMEDIATION,
};

/**
 * Inspect a `tools/call` request for shell-metacharacter syntax in an
 * identifier-shaped argument. A no-op (pass) on every other frame shape.
 */
export function detectShellMetacharArgs(msg: JSONRPCMessage): InspectResult {
  const call = toolCallArguments(msg);
  if (call === null) return PASS;

  const findings: InspectFinding[] = [];
  for (const { key, value } of stringArgLeaves(call.args)) {
    if (!isIdentifierLikeArgKey(key)) continue;
    if (matchesShellMetachar(value)) {
      findings.push(makeFinding(call.toolName, key, value));
    }
    // TAG-block decode-and-rescan (TODOS #55), run UNCONDITIONALLY —
    // not only when the plain match above missed. matchesShellMetachar only
    // sees the STRIPPED value, so a payload concealed with Unicode tag
    // characters is invisible to it; inspectTagEncoded decodes tag runs IN
    // PLACE and compares occurrence counts against a masked view (TODOS
    // #31/#34) — reused here rather than re-implemented. Running it even
    // after a plain match reports a SEPARATE concealed occurrence a value
    // can carry alongside a visible one (e.g. a visible `;` plus an
    // independently tag-concealed backtick) — an early `continue` here
    // would silently drop that a concealment attempt was ALSO present. The
    // raw value is included in the excerpt (not just the bare matched
    // delimiter inspectTagEncoded returns) so an operator sees the same
    // context the plain-match finding above shows.
    for (const f of inspectTagEncoded(value, [SIGNATURE], "tool_call_args")) {
      findings.push({
        ...f,
        matched_text_excerpt: truncate(
          `argument "${key}" of tool "${call.toolName}": ${value} (${f.matched_text_excerpt})`,
        ),
      });
    }
  }
  if (findings.length === 0) return PASS;

  return { action: worstAction(findings), findings };
}
