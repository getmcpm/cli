/**
 * TODOS #52 — structural CLI-flag-injection detector for `tools/call` argument
 * values whose KEY implies a bare namespace or opaque identifier, not a
 * free-text, title, or config field.
 *
 * Real, disclosed HIGH-severity CVE: CVE-2026-39884 (Flux159/mcp-server-kubernetes,
 * `port_forward`). The tool builds a `kubectl` invocation by string-concatenating
 * `resourceName`/`namespace`/etc. into one command string, then does a naive
 * `command.split(" ")` before `spawn()` — every OTHER tool in the same codebase
 * uses the safe array-based `execFileSync(argsArray)` pattern, so this is a
 * single-tool regression. Splitting on whitespace lets an attacker embed a
 * second CLI flag inside a string argument that should be a bare identifier;
 * the advisory's PoC is `resourceName: "my-database --address=0.0.0.0"`, which
 * turns a normally localhost-only port-forward into one bound on all
 * interfaces, exposing an internal database to the network (CVSS 8.3 HIGH).
 *
 * Same key-first design as #50/#51 (and shares their walker,
 * tool-call-args-walk.ts): `tool_call_args` carries no schema context at call
 * time, so a blanket value-only regex would false-positive on any tool whose
 * arguments legitimately carry flag-shaped text (e.g. a config/CLI-passthrough
 * field). Only testing the value when the key's canonical form names a scalar
 * namespace/opaque-identifier field scopes this to the CVE's shape.
 *
 * `name` is DELIBERATELY EXCLUDED from the key scope, same as #50/#51 — an
 * earlier version of this file included it (reasoning: the CVE's own
 * vulnerable argument is `resourceName`, and "no real name contains a literal
 * ` --word` substring"). A pre-merge adversarial review measured that claim
 * and found it FALSE, with five independently-reproduced real shapes: a
 * ticket/PR/task title mentioning a flag by name (`task_name: "Add --dry-run
 * support to sync command"`, lifted verbatim from this project's own commit
 * history), a compound `*_name` key whose OTHER token already marks it as a
 * free-text CLI-passthrough field (`flag_name`, `option_name`, `script_name`
 * under npm's own documented `<script> -- <flags>` convention), and a
 * freeform cloud-resource "Name" tag carrying an appended operational note
 * (`resource_name: "prod-db-01 --do-not-delete"`). That last shape is
 * structurally IDENTICAL to the CVE's own PoC (a single-token prefix, a
 * space, then a `--word` token) — there is no regex-level distinction between
 * an injected flag and a benign operational annotation on a "name"-shaped
 * field, because the ambiguity is semantic (does the wrapped tool interpret
 * the flag?), not structural. Excluding `name` closes all five measured FP
 * classes; the accepted cost is that the advisory's own literal PoC (via
 * `resourceName`) now scores `pass`. The SAME vulnerable code path is still
 * caught via `namespace` (named as an equally vulnerable argument by the
 * advisory itself, and namespaces are a far more constrained value space by
 * convention — a k8s namespace is a short DNS-label token, never a
 * multi-word phrase). Filed as TODOS #57 rather than left undocumented.
 *
 * TODOS #55 (closed here, same fix as #50/#51): the plain match alone only
 * sees `normalizeForMatch(value)`, which STRIPS Unicode TAG-block characters
 * rather than decoding-and-rescanning them. Fixed by reusing
 * `inspectTagEncoded` via one synthetic `Signature` — see #50's module doc
 * comment for the full rationale, including why base64 decode-and-rescan is
 * deliberately not added.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectFinding, InspectResult, Signature } from "./types.js";
import { inspectTagEncoded, normalizeForMatch, truncate, worstAction } from "./patterns.js";
import { canonicalizeKey } from "./key-canon.js";
import { stringArgLeaves, toolCallArguments } from "./tool-call-args-walk.js";

export const CLI_FLAG_INJECTION_ARG_SIGNATURE_ID = "cli-flag-injection-in-identifier-arg";

const PASS: InspectResult = { action: "pass", findings: [] };

/**
 * Canonical LAST token allowlist for a scalar namespace/opaque-identifier
 * field. `name` is deliberately EXCLUDED — see the module doc comment for the
 * measured FP classes that removing it closes, and the accepted gap (the
 * CVE advisory's own `resourceName` PoC is no longer caught by this
 * signature; `namespace` catches the same vulnerable code path).
 */
const FLAG_INJECTION_KEY_SUFFIXES: ReadonlySet<string> = new Set([
  "namespace",
  "id",
  "identifier",
  "uuid",
  "slug",
]);

export function isFlagInjectionScopedArgKey(rawKey: string): boolean {
  const tokens = canonicalizeKey(rawKey).split("_").filter(Boolean);
  const last = tokens.at(-1);
  return last !== undefined && FLAG_INJECTION_KEY_SUFFIXES.has(last);
}

// A long-form CLI flag token (`--word` or `--word=value`) embedded in a value
// that should be a bare namespace/identifier. Anchored to whitespace-or-
// start immediately before the `--` (same anchoring discipline as #51's line-
// comment patterns) so a legitimate double-hyphen used as a mid-token
// separator — a version/region suffix like `analytics--eu-west` — does not
// false-block: there is no whitespace before its `--`. The motivating CVE's
// PoC (`"my-database --address=0.0.0.0"`) has a space before the flag, which
// is the injection shape itself (a shell/argv splitter treats whitespace as
// the argument boundary) — this is not an incidental convenience, it is the
// exact mechanism the CVE exploits.
//
// Deliberately NOT matching single-dash short flags (`-v`, `-n foo`): a lone
// dash followed by a letter is far more likely to appear in legitimate values
// (version suffixes, negative-looking tokens) and neither this CVE's PoC nor
// any other known case needs it. Revisit with a benign-corpus pass if real
// single-dash-flag-injection evidence surfaces.
const CLI_FLAG_PATTERN = /(?:^|\s)--[A-Za-z][\w-]*(?:=\S*)?/;

const REMEDIATION =
  "A tool call argument named like a bare namespace or opaque identifier contains a " +
  "`--`-prefixed CLI flag token (e.g. `--address=0.0.0.0`). CVE-2026-39884 " +
  "(mcp-server-kubernetes `port_forward`) reaches this exact shape: the argument is " +
  "whitespace-split into a shell command, so an embedded flag is interpreted as a " +
  "second command-line option rather than part of the identifier — turning a " +
  "normally localhost-only operation into one exposed on all interfaces. The call " +
  "was blocked. If this tool legitimately accepts flag-shaped text in this field, " +
  "mute via `mcpm guard mute cli-flag-injection-in-identifier-arg`.";

function matchesCliFlagInjection(value: string): boolean {
  return CLI_FLAG_PATTERN.test(normalizeForMatch(value));
}

function makeFinding(toolName: string, key: string, value: string): InspectFinding {
  return {
    signature_id: CLI_FLAG_INJECTION_ARG_SIGNATURE_ID,
    category: "MCP-ARGUMENT-INJECTION",
    severity: "critical",
    target: "tool_call_args", // block-capable carrier (NOT in WARN_ONLY_TARGETS)
    matched_text_excerpt: truncate(`argument "${key}" of tool "${toolName}": ${value}`),
    remediation: REMEDIATION,
  };
}

// Wraps this detector's own pattern as a Signature so `inspectTagEncoded` can
// be reused verbatim (TODOS #55) instead of re-deriving its decode/mask/
// concealment-surplus logic.
const SIGNATURE: Signature = {
  id: CLI_FLAG_INJECTION_ARG_SIGNATURE_ID,
  category: "MCP-ARGUMENT-INJECTION",
  severity: "critical",
  description: CLI_FLAG_INJECTION_ARG_SIGNATURE_ID,
  target: "tool_call_args",
  patterns: [CLI_FLAG_PATTERN],
  remediation: REMEDIATION,
};

/**
 * Inspect a `tools/call` request for an embedded CLI flag in a
 * namespace/identifier-shaped argument. A no-op (pass) on every other frame
 * shape.
 */
export function detectCliFlagInjectionArgs(msg: JSONRPCMessage): InspectResult {
  const call = toolCallArguments(msg);
  if (call === null) return PASS;

  const findings: InspectFinding[] = [];
  for (const { key, value } of stringArgLeaves(call.args)) {
    if (!isFlagInjectionScopedArgKey(key)) continue;
    if (matchesCliFlagInjection(value)) {
      findings.push(makeFinding(call.toolName, key, value));
    }
    // TAG-block decode-and-rescan (TODOS #55), run UNCONDITIONALLY, not only
    // when the plain match above missed — see #50's detector for the full
    // rationale (a value can carry both a visible AND a separately-concealed
    // occurrence) and why the raw value is folded into the excerpt.
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
