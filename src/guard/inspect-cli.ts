/**
 * `mcpm guard inspect` — run the guard's signature catalog over MCP JSON-RPC
 * frame(s) offline, with no relay, no wrapped server, and no network.
 *
 * Why this exists as a PUBLIC command (not just an internal function): an
 * external harness — mcp-guardbench, a CI job, a researcher reproducing a
 * finding — needs to ask "what does mcpm's guard say about this frame?" without
 * importing `src/guard/*`. Before this command the benchmark's reference adapter
 * vendored an esbuild bundle of patterns+signatures, which (a) silently drifts
 * from the shipped engine and (b) gave mcpm a privileged in-process path that no
 * other guard being scored could have. This command is the level playing field:
 * every guard, mcpm included, is measured through its own published CLI.
 *
 * Contract (depended on by external adapters — treat as semi-stable):
 *   - input is ONE JSON frame (pretty-printed is fine) or NDJSON, one per line
 *   - `--json` writes exactly one verdict object per input frame, in INPUT
 *     ORDER — positional correlation is what lets a harness zip verdicts back
 *     to its own case ids without mcpm needing to know about them
 *   - an unparseable frame yields `{"action":"error"}`, never a silent skip and
 *     never a fabricated "pass" (a harness must be able to tell "my guard said
 *     this is safe" apart from "my guard fell over")
 *
 * The verdict is the same `inspectMessage` default action the relay uses,
 * including the warn-only carrier clamp — so a `resources/read` injection
 * reports `warn` here exactly as it would in-line. Policy overrides
 * (mute/log_only, `guard.policy.json`) are deliberately NOT applied: this
 * command answers "what do the signatures see", not "what would this user's
 * configured policy do".
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "./patterns.js";
import { sanitizeForTerminal } from "./sanitize.js";
import { OWASP_MCP_TOP_10 } from "./signatures.js";
import type { InspectAction, InspectFinding } from "./types.js";

export interface InspectCliOpts {
  /** Raw input text: one JSON frame, or NDJSON with one frame per line. */
  readonly source: string;
  /** Emit NDJSON verdicts (one line per input frame) instead of human text. */
  readonly json?: boolean;
  readonly write: (s: string) => void;
}

export interface InspectCliResult {
  /** Worst action across all frames — drives the process exit code. */
  readonly action: InspectAction;
  /** Frames that could not be parsed as a JSON-RPC object. */
  readonly errors: number;
  /** Frames actually inspected, including the unparseable ones. */
  readonly frames: number;
}

const ACTION_RANK: Readonly<Record<InspectAction, number>> = { pass: 0, warn: 1, block: 2 };

type ParsedFrame = { readonly frame: JSONRPCMessage } | { readonly error: string };

/**
 * Split input into frames. A whole-input parse is tried FIRST so a
 * pretty-printed single frame (the common hand-authored / captured case) works;
 * NDJSON falls through to per-line parsing.
 */
function parseFrames(rawSource: string): readonly ParsedFrame[] {
  // A leading BOM is common in editor-saved captures and makes JSON.parse throw
  // on otherwise-valid input; stripping it avoids a baffling parse error.
  const source = rawSource.replace(/^\uFEFF/, "");
  if (source.trim() === "") return [];

  try {
    return [asFrame(JSON.parse(source) as unknown)];
  } catch {
    // Not a single JSON document — treat as NDJSON.
  }

  const frames: ParsedFrame[] = [];
  for (const line of source.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue; // blank lines are separators, not frames
    try {
      frames.push(asFrame(JSON.parse(trimmed) as unknown));
    } catch (err) {
      frames.push({ error: err instanceof Error ? err.message : String(err) });
    }
  }
  return frames;
}

/**
 * A JSON-RPC frame must be a plain object. Arrays (JSON-RPC batches) are
 * rejected rather than silently mis-inspected — `inspectMessage` takes a single
 * message, and quietly passing a batch would report a false "pass" on whatever
 * it contains. Send batch members as separate NDJSON lines.
 */
function asFrame(value: unknown): ParsedFrame {
  if (typeof value !== "object" || value === null) {
    return { error: `expected a JSON-RPC object, got ${value === null ? "null" : typeof value}` };
  }
  if (Array.isArray(value)) {
    return { error: "expected a single JSON-RPC object, got an array (send batch members as separate NDJSON lines)" };
  }
  return { frame: value as JSONRPCMessage };
}

function findingToJson(f: InspectFinding): Record<string, unknown> {
  return {
    signature_id: f.signature_id,
    category: f.category,
    severity: f.severity,
    target: f.target,
    matched_text_excerpt: f.matched_text_excerpt,
    remediation: f.remediation,
    ...(f.decoded === true ? { decoded: true } : {}),
  };
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export function runInspectCommand(opts: InspectCliOpts): InspectCliResult {
  const parsed = parseFrames(opts.source);
  const json = opts.json === true;

  let worst: InspectAction = "pass";
  let errors = 0;
  const tally: Record<InspectAction, number> = { pass: 0, warn: 0, block: 0 };
  const humanLines: string[] = [];

  parsed.forEach((entry, i) => {
    if ("error" in entry) {
      errors += 1;
      if (json) {
        opts.write(`${JSON.stringify({ action: "error", error: entry.error })}\n`);
      } else {
        humanLines.push(`frame ${i + 1} — error: ${sanitizeForTerminal(entry.error)}`);
      }
      return;
    }

    const result = inspectMessage(entry.frame, OWASP_MCP_TOP_10);
    tally[result.action] += 1;
    if (ACTION_RANK[result.action] > ACTION_RANK[worst]) worst = result.action;

    if (json) {
      // Raw (unsanitized) excerpts: `--json` is a machine surface and a harness
      // needs byte-fidelity on what matched. JSON.stringify escapes every C0
      // control char, so ESC-based terminal sequences cannot survive this path
      // anyway; the human path below sanitizes in full.
      opts.write(`${JSON.stringify({ action: result.action, findings: result.findings.map(findingToJson) })}\n`);
      return;
    }

    humanLines.push(`frame ${i + 1} — ${result.action}`);
    for (const f of result.findings) {
      humanLines.push(`    ${f.signature_id} · ${f.severity} · ${f.target}${f.decoded === true ? " · decoded" : ""}`);
      // Excerpts are attacker-controlled. Sanitize before they reach a
      // terminal, or `guard inspect` becomes the ANSI/OSC injection vector the
      // guard itself detects.
      humanLines.push(`      excerpt: ${sanitizeForTerminal(f.matched_text_excerpt)}`);
      humanLines.push(`      fix: ${sanitizeForTerminal(f.remediation)}`);
    }
  });

  if (!json) {
    if (parsed.length === 0) {
      opts.write("no frames on input\n");
    } else {
      opts.write(`${humanLines.join("\n")}\n\n`);
      const parts = [plural(parsed.length, "frame")];
      for (const a of ["block", "warn", "pass"] as const) {
        if (tally[a] > 0) parts.push(`${tally[a]} ${a}`);
      }
      if (errors > 0) parts.push(plural(errors, "error"));
      opts.write(`${parts.join(" · ")}\n`);
    }
  }

  return { action: worst, errors, frames: parsed.length };
}
