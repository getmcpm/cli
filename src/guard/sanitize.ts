/**
 * Shared terminal-output sanitizer for mcpm-guard (v0.5.0 Step 7 F5).
 *
 * Server names, tool names, and error excerpts originate from MCP server
 * configs and JSON-RPC payloads — both attacker-controllable. When echoed
 * to stderr/stdout, they must be stripped of ANSI escapes, OSC sequences,
 * and all C0/C1 control characters so a malicious name like `\x1b]0;evil\x07`
 * (OSC terminal-title injection) can't manipulate the user's terminal.
 *
 * Used by run-inner.ts (stderr event logging) and cli.ts (stdout status
 * output). Both previously had their own copies; the cli.ts variant was
 * incomplete (missed ESC and OSC) — security review Step 7 F5.
 */

const ANSI_AND_C1_CONTROL =
  // ESC followed by single-char dispatch (@-Z, \, -, _) OR CSI [..letter
  // eslint-disable-next-line no-control-regex
  /\x1B(?:[@-Z\\\-_]|\[[0-9;]*[a-zA-Z])/g;
const C0_C1_CONTROL =
  // C0 (0x00-0x1F) + DEL (0x7F) + C1 (0x80-0x9F)
  // eslint-disable-next-line no-control-regex
  /[\x00-\x1F\x7F\x80-\x9F]/g;

const DEFAULT_MAX_LEN = 256;

/**
 * Strip ANSI escape sequences + all C0/C1 control characters from `s`.
 * Optionally truncates to `maxLen` chars (default 256) to prevent excessive
 * terminal output from a long crafted name.
 */
export function sanitizeForTerminal(s: string, maxLen: number = DEFAULT_MAX_LEN): string {
  const stripped = s.replace(ANSI_AND_C1_CONTROL, "").replace(C0_C1_CONTROL, "");
  return stripped.length > maxLen ? `${stripped.slice(0, maxLen)}…` : stripped;
}
