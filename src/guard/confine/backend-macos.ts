/**
 * macOS Seatbelt backend for `mcpm guard --confine`.
 *
 * Renders a ConfineProfile to SBPL and returns the `sandbox-exec` argv that
 * wraps the child. Verified live on macOS 26 (Tahoe): SBPL is last-match-wins,
 * so `(allow default)` followed by targeted `(deny …)` rules denies; `-p <inline
 * profile>` needs no `--` separator; and `sandbox-exec` is exec-style (it
 * replaces itself with the target after installing the profile), so the child's
 * PID and inherited stdio fds — the relay's ['pipe','pipe','inherit'] contract —
 * survive untouched, and the relay's signal forwarding still reaches the server.
 *
 * `-p` (inline) is used instead of `-f <file>` so there is no TOCTOU-able on-disk
 * .sb artifact between render and exec.
 *
 * CI is ubuntu-only, so this file's real enforcement is exercised by local darwin
 * dogfooding; the argv it produces is asserted by mocked tests on every platform.
 */

import { existsSync } from "node:fs";
import type { ConfineProfile } from "./profile.js";

export const SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec";

/**
 * True if `s` contains a C0 control character or DEL. A filesystem path should
 * never contain these; a hostile server name could try to inject one via the
 * scratch path, so we refuse to smuggle it into the SBPL profile. Implemented
 * with charCodeAt (not a regex literal) to keep control characters out of source.
 */
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Is the macOS backend usable right now? darwin + sandbox-exec present, unless
 * force-disabled (mirrors os-keychain's MCPM_DISABLE_OS_KEYCHAIN escape hatch —
 * used by tests and by users who want to opt out without unenrolling servers).
 */
// Memoize the binary-presence check: /usr/bin/sandbox-exec is a static system
// binary that does not appear/disappear during a process, and this runs on the
// hot relay-startup path (CLAUDE.md Reviewer Concern #8). The env + platform
// checks stay live so tests can force-disable per-case.
let _sandboxExecPresent: boolean | null = null;

export function isMacosBackendAvailable(): boolean {
  if (process.env.MCPM_DISABLE_CONFINE === "1") return false;
  if (process.platform !== "darwin") return false;
  if (_sandboxExecPresent === null) _sandboxExecPresent = existsSync(SANDBOX_EXEC_PATH);
  return _sandboxExecPresent;
}

/**
 * Escape a path for an SBPL `"..."` string literal. Backslash and quote are
 * escaped; a control character is refused rather than smuggled into the profile.
 * Spaces need no escaping — the literal is a profile token, not a shell argument
 * (a path like ".../Application Support/Claude" is fine).
 *
 * The path fields in a ConfineProfile are OS-derived (os.homedir()/os.tmpdir()/
 * the store path) or a scratch segment already reduced to ASCII [A-Za-z0-9._@-]
 * by safeServerSegment — not raw attacker input. Only `"`/`\`/control chars can
 * break out of an SBPL string literal, and all three are handled here.
 */
export function sanitizePathForSBPL(p: string): string {
  if (hasControlChar(p)) {
    throw new Error(
      `confine: refusing to render a path containing control characters into SBPL: ${JSON.stringify(p)}`,
    );
  }
  return p.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function renderSubpaths(paths: readonly string[]): string {
  return paths.map((p) => ` (subpath "${sanitizePathForSBPL(p)}")`).join("");
}

/**
 * Render a ConfineProfile to a Seatbelt SBPL profile string. Rule order matters
 * (last match wins): allow-all, then deny-all-writes + re-allow the write
 * allowlist, then deny secret reads, then (optionally) deny egress.
 */
export function renderSbpl(profile: ConfineProfile): string {
  const lines: string[] = ["(version 1)", "(allow default)"];

  // WRITE: deny everything, then re-allow only the allowlist. This denies all of
  // $HOME (except the cache/scratch entries in write_allow) in a single rule.
  lines.push("(deny file-write*)");
  if (profile.write_allow.length > 0) {
    lines.push(`(allow file-write*${renderSubpaths(profile.write_allow)})`);
  }

  // READ: allow-all-except the secret denylist.
  if (profile.read_deny.length > 0) {
    lines.push(`(deny file-read*${renderSubpaths(profile.read_deny)})`);
  }
  // The scratch dir lives under ~/.mcpm, which the read denylist covers — re-allow
  // reads within scratch AFTER the deny (last-match-wins) so the child can read
  // back what it writes there; otherwise scratch would be write-only.
  lines.push(`(allow file-read* (subpath "${sanitizePathForSBPL(profile.scratch_dir)}"))`);

  // NET: all-or-none for v1 (host-granular filtering is unreliable in Seatbelt).
  if (profile.net === "none") {
    lines.push("(deny network*)");
  }

  return `${lines.join("\n")}\n`;
}

/**
 * Build the `sandbox-exec` invocation that wraps `command`+`args` under
 * `profile`. Returns the rewritten spawn target the relay will launch.
 */
export function buildMacosWrap(
  profile: ConfineProfile,
  command: string,
  args: readonly string[],
): { command: string; args: string[] } {
  return {
    command: SANDBOX_EXEC_PATH,
    args: ["-p", renderSbpl(profile), command, ...args],
  };
}
