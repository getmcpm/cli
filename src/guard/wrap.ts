/**
 * Wrap-transformation helpers for `mcpm guard enable` (v0.5.0).
 *
 * Converts a plain MCP server config entry into a guard-wrapped entry
 * that invokes the relay as the actual subprocess, and detects / reverses
 * the transformation for `disable` + `status`.
 *
 * Form (verified-once on BaseAdapter — all four adapters use the same shape):
 *
 *   { command, args, env } → {
 *     command: <absolute path to current mcpm binary>,
 *     args:    ["guard", "run", "--inner", "--server-name", <name>, "--",
 *               <orig.command>, ...<orig.args>],
 *     env:     <orig.env>   // passthrough, including OAuth tokens the user
 *                            // explicitly placed in their MCP client config
 *   }
 *
 * The absolute mcpm path (security review F1.4) is captured at wrap time
 * so PATH disruptions, nvm switches, or `npm uninstall -g` don't take every
 * wrapped server in every IDE dark simultaneously. The wrap marker
 * (`guard run --inner`) lets `disable` reconstruct the original entry
 * without depending on `.bak` files (Eng review F6.5).
 */

import { isAbsolute } from "node:path";
import type { McpServerEntry } from "../config/adapters/index.js";

export const WRAP_MARKER_ARGS = ["guard", "run", "--inner"] as const;
export const WRAP_ARG_SEPARATOR = "--";
export const WRAP_SERVER_NAME_FLAG = "--server-name";

/**
 * Resolve the mcpm binary path used at wrap time. Falls back to "mcpm"
 * (resolved via PATH at runtime) if the absolute path cannot be determined.
 *
 * SECURITY F4: enforce absolute path so a relative argv[1] (e.g., the user
 * was social-engineered into `node ../attacker/dist/index.js guard enable`)
 * doesn't embed a relative attacker path into wrapped configs that resolve
 * differently at IDE-spawn time.
 */
export function resolveMcpmBinaryPath(argv: readonly string[] = process.argv): string {
  const script = argv[1];
  if (script && script.length > 0 && isAbsolute(script)) {
    if (script.endsWith("/dist/index.js") || script.endsWith("\\dist\\index.js")) {
      return argv[0] ?? "node";
    }
  }
  return "mcpm";
}

/**
 * Build the args array for the wrapped command. The form sandwiches the
 * relay invocation between the resolved mcpm binary and the original
 * command, with `--` separating relay args from the wrapped server's
 * original argv.
 */
function buildWrappedArgs(
  serverName: string,
  origCommand: string,
  origArgs: readonly string[],
  options: { scriptPath?: string } = {},
): string[] {
  const out: string[] = [];
  if (options.scriptPath) out.push(options.scriptPath);
  out.push(
    ...WRAP_MARKER_ARGS,
    WRAP_SERVER_NAME_FLAG,
    serverName,
    WRAP_ARG_SEPARATOR,
    origCommand,
    ...origArgs,
  );
  return out;
}

export interface WrapContext {
  readonly mcpmBinary: string;
  readonly scriptPath?: string;
}

export function defaultWrapContext(argv: readonly string[] = process.argv): WrapContext {
  const binary = resolveMcpmBinaryPath(argv);
  const script = argv[1];
  // When binary === argv[0] (node), we must also prepend the script path.
  // Only embed scriptPath when it's absolute (SECURITY F4 — same rationale).
  if (binary === argv[0] && script && isAbsolute(script)) {
    return { mcpmBinary: binary, scriptPath: script };
  }
  return { mcpmBinary: binary };
}

/**
 * Wrap an entry. Pure function — never mutates the input.
 */
export function wrapEntry(
  serverName: string,
  entry: McpServerEntry,
  ctx: WrapContext,
): McpServerEntry {
  if (!entry.command) {
    throw new Error(
      `Server "${serverName}" has no command field; cannot wrap. Only stdio-transport servers are wrappable in v0.5.0 (HTTP-transport via 'url' is deferred to V2).`,
    );
  }
  const args = buildWrappedArgs(serverName, entry.command, entry.args ?? [], {
    scriptPath: ctx.scriptPath,
  });
  return {
    command: ctx.mcpmBinary,
    args,
    ...(entry.env !== undefined ? { env: { ...entry.env } } : {}),
    ...(entry.disabled !== undefined ? { disabled: entry.disabled } : {}),
  };
}

/**
 * Returns true if the entry args look like a guard wrap. Detection is
 * based on the WRAP_MARKER_ARGS sequence — not the command field — so
 * entries wrapped via the absolute-path binary still detect correctly.
 */
export function isWrapped(entry: McpServerEntry): boolean {
  if (!entry.args) return false;
  return findMarkerIndex(entry.args) !== -1;
}

function findMarkerIndex(args: readonly string[]): number {
  for (let i = 0; i <= args.length - WRAP_MARKER_ARGS.length; i++) {
    let match = true;
    for (let j = 0; j < WRAP_MARKER_ARGS.length; j++) {
      if (args[i + j] !== WRAP_MARKER_ARGS[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

/**
 * Reverse a wrap by scanning args for the marker + `--` separator and
 * pulling out the original command + args. Returns null if the entry
 * doesn't look wrapped — callers should fall back to a `.bak` restore
 * or refuse to unwrap (Eng review F6.5).
 */
export function unwrapEntry(entry: McpServerEntry): McpServerEntry | null {
  if (!entry.args) return null;
  const markerIdx = findMarkerIndex(entry.args);
  if (markerIdx === -1) return null;

  // After the marker: --server-name <name> -- <origCommand> [...origArgs]
  const afterMarker = entry.args.slice(markerIdx + WRAP_MARKER_ARGS.length);
  // Validate: --server-name <name> -- ...
  if (
    afterMarker.length < 4 ||
    afterMarker[0] !== WRAP_SERVER_NAME_FLAG ||
    afterMarker[2] !== WRAP_ARG_SEPARATOR
  ) {
    return null;
  }
  const origCommand = afterMarker[3];
  if (origCommand === undefined) return null;
  const origArgs = afterMarker.slice(4);

  const unwrapped: McpServerEntry = { command: origCommand };
  if (origArgs.length > 0) unwrapped.args = [...origArgs];
  if (entry.env !== undefined) unwrapped.env = { ...entry.env };
  if (entry.disabled !== undefined) unwrapped.disabled = entry.disabled;
  return unwrapped;
}

/**
 * Extract the wrapped server's display name from a guard-wrapped entry.
 * Returns null if the entry isn't wrapped or the name slot is malformed.
 */
export function getWrappedServerName(entry: McpServerEntry): string | null {
  if (!entry.args) return null;
  const markerIdx = findMarkerIndex(entry.args);
  if (markerIdx === -1) return null;
  const flagIdx = markerIdx + WRAP_MARKER_ARGS.length;
  if (entry.args[flagIdx] !== WRAP_SERVER_NAME_FLAG) return null;
  return entry.args[flagIdx + 1] ?? null;
}
