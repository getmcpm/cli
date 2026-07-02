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
 *     args:    ["guard", "run", "--inner", "--server-name", <name>,
 *               "--declared-env", <csv of orig.env KEY names>,
 *               "--orig-hash", <sha256 of original entry>, "--",
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
 *
 * The marker also carries two authenticated/derived fields:
 *   - `--declared-env` (issue #20): the KEY names of the original entry's
 *     declared `env`. run-inner uses these to forward ONLY a safe baseline
 *     (buildSafeEnv) + the server's own declared vars to the wrapped child,
 *     instead of the relay's entire process.env (which also holds the user's
 *     ambient shell secrets). Without the key list, run-inner cannot tell a
 *     declared var from an ambient one.
 *   - `--orig-hash` (issue #29): a SHA-256 over the canonical original entry
 *     (command + args + sorted declared env keys). `unwrapEntry` recomputes
 *     it from the reconstructed entry and REFUSES to unwrap on mismatch, so a
 *     tampered wrapped entry cannot steer `guard disable` into writing an
 *     attacker command into the IDE config.
 */

import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import type { McpServerEntry } from "../config/adapters/index.js";

export const WRAP_MARKER_ARGS = ["guard", "run", "--inner"] as const;
export const WRAP_ARG_SEPARATOR = "--";
export const WRAP_SERVER_NAME_FLAG = "--server-name";
export const WRAP_DECLARED_ENV_FLAG = "--declared-env";
export const WRAP_ORIG_HASH_FLAG = "--orig-hash";
// F1 confine marker tokens. `--confine-profile-hash <hex>` binds the entry to a
// stored ConfineProfile (spawn-time content-hash verify). `--confine-required` is
// a BARE flag replicating require_confine into the IDE config so a required server
// still fails closed even if ~/.mcpm/guard-confine.yaml is wiped. Both sit BEFORE
// `--` and are excluded from hashOriginalEntry, so `--orig-hash` is unaffected.
export const WRAP_CONFINE_HASH_FLAG = "--confine-profile-hash";
export const WRAP_CONFINE_REQUIRED_FLAG = "--confine-required";

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
 * Sorted, de-duplicated declared env KEY names from an original entry.
 * Sorting makes the marker (and the integrity hash) deterministic regardless
 * of object key order, so a round-trip is stable.
 */
function declaredEnvKeys(env: McpServerEntry["env"]): string[] {
  if (env === undefined) return [];
  return [...new Set(Object.keys(env))].sort();
}

/**
 * Issue #29: canonical SHA-256 over the original entry's command, args, and
 * declared env KEY names. Only fields reconstructable from the wrap marker are
 * hashed (env VALUES live in the wrapped entry's `env`, not the marker, so they
 * are out of scope here). Newline-delimited length-prefixed encoding avoids any
 * ambiguity between, e.g., command "a b" + arg "c" vs command "a" + arg "b c".
 */
export function hashOriginalEntry(
  command: string,
  args: readonly string[],
  envKeys: readonly string[],
): string {
  const parts = [
    `cmd:${command}`,
    `args:${args.length}`,
    ...args.map((a, i) => `arg${i}:${a}`),
    `env:${envKeys.length}`,
    ...[...envKeys].sort().map((k) => `envkey:${k}`),
  ];
  return createHash("sha256").update(parts.join("\n")).digest("hex");
}

/**
 * Build the args array for the wrapped command. The form sandwiches the
 * relay invocation between the resolved mcpm binary and the original
 * command, with `--` separating relay args from the wrapped server's
 * original argv. The `--declared-env` (issue #20) and `--orig-hash`
 * (issue #29) flags are placed BEFORE `--` so Commander parses them as
 * options rather than treating them as part of the wrapped argv.
 */
function buildWrappedArgs(
  serverName: string,
  origCommand: string,
  origArgs: readonly string[],
  envKeys: readonly string[],
  options: { scriptPath?: string; confine?: ConfineMarker } = {},
): string[] {
  const out: string[] = [];
  if (options.scriptPath) out.push(options.scriptPath);
  out.push(...WRAP_MARKER_ARGS, WRAP_SERVER_NAME_FLAG, serverName);
  if (envKeys.length > 0) {
    out.push(WRAP_DECLARED_ENV_FLAG, envKeys.join(","));
  }
  out.push(WRAP_ORIG_HASH_FLAG, hashOriginalEntry(origCommand, origArgs, envKeys));
  // F1: confine tokens go AFTER --orig-hash and BEFORE `--`. They are NOT part of
  // hashOriginalEntry's inputs, and origStartIdx still points past `--`, so the
  // orig-hash check + unwrap reconstruction are unaffected.
  if (options.confine) {
    // Refuse to embed a malformed hash: parseMarker rejects a non-64-hex value at
    // read time (→ malformed marker), so writing one would silently degrade the
    // server on the next spawn. Fail loudly at enable time instead.
    if (!/^[0-9a-f]{64}$/.test(options.confine.profileHash)) {
      throw new Error(
        `wrapEntry: confine profileHash must be 64 lowercase hex chars, got ` +
          `${JSON.stringify(options.confine.profileHash)}`,
      );
    }
    out.push(WRAP_CONFINE_HASH_FLAG, options.confine.profileHash);
    if (options.confine.required) out.push(WRAP_CONFINE_REQUIRED_FLAG);
  }
  out.push(WRAP_ARG_SEPARATOR, origCommand, ...origArgs);
  return out;
}

export interface WrapContext {
  readonly mcpmBinary: string;
  readonly scriptPath?: string;
}

/**
 * F1: per-server confine info embedded into the wrap marker. Passed to wrapEntry
 * (not folded into the shared WrapContext, which carries no per-server data).
 */
export interface ConfineMarker {
  /** SHA-256 content hash of the stored ConfineProfile (hashConfineProfile). */
  readonly profileHash: string;
  /** Whether to emit the bare --confine-required flag (require_confine). */
  readonly required: boolean;
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
  confine?: ConfineMarker,
): McpServerEntry {
  if (!entry.command) {
    throw new Error(
      `Server "${serverName}" has no command field; cannot wrap. Only stdio-transport servers are wrappable in v0.5.0 (HTTP-transport via 'url' is deferred to V2).`,
    );
  }
  const args = buildWrappedArgs(
    serverName,
    entry.command,
    entry.args ?? [],
    declaredEnvKeys(entry.env),
    { scriptPath: ctx.scriptPath, confine },
  );
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
 * Parsed view of the marker section between the WRAP_MARKER_ARGS sequence and
 * the `--` separator: `--server-name <name> [--declared-env <csv>]
 * [--orig-hash <hex>]`. Returns null when the section is structurally invalid.
 */
interface ParsedMarker {
  readonly serverName: string;
  readonly declaredEnvKeys: string[];
  readonly origHash: string | null;
  /** F1: the --confine-profile-hash value (validated 64-hex), or null. */
  readonly confineProfileHash: string | null;
  /** F1: whether the bare --confine-required flag was present. */
  readonly confineRequired: boolean;
  /** Index (into entry.args) of the element immediately after `--`. */
  readonly origStartIdx: number;
}

function parseMarker(args: readonly string[]): ParsedMarker | null {
  const markerIdx = findMarkerIndex(args);
  if (markerIdx === -1) return null;
  let i = markerIdx + WRAP_MARKER_ARGS.length;

  // Required: --server-name <name>
  if (args[i] !== WRAP_SERVER_NAME_FLAG) return null;
  const serverName = args[i + 1];
  if (serverName === undefined) return null;
  i += 2;

  let declaredEnvKeys: string[] = [];
  let origHash: string | null = null;
  let confineProfileHash: string | null = null;
  let confineRequired = false;

  // Optional named flags, in any order, until the `--` separator.
  while (i < args.length && args[i] !== WRAP_ARG_SEPARATOR) {
    const flag = args[i];
    const value = args[i + 1];
    if (flag === WRAP_DECLARED_ENV_FLAG && value !== undefined) {
      declaredEnvKeys = value.length > 0 ? value.split(",") : [];
      i += 2;
    } else if (flag === WRAP_ORIG_HASH_FLAG && value !== undefined) {
      origHash = value;
      i += 2;
    } else if (flag === WRAP_CONFINE_HASH_FLAG && value !== undefined) {
      // Validate the shape here so a crafted `--confine-profile-hash --` can't
      // pass `--` as the value and shift the real separator (a marker that would
      // corrupt origStartIdx is treated as malformed).
      if (!/^[0-9a-f]{64}$/.test(value)) return null;
      confineProfileHash = value;
      i += 2;
    } else if (flag === WRAP_CONFINE_REQUIRED_FLAG) {
      // Bare boolean flag — NO value; advance by ONE (not two).
      confineRequired = true;
      i += 1;
    } else {
      // Unknown token before the separator — marker is malformed.
      return null;
    }
  }

  if (args[i] !== WRAP_ARG_SEPARATOR) return null; // no separator found
  return {
    serverName,
    declaredEnvKeys,
    origHash,
    confineProfileHash,
    confineRequired,
    origStartIdx: i + 1,
  };
}

/**
 * Reverse a wrap by parsing the marker and pulling out the original command +
 * args. Returns null if the entry doesn't look wrapped, the marker is
 * malformed, or (issue #29) the embedded `--orig-hash` does not match a hash
 * recomputed from the reconstructed entry — callers should fall back to a
 * `.bak` restore or refuse to unwrap (Eng review F6.5).
 */
export function unwrapEntry(entry: McpServerEntry): McpServerEntry | null {
  if (!entry.args) return null;
  const marker = parseMarker(entry.args);
  if (marker === null) return null;

  const origCommand = entry.args[marker.origStartIdx];
  if (origCommand === undefined) return null;
  const origArgs = entry.args.slice(marker.origStartIdx + 1);

  // Issue #29: verify the integrity hash before trusting reconstructed args.
  // A tampered marker (or a manual edit) that rewrites the wrapped command or
  // the declared-env list will not match the embedded hash, so we refuse to
  // write an attacker-influenced command back into the IDE config.
  //
  // Fail closed when the hash is absent. An attacker can strip the
  // `--orig-hash <hex>` pair from a wrapped entry to skip verification entirely
  // (a downgrade/strip bypass); treating a missing hash as "legacy, trust it"
  // would re-open exactly the hole the hash closes. Every entry this mcpm wraps
  // carries the flag, so refusing here only rejects tampered (or genuinely
  // pre-hash legacy) markers — callers fall back to a `.bak` restore.
  if (marker.origHash === null) return null;
  const recomputed = hashOriginalEntry(origCommand, origArgs, marker.declaredEnvKeys);
  if (recomputed !== marker.origHash) return null;

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
  const marker = parseMarker(entry.args);
  return marker?.serverName ?? null;
}
