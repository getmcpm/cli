/**
 * Derive a default "standard tier" ConfineProfile for a server.
 *
 * Pure function (no I/O): the caller resolves `home`, the `sandboxRoot`
 * (~/.mcpm/sandbox), a `tmpDir`, and `capturedAt`, so this is fully testable on
 * the ubuntu-only CI. The macOS backend renders the returned profile to SBPL.
 *
 * Standard tier (see docs/ROADMAP.md F1 + the design decisions):
 *   - READ: allow-all EXCEPT a fixed secret-dir denylist (the load-bearing win —
 *     the child cannot read ~/.ssh, cloud creds, keychains, browser cookies,
 *     sibling MCP client configs, or mcpm's own store).
 *   - WRITE: deny-all EXCEPT scratch + system temp + launcher caches + /dev. This
 *     denies ALL of $HOME (except caches) in one rule, so every persistence
 *     vector under $HOME — ~/.zshrc, ~/Library/LaunchAgents, ~/bin PATH-shadowing,
 *     git hooks — is blocked without enumerating them (why a write ALLOWLIST, not
 *     a denylist). A server needing broader write is widened via --allow-write or
 *     simply not confined.
 *   - NET: launcher commands (npx/uvx/pip/…) that fetch at launch get "all";
 *     everything else defaults to "none" (egress-deny). Overridable.
 */

import { createHash } from "node:crypto";
import path from "node:path";
import type { ConfineNet, ConfineProfile } from "./profile.js";

/**
 * $HOME-relative secret locations the confined child may not READ. Resolved to
 * absolute paths against the caller-supplied home. A path that does not exist on
 * a given machine is harmless (Seatbelt denies a subpath that isn't there).
 */
export const SECRET_DIR_SEGMENTS: readonly string[] = [
  // SSH / cloud / package-registry / signing credentials.
  ".ssh",
  ".aws",
  ".gnupg",
  ".config/gh",
  ".config/gcloud",
  ".npmrc",
  ".docker",
  ".kube",
  ".netrc",
  ".git-credentials",
  ".cargo/credentials",
  ".cargo/credentials.toml",
  ".pypirc",
  // OS keychains + browser cookie stores (highest-value credential theft).
  "Library/Keychains",
  "Library/Application Support/Google/Chrome",
  "Library/Application Support/Firefox",
  "Library/Cookies",
  // mcpm's own store (secrets.enc.json, pins, policy, the confine store itself).
  ".mcpm",
  // Sibling MCP client configs (each can hold another server's plaintext secrets).
  "Library/Application Support/Claude",
  "Library/Application Support/Cursor",
  "Library/Application Support/Code/User",
  "Library/Application Support/Windsurf",
  ".cursor",
  ".vscode",
  ".codeium",
];

/**
 * $HOME-relative dirs the child MAY write (so node/npx/uvx still run: their
 * caches live here). Everything else under $HOME is write-denied.
 */
const WRITE_ALLOW_HOME_SEGMENTS: readonly string[] = [".npm", ".cache", "Library/Caches"];

/** Absolute temp / device write roots the child may write. */
const WRITE_ALLOW_STATIC: readonly string[] = [
  "/tmp",
  "/private/tmp",
  "/var/tmp",
  "/var/folders",
  "/private/var/folders",
  "/dev",
];

/**
 * Commands that DOWNLOAD-and-run at launch (so the sandboxed tree needs egress
 * to start). Everything else defaults to egress-deny.
 */
const LAUNCHER_COMMANDS: ReadonlySet<string> = new Set([
  "npx",
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "bunx",
  "uv",
  "uvx",
  "pip",
  "pip3",
  "pipx",
  "pipenv",
  "poetry",
  "docker",
]);

/** basename without extension, lowercased — matches `npx`, `/usr/bin/npx`, `npx.cmd`. */
function commandBasename(command: string): string {
  const base = path.basename(command).toLowerCase();
  const dot = base.indexOf(".");
  return dot === -1 ? base : base.slice(0, dot);
}

/** Egress posture for a launcher command (fetches at launch → "all"; else "none"). */
export function classifyNet(command: string): ConfineNet {
  return LAUNCHER_COMMANDS.has(commandBasename(command)) ? "all" : "none";
}

/**
 * Turn a server name into a traversal-safe, collision-free path segment for its
 * scratch dir. Any char outside [A-Za-z0-9._@-] becomes "_", leading dots are
 * neutralized (no "." / ".." segment), and a short content hash suffix keeps
 * distinct names distinct even after sanitization (e.g. "a/b" vs "a_b").
 */
export function safeServerSegment(serverName: string): string {
  if (serverName.length === 0) throw new Error("confine: empty server name");
  const cleaned = serverName
    .replace(/[^A-Za-z0-9._@-]/g, "_")
    .replace(/\.{2,}/g, "_") // collapse interior ".." runs (cosmetic; no traversal reaches the OS)
    .replace(/^\.+/, "_");
  const suffix = createHash("sha256").update(serverName).digest("hex").slice(0, 8);
  return `${cleaned}-${suffix}`;
}

export interface DeriveInput {
  readonly serverName: string;
  readonly command: string;
  readonly args?: readonly string[];
  /** Absolute home dir (os.homedir()). */
  readonly home: string;
  /** Absolute ~/.mcpm/sandbox root (getStorePath()/sandbox). */
  readonly sandboxRoot: string;
  /** Absolute OS temp dir (os.tmpdir()) — included in the write allowlist. */
  readonly tmpDir: string;
  /** ISO 8601 timestamp. */
  readonly capturedAt: string;
  /** Override the launcher-classified net posture. */
  readonly net?: ConfineNet;
  /** Force fail-closed-when-unconfinable for this server. */
  readonly requireConfine?: boolean;
}

/** Build the standard-tier profile. Arrays are sorted so the content hash is stable. */
export function deriveDefaultProfile(input: DeriveInput): ConfineProfile {
  if (input.command.length === 0) throw new Error("confine: empty command");
  const scratchDir = path.join(input.sandboxRoot, safeServerSegment(input.serverName));

  const readDeny = SECRET_DIR_SEGMENTS.map((seg) => path.join(input.home, seg));

  const writeAllow = [
    scratchDir,
    ...WRITE_ALLOW_STATIC,
    input.tmpDir,
    ...WRITE_ALLOW_HOME_SEGMENTS.map((seg) => path.join(input.home, seg)),
  ];

  return {
    tier: "standard",
    require_confine: input.requireConfine === true,
    read_deny: dedupeSorted(readDeny),
    write_allow: dedupeSorted(writeAllow),
    net: input.net ?? classifyNet(input.command),
    scratch_dir: scratchDir,
    captured_at: input.capturedAt,
  };
}

function dedupeSorted(paths: readonly string[]): string[] {
  return [...new Set(paths)].sort();
}
