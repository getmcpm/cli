/**
 * Policy file storage for mcpm-guard (~/.mcpm/guard-policy.yaml).
 *
 * v0.5.0 surface (read at every `mcpm guard run --inner` invocation):
 *
 *   signature_overrides:
 *     - id: <signature-id>
 *       action: ignore | warn | block | log_only
 *       expires_at: <ISO8601, optional — auto-removed after this timestamp>
 *
 *   paused_until: <ISO8601, optional — when set, all inspection passes through>
 *
 * v0.5.0 commands that edit this file:
 *   - mcpm guard mute <id> [--for <duration>]
 *   - mcpm guard unmute <id>
 *   - mcpm guard pause [--for <duration>]
 *
 * Pure load/save here; subcommand handlers in cli.ts compose these helpers.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, rename, unlink, lstat } from "node:fs/promises";
import path from "node:path";
import lockfile from "proper-lockfile";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import { getStorePath } from "../store/index.js";

const POLICY_FILENAME = "guard-policy.yaml";
const POLICY_INTEGRITY_FILENAME = "guard-policy.yaml.integrity";

export type OverrideAction = "ignore" | "warn" | "block" | "log_only";

export interface SignatureOverride {
  readonly id: string;
  readonly action: OverrideAction;
  /** ISO 8601 timestamp after which the override expires + is removed. */
  readonly expires_at?: string;
}

export interface GuardPolicyFile {
  readonly signature_overrides?: readonly SignatureOverride[];
  /** When set + in the future, all inspection passes through. */
  readonly paused_until?: string;
}

// #26 (replicated from config/adapters/base.ts, which does not export it): throw
// if `targetPath` is a symlink. lstat does not follow the final component, so
// this detects a symlinked target before a write follows it onto an
// attacker-chosen path. A missing path (ENOENT) is fine — nothing to traverse.
async function assertNotSymlink(targetPath: string): Promise<void> {
  let st: Awaited<ReturnType<typeof lstat>>;
  try {
    st = await lstat(targetPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`Refusing to write policy through a symlink: ${targetPath}`);
  }
}

// Write `data` atomically to `target`: refuse symlinks, clear any stale `.tmp`
// (which may itself be a pre-placed symlink — unlinking removes only the link),
// then create the `.tmp` EXCLUSIVELY (wx) so it is a fresh, unfollowed inode,
// and rename into place. Mirrors base.ts/writeAtomic.
async function writeFileAtomic(target: string, data: string): Promise<void> {
  await assertNotSymlink(target);
  const tmp = `${target}.tmp`;
  try {
    await unlink(tmp);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  await writeFile(tmp, data, { encoding: "utf-8", mode: 0o600, flag: "wx" });
  await rename(tmp, target);
}

async function policyPath(): Promise<string> {
  return path.join(await getStorePath(), POLICY_FILENAME);
}

async function integrityPath(): Promise<string> {
  return path.join(await getStorePath(), POLICY_INTEGRITY_FILENAME);
}

// Issue #19: UNKEYED SHA-256 — integrity (tamper-evidence), not authenticity.
// A same-user/postinstall process can recompute this to match a malicious
// edit, so it is not anti-malware. A keyed MAC needs a secret absent here (#15).
function fileSha(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

export class PolicyIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyIntegrityError";
  }
}

// SECURITY F2/F8: validate the YAML shape strictly. An unchecked cast lets a
// malicious YAML write (e.g., `paused_until: 99999999999999`) bypass all
// inspection because new Date(numeric) is a far-future date. Zod with .catch
// falls back to an empty policy on any structural mismatch — fail toward
// MORE restrictive (full inspection) rather than less.
const SignatureOverrideSchema = z.object({
  id: z.string().min(1).max(256),
  action: z.enum(["ignore", "warn", "block", "log_only"]),
  expires_at: z.string().datetime().optional(),
});
const GuardPolicyFileSchema = z
  .object({
    signature_overrides: z.array(SignatureOverrideSchema).optional(),
    paused_until: z.string().datetime().optional(),
  })
  .catch({});

export async function readPolicy(): Promise<GuardPolicyFile> {
  const p = await policyPath();
  const sidecarP = await integrityPath();
  let raw: string;
  try {
    raw = await readFile(p, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw err;
  }
  if (raw.trim() === "") return {};

  // SECURITY F4 / issue #19: integrity sidecar parity with pins.json. This is
  // an UNKEYED SHA-256 — it provides INTEGRITY (tamper-evidence vs accidental
  // corruption / cross-machine copies / a different OS-user account), NOT
  // AUTHENTICITY vs a same-user/postinstall attacker. A malicious postinstall
  // script (running as this user) that mutates the policy can also recompute
  // and rewrite this sidecar to match, so the mismatch check does NOT stop it.
  // What it does catch: a naive edit that leaves the sidecar stale. A keyed
  // scheme (HMAC/signature) would need a secret the writable store lacks (same
  // constraint as the secret store, issue #15) — deferred to OS-keychain.
  // On mismatch, refuse to use the policy until the user reviews + runs
  // `mcpm guard reset-integrity --policy`.
  let sidecar: string | null = null;
  try {
    sidecar = (await readFile(sidecarP, "utf-8")).trim();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (sidecar !== null && fileSha(raw) !== sidecar) {
    throw new PolicyIntegrityError(
      `guard-policy.yaml integrity check failed. If you intentionally edited the file, ` +
        `run \`mcpm guard reset-integrity --policy\`. Otherwise, review ~/.mcpm/guard-policy.yaml ` +
        `for unauthorized changes (signatures disabled, paused_until set far-future, etc.).`,
    );
  }

  const parsed: unknown = parseYaml(raw) ?? {};
  return GuardPolicyFileSchema.parse(parsed);
}

export async function writePolicy(policy: GuardPolicyFile): Promise<void> {
  const p = await policyPath();
  const sidecarP = await integrityPath();
  await mkdir(path.dirname(p), { recursive: true, mode: 0o700 });

  // SECURITY F6: lock around the write — concurrent `mcpm guard mute` invocations
  // otherwise lose the second update silently.
  try {
    await writeFile(p, "", { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }
  const release = await lockfile.lock(p, {
    retries: { retries: 5, minTimeout: 10, maxTimeout: 200 },
    stale: 5_000,
  });
  try {
    const serialized = stringifyYaml(policy);
    await writeFileAtomic(p, serialized);
    await writeFileAtomic(sidecarP, fileSha(serialized));
  } finally {
    await release();
  }
}

export async function resetPolicyIntegrity(): Promise<void> {
  const p = await policyPath();
  const sidecarP = await integrityPath();
  let raw: string;
  try {
    raw = await readFile(p, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      await unlink(sidecarP).catch(() => undefined);
      return;
    }
    throw err;
  }
  const tmpSidecar = `${sidecarP}.tmp`;
  await writeFile(tmpSidecar, fileSha(raw), { encoding: "utf-8", mode: 0o600 });
  await rename(tmpSidecar, sidecarP);
}

export async function deletePolicy(): Promise<void> {
  const p = await policyPath();
  const sidecarP = await integrityPath();
  await unlink(p).catch(() => undefined);
  await unlink(sidecarP).catch(() => undefined);
}

// ---------------------------------------------------------------------------
// Pure mutation helpers
// ---------------------------------------------------------------------------

/**
 * Drop expired overrides + clear paused_until if it's in the past.
 * Pure: returns a new GuardPolicyFile.
 */
export function expireStale(policy: GuardPolicyFile, now: Date = new Date()): GuardPolicyFile {
  const overrides = (policy.signature_overrides ?? []).filter(
    (o) => o.expires_at === undefined || new Date(o.expires_at) > now,
  );
  const paused =
    policy.paused_until !== undefined && new Date(policy.paused_until) > now
      ? policy.paused_until
      : undefined;
  return {
    ...(overrides.length > 0 ? { signature_overrides: overrides } : {}),
    ...(paused !== undefined ? { paused_until: paused } : {}),
  };
}

export function setOverride(
  policy: GuardPolicyFile,
  id: string,
  action: OverrideAction,
  expiresAt?: string,
): GuardPolicyFile {
  const existing = (policy.signature_overrides ?? []).filter((o) => o.id !== id);
  const updated: SignatureOverride =
    expiresAt !== undefined ? { id, action, expires_at: expiresAt } : { id, action };
  return { ...policy, signature_overrides: [...existing, updated] };
}

export function removeOverride(policy: GuardPolicyFile, id: string): GuardPolicyFile {
  const existing = policy.signature_overrides ?? [];
  const filtered = existing.filter((o) => o.id !== id);
  if (filtered.length === existing.length) return policy;
  const { signature_overrides: _drop, ...rest } = policy;
  return filtered.length > 0 ? { ...rest, signature_overrides: filtered } : rest;
}

export function setPausedUntil(policy: GuardPolicyFile, until: string | null): GuardPolicyFile {
  if (until === null) {
    const { paused_until: _drop, ...rest } = policy;
    return rest;
  }
  return { ...policy, paused_until: until };
}

// ---------------------------------------------------------------------------
// Duration parsing — accepts 5m, 1h, 24h, 30s (deliberately small set)
// ---------------------------------------------------------------------------

const DURATION_RE = /^(\d+)(s|m|h|d)$/;
// SECURITY F3: cap at 10 years. Larger values risk Date overflow in
// isoOffsetFromNow + indistinguishable-from-permanent overrides via the CLI.
const MAX_DURATION_DAYS = 365 * 10;
const MAX_DURATION_MS = MAX_DURATION_DAYS * 86_400_000;

export function parseDuration(input: string): number {
  const match = DURATION_RE.exec(input);
  if (!match) {
    throw new Error(`Invalid duration "${input}". Use e.g. 30s, 5m, 1h, 24h, 7d.`);
  }
  const n = Number.parseInt(match[1] ?? "0", 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`Duration must be greater than zero (got "${input}").`);
  }
  const unit = match[2];
  const ms = unit === "s" ? 1_000 : unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  const result = n * ms;
  if (!Number.isFinite(result) || result > MAX_DURATION_MS) {
    throw new Error(`Duration "${input}" exceeds maximum (${MAX_DURATION_DAYS} days).`);
  }
  return result;
}

export function isoOffsetFromNow(durationMs: number, now: Date = new Date()): string {
  return new Date(now.getTime() + durationMs).toISOString();
}
