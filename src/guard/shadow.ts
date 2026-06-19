/**
 * F2 (v1 slice) — cross-server tool-name-collision detection.
 *
 * A pure, deterministic detector: given each server's tool-name inventory, it
 * flags any tool NAME exposed by two or more distinct servers. The threat is
 * tool *shadowing* — in a multi-server stack, a lower-trust server that exposes
 * a tool with the same name as a tool on a trusted server can intercept or
 * impersonate calls meant for the trusted one. `guard run --inner` wraps exactly
 * one server, so a single relay structurally cannot correlate names across
 * servers; the per-server trust gate never reasons about *composition*. `mcpm up`
 * is the one place that sees the whole resolved set at once.
 *
 * HONEST SCOPE (v1):
 * - Inventory comes from `~/.mcpm/pins.json` — the only zero-new-persistence
 *   cross-server tool source `up` can read. Pins are TOFU-populated by the guard
 *   relay on a server's first guarded session, NOT by `up`. So a server that has
 *   never run under guard contributes NO tool names and cannot be checked. v1 is
 *   therefore **best-effort over the already-guarded subset** — a stack-hygiene /
 *   re-audit aid, strongest in steady state, blind at cold start. It does NOT
 *   defend a fresh malicious server on its first `up` (no pin yet). The caller
 *   must report that blind spot loudly (see up.ts coverage line).
 * - Detection is **exact-name** only. Casefold / homoglyph folding is the
 *   FP-laden text-heuristic family the ROADMAP defers, so a deliberate
 *   one-character evasion (`send_email` vs Cyrillic-е `sеnd_email`) is NOT caught
 *   by v1. This catches accidental collisions and literal name-squatting.
 * - It does NOT catch the description-reference confused-deputy (server A's TEXT
 *   names a tool owned only by server B, with no shared name) — that needs the
 *   deferred `detectCrossOriginReferences` heuristic.
 *
 * Deferred to the fast-follow (do not build here): `origin-index.json`
 * persistence (closes the non-guarded coverage gap), the cross-origin
 * text-reference heuristic, privilege-composition scoring, and the relay-time
 * Integration A (a `guard-cross-server-shadow` signature).
 */

import type { PinsFile } from "./pins.js";

export interface ShadowFinding {
  /** The colliding tool name (exact). */
  readonly toolName: string;
  /** The owning servers, sorted, length >= 2. */
  readonly servers: readonly string[];
}

/**
 * Group tool names across servers and flag any owned by >= 2 distinct servers.
 *
 * @param inventory serverName -> that server's tool-name list (may be empty).
 *   A server appearing once with a unique tool set never produces a finding; a
 *   same-server duplicate name cannot collide (the owner Set dedupes by server).
 * @returns one finding per colliding name, sorted by name; each finding's
 *   `servers` array is sorted — fully deterministic output for stable testing.
 */
export function detectNameCollisions(
  inventory: ReadonlyMap<string, readonly string[]>,
): ShadowFinding[] {
  const ownersByTool = new Map<string, Set<string>>();
  for (const [server, tools] of inventory) {
    for (const tool of tools) {
      let owners = ownersByTool.get(tool);
      if (owners === undefined) {
        owners = new Set<string>();
        ownersByTool.set(tool, owners);
      }
      owners.add(server);
    }
  }

  const findings: ShadowFinding[] = [];
  for (const [toolName, owners] of ownersByTool) {
    if (owners.size >= 2) {
      findings.push({ toolName, servers: [...owners].sort() });
    }
  }
  return findings.sort((a, b) => a.toolName.localeCompare(b.toolName));
}

/**
 * Build a `serverName -> [tool names]` inventory from pins. Tool names are the
 * keys of each server's pin record (`pins.servers[name]`), so this reads keys
 * only and never touches the hash values. A server absent from pins (never
 * guarded) contributes an empty list — it is included so the caller can report
 * it as having no baseline rather than silently dropping it.
 */
export function buildInventoryFromPins(
  pins: PinsFile,
  serverNames: readonly string[],
): Map<string, string[]> {
  const inventory = new Map<string, string[]>();
  for (const name of serverNames) {
    inventory.set(name, toolNamesFor(pins, name));
  }
  return inventory;
}

/**
 * Tool names for one server, or [] if it has no pin entry. Uses Object.hasOwn so
 * a server literally named `toString` / `constructor` reads its own (absent)
 * entry rather than an inherited Object.prototype member (pins.ts F13 discipline).
 */
function toolNamesFor(pins: PinsFile, name: string): string[] {
  return Object.hasOwn(pins.servers, name) ? Object.keys(pins.servers[name]!) : [];
}

/**
 * The subset of `serverNames` that has no guard baseline in pins (no pin entry,
 * or an entry with zero tools) — these contribute no names and cannot be checked
 * for shadowing. The caller surfaces this as the coverage blind spot.
 */
export function serversWithoutBaseline(
  pins: PinsFile,
  serverNames: readonly string[],
): string[] {
  return serverNames.filter((name) => toolNamesFor(pins, name).length === 0);
}
