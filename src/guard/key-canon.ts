/**
 * Shared identifier-KEY canonicalization.
 *
 * Folds homoglyph/zero-width evasions via normalizeForMatch, splits camelCase
 * BEFORE folding (so `_systemPrompt_` reduces the same as `_system_prompt_`),
 * lowercases, and collapses hyphen/whitespace/underscore runs to a single `_`.
 *
 * Extracted from exfil-names.ts (F5) so shell-metachar-args.ts (#50) can reuse
 * the identical canonicalization instead of a second copy — both classifiers
 * compare an attacker-controlled property NAME against a canonical form, only
 * the allow/deny table differs.
 */

import { normalizeForMatch } from "./patterns.js";

export function canonicalizeKey(rawKey: string): string {
  // Fold homoglyph/zero-width evasions FIRST, then split camelCase on the
  // FOLDED (still-cased) string. normalizeForMatch does not lowercase —
  // foldConfusables preserves case — so an ASCII input still has real
  // uppercase letters for the split regex to find after folding. Doing it in
  // the OLD order (split, then fold) let a homoglyph standing in for an ASCII
  // uppercase letter hide a real camelCase boundary: `[A-Z]` doesn't match a
  // Cyrillic "Р" (which folds to Latin "P"), so "projectРath" was never split
  // into "project"/"path" and the identifier-suffix classifier missed it.
  // Folding first also incidentally fixes a zero-width separator planted at
  // the exact boundary (e.g. "system​Prompt"), which the old order
  // couldn't split either since the regex needs `[a-z0-9]` immediately before
  // `[A-Z]`. (review: TODOS #50)
  const folded = normalizeForMatch(rawKey);
  const camelSplit = folded.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  return camelSplit
    .toLowerCase()
    .replace(/[\s-]+/g, "_") // hyphens / whitespace → underscore
    .replace(/_{2,}/g, "_"); // collapse runs (a deliberate wrap stays a single `_`)
}

/**
 * Canonical form of a tool NAME, for keying the same-session drift cache and
 * the pin store (TODOS #58 residual, left open by #191's review).
 *
 * Deliberately a WEAKER fold than {@link canonicalizeKey}: normalizeForMatch
 * (NFKC + zero-width/TAG strip + confusable fold) plus a case-fold, and NOTHING
 * else. It must map only VISUALLY IDENTICAL spellings together — the concealed
 * twin an attacker ships to ride the "new tool name = legitimate addition"
 * carve-out — never spellings a human tells apart at a glance.
 *
 * Why not canonicalizeKey: its camelCase split and `[\s-]+`→`_` collapse fold
 * `get-user`, `getUser` and `get_user` into one key. Those are SEP-986-legal,
 * visibly distinct identifiers, and separator style is a live per-server
 * convention (Notion ships `get-user`, Linear `get_user`) — folding them would
 * make a server's second, benign tool look like a mutation of its first and
 * hard-block it, the failure direction this project judges worst. They also buy
 * nothing here: a `format-code` shipped beside `format_code` is visibly a
 * different tool, which is exactly what the new-name carve-out is for.
 *
 * Measured before choosing this rung: over 96 real server snapshots / 944
 * distinct tool names (53 public + hosted servers, 43 corpus snapshots), this
 * fold produces ZERO within-server collisions, and SEP-986 (SDK 1.30.0
 * `TOOL_NAME_REGEX = /^[A-Za-z0-9._-]{1,128}$/`, names case-sensitive) makes
 * that near-structural: 863/863 real names are pure ASCII, so the zero-width
 * strip and confusable fold can only ever alter a name that is ALREADY outside
 * the spec charset. Case-fold is the one spec-legal distinction it merges, and
 * no observed server exposes a case-only pair. The separator/camel rungs scored
 * zero too, but VACUOUSLY — 0 of 96 servers mixes naming styles, so that zero is
 * absence of test input, not evidence of safety. See research/name-canon/.
 */
export function canonicalToolName(rawName: string): string {
  return normalizeForMatch(rawName).toLowerCase();
}
