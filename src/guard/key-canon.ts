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
