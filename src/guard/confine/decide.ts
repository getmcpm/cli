/**
 * The spawn-time confine decision table (pure — fully unit-testable).
 *
 * Inputs at spawn: the profile LOADED FROM THE STORE by server name (the source
 * of truth for "is this server enrolled"), the marker's --confine-profile-hash
 * and --confine-required (from the IDE config, a different file than the store),
 * and whether an OS backend is available on this platform.
 *
 * Two files must both be compromised to defeat this: the store (to change the
 * profile) AND the IDE config (to change the marker). An attacker who can write
 * only ~/.mcpm is caught by the marker; one who can write only the IDE config is
 * caught by the store + orig-hash. One who can write both could just replace the
 * command outright, so confinement was never the relevant control there.
 */

import { hashConfineProfile, type ConfineProfile } from "./profile.js";

export type ConfineAction = "confine" | "unconfined" | "fail-closed";

export interface ConfineDecisionInput {
  /** Profile loaded from the store by server name; null if absent OR unreadable. */
  readonly profile: ConfineProfile | null;
  /** --confine-profile-hash from the marker, or null if the flag is absent. */
  readonly markerHash: string | null;
  /** --confine-required from the marker (survives a wiped store). */
  readonly markerRequired: boolean;
  /** Is an OS sandbox backend usable on this platform right now? */
  readonly backendAvailable: boolean;
}

export interface ConfineDecision {
  readonly action: ConfineAction;
  readonly reason: string;
  /** Event id for guard-events.jsonl; undefined = don't log (the row-6 no-op). */
  readonly event?: string;
}

export function decideConfine(input: ConfineDecisionInput): ConfineDecision {
  const { profile, markerHash, markerRequired, backendAvailable } = input;
  const mustConfine = markerRequired || profile?.require_confine === true;

  if (profile !== null) {
    // Enrolled: the store has a profile for this server.
    if (markerHash === null) {
      // Rows 4 / 4b: the marker's hash flag was stripped but the store says
      // enrolled. A required server refuses; otherwise warn + run unconfined
      // (hybrid posture — a stripped flag is observationally "confinement isn't
      // happening", the same class as a missing backend for a non-required server).
      return mustConfine
        ? { action: "fail-closed", reason: "confine marker stripped on a required server", event: "confine-marker-stripped" }
        : { action: "unconfined", reason: "confine marker stripped", event: "confine-marker-stripped" };
    }
    if (hashConfineProfile(profile) !== markerHash) {
      // Row 3: the stored profile no longer matches the marker hash — tamper on
      // either side. Always fail closed, regardless of posture.
      return { action: "fail-closed", reason: "confine profile hash mismatch (tamper)", event: "confine-hash-mismatch" };
    }
    if (!backendAvailable) {
      // Row 2: enrolled + verified, but no backend. Hybrid posture.
      return mustConfine
        ? { action: "fail-closed", reason: "no confine backend on a required server", event: "confine-backend-missing" }
        : { action: "unconfined", reason: "no confine backend on this platform", event: "confine-backend-missing" };
    }
    // Row 1: enrolled, verified, backend up → confine.
    return { action: "confine", reason: "confined", event: "confine-applied" };
  }

  // profile === null: not enrolled, OR the store was deleted / unreadable.
  if (markerRequired) {
    // Rows 5 / 7: the marker demands confinement but there is no profile to apply
    // (store wiped). --confine-required survives store deletion, so we still refuse.
    return { action: "fail-closed", reason: "confine required but no stored profile (store missing?)", event: "confine-profile-missing" };
  }
  if (markerHash !== null) {
    // Row 5b: dangling marker hash with no stored profile. Warn + run unconfined.
    return { action: "unconfined", reason: "confine marker present but no stored profile", event: "confine-profile-missing" };
  }
  // Row 6: no marker tokens, not enrolled — a normal unconfined server. No-op.
  return { action: "unconfined", reason: "not confined" };
}
