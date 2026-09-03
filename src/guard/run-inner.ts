/**
 * `mcpm guard run --inner` entry point (v0.5.0).
 *
 * Spawned by wrapped client configs after `mcpm guard enable` rewrites them.
 * Wires the production relay to the current process's stdio + the OWASP MCP
 * Top 10 signature set + schema-drift detection against the pin store.
 *
 * IMPORTANT: this is the internal hot path. Keep startup work minimal —
 * security review Reviewer Concern #8 (warm-up latency) calls out cold-start
 * cost for every wrapped-server session. Defer non-essential imports.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { defaultActionForFinding, ACTION_RANK, worstAction } from "./patterns.js";
import {
  inspectFrame,
  inspectStatelessDetectors,
  mergeInspect,
  withReplyToOrigin,
  hasToolsList,
  inspectServerInitiated,
} from "./inspect-frame.js";
import { startRelay, buildSafeEnv, type GuardEvent } from "./relay.js";
import {
  inspectForDrift,
  inspectHandshakeForDrift,
  classifyDrift,
  classifyFieldDrift,
  buildDriftFinding,
  lookupToolPin,
} from "./drift.js";
import { readPins, writePins } from "./pins.js";
import { readPolicy, expireStale, PolicyIntegrityError, type GuardPolicyFile } from "./policy.js";
import { appendEvent } from "./event-log.js";
import { hashOriginalEntry } from "./wrap.js";
import { loadProfile } from "./confine/store.js";
import { isConfineBackendAvailable, wrapForConfinement } from "./confine/apply.js";
import { decideConfine } from "./confine/decide.js";
import type { ConfineProfile } from "./confine/profile.js";
import { canonicalToolName } from "./key-canon.js";
import { sanitizeForTerminal } from "./sanitize.js";
import { resolveEnvPlaceholders } from "../store/keychain.js";
import type { InspectFinding, InspectResult, Severity } from "./types.js";

export interface RunInnerArgs {
  readonly serverName: string;
  readonly command: string;
  readonly args: readonly string[];
  /**
   * Issue #20: KEY names of the wrapped server's DECLARED env (embedded in the
   * wrap marker at `enable` time). Only these keys are forwarded from the
   * relay's process.env to the child, on top of the safe baseline — ambient
   * shell secrets (OPENAI_API_KEY, AWS_*, GITHUB_TOKEN, …) are NOT forwarded.
   */
  readonly declaredEnvKeys: readonly string[];
  /**
   * Issue #29 — the `--orig-hash` carried in the wrap marker (a SHA-256 over the
   * original command + args + declared-env KEY names, computed at `mcpm guard
   * enable` time). Verified at spawn (warn-once on mismatch — see runInner). Absent
   * for pre-#29 legacy wraps, in which case the check is skipped (not failed).
   */
  readonly origHash?: string;
  /**
   * F1: the wrap marker's confine tokens. `confineProfileHash` is the content
   * hash of the enrolled ConfineProfile (`--confine-profile-hash`);
   * `confineRequired` mirrors `--confine-required`. Both drive the spawn confine
   * decision table (see runInner). Absent for non-confined servers.
   */
  readonly confineProfileHash?: string;
  readonly confineRequired?: boolean;
}

const SIGNATURE_LIST_VERSION = "owasp-mcp-top-10@v0.5.0";

/**
 * Apply guard-policy.yaml signature_overrides to an inspection result.
 *
 * Per-finding semantics:
 *   - no override  → finding keeps its native severity → action
 *   - "ignore"     → finding is dropped from the result entirely
 *   - "log_only"   → finding is kept (visible in event log) but counts as "pass" for action
 *   - "warn"       → finding is kept, counts as "warn"
 *   - "block"      → finding is kept, counts as "block"
 *
 * Action is the MAX severity across ALL findings post-override. A log_only
 * override on one finding cannot suppress a block from another unmuted
 * finding — security review Step 7 F1 caught this as the previous code's
 * critical bug.
 *
 * With no override, a finding's default action comes from {@link defaultActionForFinding}
 * — which applies the warn-only carrier clamp (a critical match in retrieved
 * resource/prompt data degrades to `warn`). This keeps the clamp from being
 * silently undone by a second severity→action recompute here. An EXPLICIT user
 * override (warn/block/log_only/ignore) still wins: user intent outranks the
 * default carrier policy, so a user can choose to block even retrieved data.
 */
export function applyPolicy(result: InspectResult, policy: GuardPolicyFile): InspectResult {
  const overrides = policy.signature_overrides ?? [];
  if (overrides.length === 0) return result;
  const byId = new Map(overrides.map((o) => [o.id, o]));

  let highest: InspectResult["action"] = "pass";
  const kept: InspectFinding[] = [];
  for (const f of result.findings) {
    const o = byId.get(f.signature_id);
    let perFindingAction: InspectResult["action"];
    if (o === undefined) {
      perFindingAction = defaultActionForFinding(f);
      kept.push(f);
    } else if (o.action === "ignore") {
      continue; // drop entirely
    } else if (o.action === "log_only") {
      perFindingAction = "pass";
      kept.push(f);
    } else {
      perFindingAction = o.action; // "warn" or "block"
      kept.push(f);
    }
    if (ACTION_RANK[perFindingAction] > ACTION_RANK[highest]) highest = perFindingAction;
  }

  // H7: carry replyToOrigin through, but withReplyToOrigin drops it unless the
  // post-policy action is STILL a block — a policy that downgrades block→warn/pass
  // must not leave a stranded reply-to-origin flag on a non-block result.
  return withReplyToOrigin({ action: highest, findings: kept }, result.replyToOrigin === true);
}


/**
 * Build a synthetic CONFINE-category GuardEvent for guard-events.jsonl (mirrors
 * the H9 spawn-failure precedent: a valid InspectFinding shape, no type change).
 */
function confineGuardEvent(
  event: string,
  reason: string,
  action: InspectResult["action"],
  severity: Severity,
): GuardEvent {
  return {
    ts: new Date().toISOString(),
    direction: "parent->child",
    action,
    findings: [
      {
        signature_id: event,
        category: "CONFINE",
        severity,
        target: "tool_response",
        matched_text_excerpt: reason,
        remediation: "See docs/GUARD.md — `mcpm guard confine`.",
      },
    ],
  };
}

export async function runInner(parsed: RunInnerArgs): Promise<number> {
  const safeName = sanitizeForTerminal(parsed.serverName);

  // Issue #29 — spawn-time wrap-marker integrity check. `--orig-hash` (a SHA-256
  // over the original command + args + declared-env KEY names, set at `mcpm guard
  // enable` time) was, until now, verified ONLY on the disable/unwrap path
  // (wrap.ts `unwrapEntry`) — never at spawn, so a client-config edit that rewrote
  // the wrapped argv launched unchecked. Recompute and compare here.
  //
  // Phase 1 (this release): WARN on mismatch but DO NOT fail closed — promotion to
  // a hard refusal is gated on dogfood evidence of zero benign mismatches. An
  // ABSENT hash is a pre-#29 legacy wrap: skip silently (failing closed there
  // would brick servers wrapped by an older mcpm the moment the user upgrades).
  if (typeof parsed.origHash === "string" && parsed.origHash.length > 0) {
    const recomputed = hashOriginalEntry(parsed.command, parsed.args, parsed.declaredEnvKeys);
    if (recomputed !== parsed.origHash) {
      process.stderr.write(
        `[mcpm-guard] ORIG-HASH-MISMATCH ${safeName}: the wrapped command/args/declared-env ` +
          `no longer match the integrity hash embedded at \`mcpm guard enable\` time — the ` +
          `client config entry may have been edited or tampered with. Starting anyway ` +
          `(advisory); a future mcpm release will refuse to start on mismatch. Review ` +
          `~/.mcpm/guard-events.jsonl, and if you changed the entry on purpose re-run ` +
          `\`mcpm guard enable\` to re-pin it.\n`,
      );
      // Persist to the audit log so the mismatch is reviewable (mirrors the H9
      // spawn-failure synthetic-finding precedent in relay.ts — RELAY category,
      // valid InspectFinding shape, no GuardEvent type change).
      void appendEvent(
        {
          ts: new Date().toISOString(),
          direction: "parent->child",
          action: "warn",
          findings: [
            {
              signature_id: "orig-hash-mismatch",
              category: "RELAY",
              severity: "high",
              target: "tool_response",
              matched_text_excerpt: "wrap-marker integrity: recomputed hash != embedded --orig-hash",
              remediation:
                "Re-run `mcpm guard enable` to re-pin, or restore the original wrapped entry in the client config.",
            },
          ],
        },
        parsed.serverName,
      );
    }
  }

  const logEvent = (event: GuardEvent): void => {
    if (event.action === "block" || event.action === "warn") {
      process.stderr.write(
        `[mcpm-guard] ${event.action.toUpperCase()} ${safeName} ` +
          `${event.findings.map((f) => f.signature_id).join(",")}\n`,
      );
      // Persist to ~/.mcpm/guard-events.jsonl best-effort (Step 10).
      void appendEvent(event, parsed.serverName);
    }
  };

  // Drift detection is async (reads + writes pins.json). The relay's inspect
  // callbacks are sync, so we keep a cached snapshot updated off-thread.
  //
  // FAIL CLOSED on a pins-read error. First-run ENOENT is handled INSIDE
  // readPins (returns an empty pins file, no throw), so the only errors that
  // reach here are the dangerous ones: a PinsIntegrityError (tampered sidecar),
  // EACCES/EMFILE, or a corrupt/invalid pins.json. Swallowing those to an empty
  // snapshot would silently disable cross-session rug-pull detection — exactly
  // when it matters most. Refuse to start the relay instead.
  let pinsSnapshot: PinsFile;
  try {
    pinsSnapshot = await readPins();
  } catch (err) {
    process.stderr.write(
      `[mcpm-guard] PINS-READ-ERROR: ${safeName} could not load ~/.mcpm/pins.json: ` +
        `${(err as Error).message}\n` +
        `Refusing to start the relay — running with rug-pull (schema-drift) protection ` +
        `silently disabled is more dangerous than not starting. Review ` +
        `~/.mcpm/guard-events.jsonl for unauthorized activity. If you intentionally ` +
        `changed pins.json, run \`mcpm guard reset-integrity\`.\n`,
    );
    process.exit(1);
  }

  // Load policy once per session (mute/pause/etc.). Stale overrides expire
  // here; the next session picks up fresh state. Pausing mid-session is not
  // supported in v0.5.0 — restart the wrapped server to pick up changes.
  //
  // The `{}` fallback is the SAFE state (full enforcement), so we keep falling
  // back on any read failure. BUT a PolicyIntegrityError (tampered
  // guard-policy.yaml) would otherwise be invisible — surface it on stderr
  // before falling back so the user knows their policy file was tampered with.
  const policy = expireStale(
    await readPolicy().catch((err: unknown) => {
      if (err instanceof PolicyIntegrityError) {
        process.stderr.write(
          `[mcpm-guard] POLICY-INTEGRITY-ERROR: ${safeName} ${(err as Error).message}\n` +
            `Falling back to full enforcement (ignoring guard-policy.yaml) for this session.\n`,
        );
      } else {
        // Generic non-ENOENT I/O error (EACCES, EMFILE, …). ENOENT is already
        // returned as {} inside readPolicy and never reaches here. The {}
        // fallback is the SAFE state (full enforcement), but swallowing the
        // error silently hides a misconfigured/unreadable policy file — surface
        // it on stderr before falling back. Do NOT exit: enforcement is preserved.
        process.stderr.write(
          `[mcpm-guard] POLICY-READ-ERROR: ${(err as Error).message}\n`,
        );
      }
      return {};
    }),
  );
  const pausedUntilFuture =
    policy.paused_until !== undefined && new Date(policy.paused_until) > new Date();

  // SECURITY F3: per-session drift state — the "first hash seen" cache + the H4
  // single-shot re-validation arm. Closes the double-tools/list bypass (a server
  // sending two tools/list within a session must hash-match or block) while
  // letting an ANNOUNCED list_changed legitimately re-baseline once.
  const sessionState: SessionDriftState = {
    firstHashes: new Map(),
    revalidationArmed: false,
    handshakeSeenHash: null,
    firstFieldHashes: new Map(),
  };

  // FROZEN session-start baseline. The off-thread refresh may keep reassigning
  // pinsSnapshot for its own fallback, but the sync classifier must compare
  // against the immutable session-start pins so a mid-session pin rewrite can't
  // retroactively launder a drift.
  const baselineForDrift = pinsSnapshot;

  // Issue #27: this server has no pin on disk AT ALL as of session start — the
  // "closing the last same-session-unprotected window" case below only applies
  // to it. Combined with `firstToolsListPinAwaited`, this scopes the pin-commit
  // wait to exactly one tools/list frame per session per server; a server that
  // is already pinned is compared against that pin immediately (no wait needed).
  // Known residual gap (not a regression — same scope the backlog item named):
  // a PLACEHOLDER entry (`current_hash: null`, from a failed install-time
  // capture) still counts as "has a pin" here and is never held, and a brand-
  // new tool added to an ALREADY-pinned server is first-session-captured
  // fire-and-forget same as before — neither is covered by the in-memory
  // `firstHashes` cache either, since that only guards a name it has already
  // seen this session.
  const neverPinnedThisServer = !Object.hasOwn(baselineForDrift.servers, parsed.serverName);
  let firstToolsListPinAwaited = false;

  const inspectChild = (msg: JSONRPCMessage): InspectResult | Promise<InspectResult> => {
    if (pausedUntilFuture) return { action: "pass", findings: [] };

    // H4: a server→client list_changed notification ARMS single-shot
    // re-validation. Forward it silently (no stderr noise) — the follow-up
    // list's classification is the logged event. No pattern/drift on the bare
    // notification.
    if (isToolsListChangedNotification(msg)) {
      sessionState.revalidationArmed = true;
      return { action: "pass", findings: [] };
    }

    // H7: a server-INITIATED sampling/elicitation request — scan its
    // server-authored content for prompt injection BEFORE the regular pattern/
    // drift path. A detected injection blocks the request BACK to the server
    // (replyToOrigin), via applyPolicy so user overrides still apply. A benign
    // request returns null here and falls through to forward untouched (we gate
    // the injection content, not the mechanism).
    // Every STATELESS verdict (patterns + F5 exfil-param + H7 server-initiated)
    // comes from the one shared composition, so `mcpm guard inspect` and the
    // fixture release-gate cannot drift from what the relay actually enforces.
    // A server-initiated frame short-circuits inside inspectFrame; it carries
    // `method` not `result`, so neither drift branch below applies to it.
    const statelessResult = inspectFrame(msg);
    let driftResult: InspectResult = { action: "pass", findings: [] };
    // Issue #27: set only for a tools/list frame — the off-thread refresh +
    // first-session pin capture, factored out so the branch below can either
    // fire it (existing behavior) or await it once before returning.
    let commitPin: (() => Promise<void>) | null = null;
    // Issue #27 (review finding): an empty/nameless tools/list (`{tools:[]}`,
    // or every entry missing a string `name`) makes inspectForDrift a no-op —
    // nothing gets pinned. Only a frame that can actually PRODUCE a pin is
    // allowed to consume the one-shot hold below; otherwise a malformed or
    // slow-starting server's first frame would burn it and the REAL list that
    // follows would go straight back to fire-and-forget.
    let canProducePin = false;

    if (hasToolsList(msg)) {
      driftResult = inspectForDriftSync(msg, parsed.serverName, baselineForDrift, sessionState);
      canProducePin = hasNameableTool(msg);

      // Off-thread: refresh snapshot + apply first-session pin capture.
      commitPin = async () => {
        await inspectForDrift(msg, parsed.serverName, {
          read: () => readPins().catch(() => pinsSnapshot),
          write: writePins,
          signatureListVersion: SIGNATURE_LIST_VERSION,
        });
        pinsSnapshot = await readPins().catch(() => pinsSnapshot);
        // Issue #27 (review finding): inspectForDrift's own write is
        // best-effort — it swallows a write failure (drift.ts) so drift
        // detection degrades gracefully rather than blocking the session.
        // That is the right default everywhere else it's used, but it means
        // this specific write — the one the hold below exists to make
        // durable — can silently fail with nothing to show for the wait.
        // Confirm it actually landed and warn (don't block) if it didn't.
        if (canProducePin && !allNameableToolsPinned(msg, parsed.serverName, pinsSnapshot)) {
          process.stderr.write(
            `[mcpm-guard] PIN-COMMIT-UNCONFIRMED ${safeName}: could not confirm the ` +
              `first-session tools/list pin was persisted to ~/.mcpm/pins.json. A crash ` +
              `before a future write succeeds would leave this session's tool definitions ` +
              `unpinned. Review ~/.mcpm/guard-events.jsonl and re-check with \`mcpm guard status\`.\n`,
          );
        }
      };
    } else if (isInitializeResult(msg)) {
      // H5: handshake-drift inspection (capabilities + identity). WARN-tier —
      // never blocks (blocking an initialize result kills the session). The sync
      // pass compares against the FROZEN baseline; the off-thread async path does
      // first-session capture + the cross-session warn-once previous_hashes append.
      driftResult = inspectHandshakeDriftSync(msg, parsed.serverName, baselineForDrift, sessionState);

      void (async () => {
        await inspectHandshakeForDrift(msg, parsed.serverName, {
          read: () => readPins().catch(() => pinsSnapshot),
          write: writePins,
          signatureListVersion: SIGNATURE_LIST_VERSION,
        });
        pinsSnapshot = await readPins().catch(() => pinsSnapshot);
      })();
    }

    const result = applyPolicy(mergeInspect(statelessResult, driftResult), policy);
    if (commitPin === null) return result;

    // Issue #27: the FIRST tools/list this session that can actually produce a
    // pin for a NEVER-pinned server is held until its pin write is attempted
    // and confirmed (warned if it can't be) — otherwise the frame reaches the
    // client (and whatever it's shown gets trusted) before there is any disk
    // record of what that was; a crash/kill in that gap would make the NEXT
    // launch look like another first session, with no baseline left to catch a
    // swapped definition against. Every later tools/list this session is
    // already covered by the in-memory `firstHashes` same-session cache
    // (SECURITY F3 / #58), so it stays fire-and-forget — one extra round-trip,
    // once per session per server. `firstToolsListPinAwaited` is set ONLY on
    // the branch that actually holds — an empty/nameless list must not burn
    // the one-shot opportunity (review finding).
    if (neverPinnedThisServer && !firstToolsListPinAwaited && canProducePin) {
      firstToolsListPinAwaited = true;
      return commitPin().then(() => result);
    }
    void commitPin();
    return result;
  };

  const inspectParent = (msg: JSONRPCMessage): InspectResult => {
    if (pausedUntilFuture) return { action: "pass", findings: [] };
    // TODOS #50: route through the shared stateless-detector composition
    // instead of calling inspectMessage bare. Behavior-preserving for every
    // pre-existing detector — detectExfilParams self-guards on a frame shape
    // (`result.tools`) a parent->child request never has — but it is what
    // makes detectShellMetacharArgs (a bespoke tool_call_args detector)
    // actually enforced on live parent->child traffic instead of only
    // visible to `mcpm guard inspect` / the fixture release-gate. Without
    // this, a future request-side bespoke detector added there would
    // silently apply everywhere except the live relay — the parent-side
    // mirror of the v0.27.0 (#153) gap.
    //
    // Deliberately inspectStatelessDetectors, NOT inspectFrame: inspectFrame
    // also runs inspectServerInitiated, which is only valid on the
    // child->parent direction. Review found that routing a parent request
    // through inspectFrame would make inspectServerInitiated's
    // replyToOrigin path reachable from a malformed/malicious client message
    // (nothing here enforces that a client never sends a method literally
    // named "sampling/createMessage"/"elicitation/create"), and the
    // in-process relay's block-response sink selection for replyToOrigin is
    // shared, non-direction-aware code — a false match on this path would
    // have misrouted a block meant for the client to the child instead.
    return applyPolicy(inspectStatelessDetectors(msg), policy);
  };

  // SECURITY F2 / issue #20: build the wrapped child's env from an intentional
  // allowlist instead of forwarding the relay's entire process.env. The relay
  // env mixes the user's AMBIENT shell secrets (OPENAI_API_KEY, AWS_*,
  // GITHUB_TOKEN, …) with the IDE-injected DECLARED vars; the wrapped server is
  // only semi-trusted, so it must see just:
  //   1. a safe baseline (PATH, HOME, locale, … via buildSafeEnv), plus
  //   2. the server's own DECLARED env keys (names carried in the wrap marker).
  // Values written as `mcpm:keychain:server/KEY` placeholders (by `mcpm
  // secrets`) are then resolved to their decrypted secrets, so the plaintext
  // exists only in this child's in-memory env and never on disk.
  const baselineEnv = buildSafeEnv(process.env);
  const childEnvSource: NodeJS.ProcessEnv = { ...baselineEnv };
  for (const key of parsed.declaredEnvKeys) {
    const value = process.env[key];
    if (value !== undefined) childEnvSource[key] = value;
  }

  let childEnv: Record<string, string>;
  try {
    childEnv = await resolveEnvPlaceholders(childEnvSource);
  } catch (err) {
    process.stderr.write(
      `[mcpm-guard] SECRET-MISSING ${safeName} ${(err as Error).message}\n`,
    );
    return 1;
  }

  // F1 — spawn-time confinement decision. The confine store is the source of
  // truth for "is this server enrolled" (so a stripped marker on an enrolled
  // server is still caught); the marker's --confine-profile-hash +
  // --confine-required bind it. backendAvailable is PRE-CHECKED here (never via
  // the child's 'error' event) so a missing sandbox binary can't misattribute
  // H9's spawn-failure forensics to the wrapper instead of the real server.
  //
  // A confine hash flag that is present but NOT 64-hex is a tampered/corrupt
  // marker (parseMarker rejects the same shape for unwrap). Treat it as tamper and
  // fail closed with a dedicated event — do not let it fall through to a
  // misleading "hash mismatch" verdict.
  if (
    parsed.confineProfileHash !== undefined &&
    !/^[0-9a-f]{64}$/.test(parsed.confineProfileHash)
  ) {
    process.stderr.write(
      `[mcpm-guard] CONFINE-BLOCK ${safeName}: malformed --confine-profile-hash in the wrap ` +
        `marker (the client config entry may be tampered or corrupt). Refusing to start.\n`,
    );
    void appendEvent(
      confineGuardEvent(
        "confine-marker-malformed",
        "malformed confine profile hash",
        "block",
        "critical",
      ),
      parsed.serverName,
    );
    process.exit(1);
  }
  let spawnCommand = parsed.command;
  let spawnArgs: readonly string[] = parsed.args;
  let confineProfile: ConfineProfile | null = null;
  try {
    confineProfile = await loadProfile(parsed.serverName);
  } catch (err) {
    // A corrupt/tampered store fails closed at the read. Surface it and treat the
    // profile as absent, so the decision keys fail-closed on --confine-required.
    process.stderr.write(
      `[mcpm-guard] CONFINE-STORE-ERROR ${safeName}: ${(err as Error).message}\n`,
    );
  }
  const confineDecision = decideConfine({
    profile: confineProfile,
    markerHash: parsed.confineProfileHash ?? null,
    markerRequired: parsed.confineRequired === true,
    backendAvailable: isConfineBackendAvailable(),
  });
  if (confineDecision.action === "fail-closed") {
    process.stderr.write(
      `[mcpm-guard] CONFINE-BLOCK ${safeName}: ${confineDecision.reason}. Refusing to start ` +
        `(this server is marked require-confine). Run \`mcpm guard doctor-confine\` to check the ` +
        `backend, and review ~/.mcpm/guard-events.jsonl.\n`,
    );
    if (confineDecision.event !== undefined) {
      void appendEvent(
        confineGuardEvent(confineDecision.event, confineDecision.reason, "block", "critical"),
        parsed.serverName,
      );
    }
    process.exit(1);
  }
  if (confineDecision.action === "confine" && confineProfile !== null) {
    const wrapped = wrapForConfinement(confineProfile, parsed.command, parsed.args);
    if (wrapped !== null) {
      spawnCommand = wrapped.command;
      spawnArgs = wrapped.args;
      void appendEvent(
        confineGuardEvent(
          confineDecision.event ?? "confine-applied",
          confineDecision.reason,
          "pass",
          "low",
        ),
        parsed.serverName,
      );
    } else {
      // The backend was available when decideConfine ran but wrapForConfinement
      // returned null (e.g. MCPM_DISABLE_CONFINE flipped, or the binary vanished,
      // between the pre-check and here). NEVER silently run a to-be-confined server
      // unconfined: fail closed if required, else warn loudly + log.
      const required = parsed.confineRequired === true || confineProfile.require_confine;
      if (required) {
        process.stderr.write(
          `[mcpm-guard] CONFINE-BLOCK ${safeName}: sandbox backend became unavailable at spawn ` +
            `(require-confine). Refusing to start.\n`,
        );
        void appendEvent(
          confineGuardEvent(
            "confine-backend-missing",
            "backend unavailable at wrap",
            "block",
            "critical",
          ),
          parsed.serverName,
        );
        process.exit(1);
      }
      process.stderr.write(
        `[mcpm-guard] CONFINE-UNCONFINED ${safeName}: sandbox backend unavailable at wrap — ` +
          `running unconfined.\n`,
      );
      void appendEvent(
        confineGuardEvent("confine-backend-missing", "backend unavailable at wrap", "warn", "high"),
        parsed.serverName,
      );
    }
  } else if (confineDecision.event !== undefined) {
    // Unconfined but noteworthy (stripped marker / missing profile / no backend).
    process.stderr.write(
      `[mcpm-guard] CONFINE-UNCONFINED ${safeName}: ${confineDecision.reason} — running unconfined.\n`,
    );
    void appendEvent(
      confineGuardEvent(confineDecision.event, confineDecision.reason, "warn", "high"),
      parsed.serverName,
    );
  }

  const handle = startRelay({
    command: spawnCommand,
    args: spawnArgs,
    env: childEnv,
    parentIn: process.stdin,
    parentOut: process.stdout,
    inspectChildResponse: inspectChild,
    inspectParentRequest: inspectParent,
    onEvent: logEvent,
  });

  return handle.exit;
}

// ---------------------------------------------------------------------------
// Sync drift inspection against a pin snapshot (no I/O — pure function).
// drift.ts has the async version that also writes first-session pins; this
// is the sync variant the per-message inspect callback uses.
// ---------------------------------------------------------------------------

import {
  hashToolDefinition,
  pinStillMatches,
  legacyFieldHashCandidates,
  handshakeStillMatches,
  legacyHandshakeFieldCandidates,
  fieldHashesOf,
  handshakeFieldHashesOf,
  handshakeCapabilityKeys,
  hashHandshake,
  lookupHandshake,
  type FieldHashes,
  type PinsFile,
} from "./pins.js";
import {
  classifyHandshakeDrift,
  buildHandshakeDriftFinding,
} from "./drift.js";

/**
 * Per-session drift state. `firstHashes` is the SECURITY F3 same-session "first
 * hash seen" cache (the ONE deliberately-mutable in-memory session cache).
 * `revalidationArmed` is a SINGLE-SHOT flag set by an announced
 * `notifications/tools/list_changed`: the next tools/list frame is allowed to
 * legitimately change definitions, after which the flag reverts to the strict
 * F3 guard.
 *
 * `handshakeSeenHash` is the H5 same-session guard: `initialize` should happen
 * once, so a SECOND initialize result whose whole-hash differs is anomalous and
 * warns (`handshake-drift-in-session`) — never blocks.
 *
 * `firstFieldHashes` is #58 (Deadbugz): per-field hashes captured at the SAME
 * moments as `firstHashes` (first sight / armed rebaseline). It is the
 * baseline the ARMED same-session revalidation path tiers an EXISTING tool's
 * mutation against (H4: description-only = cosmetic, schema/annotations =
 * security) — closing the gap where a never-pinned server's `list_changed`
 * cover let a mutated tool through with zero findings. Optional + lazily
 * created (mirrors PinEntry.field_hashes' additive-optional precedent) so
 * pre-#58 state literals still compile.
 */
export interface SessionDriftState {
  firstHashes: Map<string, string>;
  revalidationArmed: boolean;
  handshakeSeenHash: string | null;
  firstFieldHashes?: Map<string, FieldHashes>;
  /**
   * Canonical names this session has seen advertised under TWO different raw
   * spellings in one tools/list. The shared canonical slot is then AMBIGUOUS —
   * it cannot say which tool owns it — so it is retired for the rest of the
   * session and those tools are matched by raw name only. Sticky on purpose: if
   * it were per-frame, a `[Read, read]` frame followed by a `[Read]`-only frame
   * would resolve `Read` through the canonical slot the twin also wrote.
   */
  ambiguousCanons?: Set<string>;
}

function sanitizeLabel(s: string): string {
  return sanitizeForTerminal(s, 128);
}

/**
 * Sync, pure-ish (no I/O) drift inspection against an in-memory pin snapshot.
 * The ONLY mutation is the session-state cache (firstHashes / revalidationArmed)
 * — a deliberate in-memory session store. Exported for unit testing the
 * SECURITY F3 same-session guard + the H4 tiered classification; the async
 * {@link inspectForDrift} in drift.ts also writes first-session pins.
 */
export function inspectForDriftSync(
  msg: JSONRPCMessage,
  serverName: string,
  baseline: PinsFile,
  state: SessionDriftState,
): InspectResult {
  // Frame-scoped single-shot arm: read then immediately disarm so a SECOND
  // frame in the same buffer chunk reverts to the strict F3 guard.
  const armed = state.revalidationArmed;
  state.revalidationArmed = false;

  const result = (msg as { result?: { tools?: unknown } }).result;
  const tools = Array.isArray(result?.tools) ? result.tools : [];

  // TODOS #58 residual, FP guard. Two tools in ONE list whose names canonicalize
  // together (a spec-legal `Read`/`read` pair, or an attacker's twin sitting
  // beside the tool it imitates) would otherwise share a session cache slot: the
  // second would be compared against the first's hashes, differ, and hard-BLOCK
  // a legitimate server. Such names are excluded from the drift comparison AND
  // from every cache/pin write, so neither can poison the other's baseline.
  // They are not silently dropped — the stateless detector
  // (tool-name-confusable.ts) warns on exactly this shape, on every surface
  // including `mcpm guard inspect`. Net effect: the REPLACE form of the attack
  // (twin replaces the trusted tool — the Deadbugz shape) blocks via the
  // canonical key above; the CO-EXIST form warns instead of passing silently.
  // TODOS #58 residual, FP guard. Two tools in ONE list whose names canonicalize
  // together (a spec-legal `Read`/`read` pair, or an attacker's twin sitting
  // beside the tool it imitates) must not share a session slot: the second would
  // be compared against the first's hashes, differ, and hard-BLOCK a legitimate
  // server. Those canonical names fall back to RAW keying — for the rest of the
  // session — so each tool keeps its own independent baseline.
  //
  // They are deliberately NOT skipped. An adversarial review measured that
  // dropping a collision group from inspection drops the INCUMBENT too (the group
  // always contains it), so appending one throwaway ASCII case-variant beside a
  // real tool removed that tool from drift inspection entirely — turning this FP
  // guard into a universal disarm of the very control it protects. Raw keying
  // preserves the zero-FP property without ever taking a tool out of inspection.
  for (const canon of duplicateCanonicalNames(tools)) {
    (state.ambiguousCanons ??= new Set()).add(canon);
    // Retire the shared slot: whichever twin wrote it, it can no longer be
    // attributed. Each tool keeps its own raw slot, so the INCUMBENT stays
    // protected — that is what stops a throwaway twin from disarming it.
    state.firstHashes.delete(`${serverName}::canon::${canon}`);
    state.firstFieldHashes?.delete(`${serverName}::canon::${canon}`);
  }

  const findings: InspectFinding[] = [];
  for (const rawTool of tools) {
    const finding = inspectToolDrift(rawTool, serverName, baseline, state, armed);
    if (finding !== null) findings.push(finding);
  }
  // Action = MAX over findings via defaultActionForFinding (no hardcoded block):
  // a cosmetic-only result is warn; any security finding makes it block.
  const action = worstAction(findings);
  return { action, findings };
}

/**
 * Canonical tool names that appear more than once (under DIFFERENT raw
 * spellings) in one tools/list. See the FP guard in inspectForDriftSync.
 * A byte-identical name repeated twice is a malformed list, not a confusable
 * pair, and is deliberately NOT treated as a duplicate here.
 */
function duplicateCanonicalNames(tools: readonly unknown[]): ReadonlySet<string> {
  const seenRaw = new Map<string, string>();
  const dupes = new Set<string>();
  for (const t of tools) {
    const name = (t as RawTool | null)?.name;
    if (typeof name !== "string") continue;
    const canon = canonicalToolName(name);
    const prior = seenRaw.get(canon);
    if (prior === undefined) seenRaw.set(canon, name);
    else if (prior !== name) dupes.add(canon);
  }
  return dupes;
}

interface RawTool {
  name?: unknown;
  description?: unknown;
  schema?: unknown;
  inputSchema?: unknown;
  annotations?: unknown;
}

/**
 * Inspect ONE tool from a tools/list frame. Mutates the session `firstHashes`
 * cache (records on first sight, rebaselines when `armed`). Returns at most one
 * finding (F3 same-session block, OR a tiered pin-drift finding), or null.
 */
function inspectToolDrift(
  rawTool: unknown,
  serverName: string,
  baseline: PinsFile,
  state: SessionDriftState,
  armed: boolean,
): InspectFinding | null {
  if (rawTool === null || typeof rawTool !== "object") return null;
  const tool = rawTool as RawTool;
  const toolName = typeof tool.name === "string" ? tool.name : null;
  if (toolName === null) return null;

  const fields = {
    description: typeof tool.description === "string" ? tool.description : null,
    schema: tool.inputSchema ?? tool.schema,
    annotations: tool.annotations,
  };
  const liveWhole = hashToolDefinition(fields);
  const liveFields = fieldHashesOf(fields);

  // SECURITY F13: lookup via Object.hasOwn to avoid prototype/constructor confusion.
  const serverPins = Object.hasOwn(baseline.servers, serverName) ? baseline.servers[serverName] : undefined;
  // A canonical name this session saw under two raw spellings has an ambiguous
  // shared slot, so those tools match by RAW name only (and get an exact-only
  // pin lookup) — the two never share a baseline.
  const canon = canonicalToolName(toolName);
  const collides = state.ambiguousCanons?.has(canon) === true;
  // Canonical-aware: a confusable/case twin of a pinned tool resolves to THAT
  // pin instead of being filed as a brand-new tool (TODOS #58 residual).
  const lookup = lookupToolPin(serverPins, toolName, { exactOnly: collides });
  const pinned = lookup.kind === "exact" || lookup.kind === "canonical" ? lookup.entry : undefined;

  const newDescriptionExcerpt =
    typeof tool.description === "string" ? sanitizeForTerminal(tool.description, 80) : undefined;

  // SECURITY F3: same-session bypass check. If we've already seen a hash for
  // (server, tool) this session, a subsequent differing tools/list is a rug-pull
  // attempt — UNLESS `armed` (an announced list_changed legitimately changes
  // definitions). When armed we skip F3 and rebaseline instead.
  // TODOS #58 residual: key by the CANONICAL name so a case / zero-width /
  // homoglyph twin of an already-seen tool lands on that tool's baseline rather
  // than on a fresh key. The raw name is kept for the finding text. Placed at
  // the SHARED key derivation, not inside the armed branch, because the
  // unarmed F3 guard below skips on `firstSeen === undefined` in exactly the
  // same way — both paths were evadable.
  // TWO namespaced slots per tool, never one shared keyspace. Writing raw and
  // canonical names into a single map aliases them — `read`'s raw key is byte-
  // identical to `Read`'s canonical key — which made two benign, unchanged tools
  // read as a rug-pull depending only on the order they were first seen (found
  // in review). Resolve RAW first (exact identity, always correct), then the
  // canonical slot (the twin-catching fallback) unless it has been retired.
  const rawKey = `${serverName}::raw::${toolName}`;
  const canonKey = `${serverName}::canon::${canon}`;
  const firstSeen = state.firstHashes.get(rawKey) ?? (collides ? undefined : state.firstHashes.get(canonKey));
  const firstSeenFields =
    state.firstFieldHashes?.get(rawKey) ?? (collides ? undefined : state.firstFieldHashes?.get(canonKey));
  if (!armed && firstSeen !== undefined && firstSeen !== liveWhole) {
    return inSessionDriftFinding(serverName, toolName, firstSeen, liveWhole);
  }

  // #58 (Deadbugz): `armed` exists so a server can legitimately ADD tools via
  // list_changed — that's why F3 above is skipped. It must not also give a
  // blank check to MUTATE a tool this session has already seen: that is the
  // Deadbugz mechanism (benign list -> list_changed -> poisoned list), and for
  // a server's first-ever session there is no disk pin below to catch it
  // either. Tier the change with the same H4 doctrine the disk-pin path uses
  // (classifyFieldDrift mirrors classifyDrift), against the session's
  // first-seen field hashes. A brand-new tool name (firstSeenFields
  // undefined) is unaffected — no finding — which is what keeps a real
  // list_changed addition zero-FP.
  let armedMutationFinding: InspectFinding | null = null;
  if (armed && firstSeen !== undefined && firstSeen !== liveWhole && firstSeenFields !== undefined) {
    armedMutationFinding = buildDriftFinding({
      cls: classifyFieldDrift(firstSeenFields, liveFields),
      safeServer: sanitizeLabel(serverName),
      safeTool: sanitizeLabel(toolName),
      expected: firstSeen,
      actual: liveWhole,
      newDescriptionExcerpt,
    });
  }

  // Record on first sight, or rebaseline when an announced list_changed armed us.
  if (firstSeen === undefined || armed) {
    state.firstHashes.set(rawKey, liveWhole);
    (state.firstFieldHashes ??= new Map()).set(rawKey, liveFields);
    // The canonical slot is what catches a look-alike twin in a LATER frame.
    // Never write it for a name whose canonical form is already ambiguous.
    if (!collides) {
      state.firstHashes.set(canonKey, liveWhole);
      state.firstFieldHashes.set(canonKey, liveFields);
    }
  }

  if (armedMutationFinding !== null) return armedMutationFinding;

  // TODOS #58 follow-up: this server's pin store already holds two names that
  // fold together, and this live name matches neither exactly. Falling through
  // to `pinned === undefined` would file it as a brand-new tool — precisely the
  // carve-out this work exists to close, and reachable by planting a
  // benign-looking colliding pair in a server's first-ever list, after which
  // EVERY confusable spelling of that tool reads as new, on every future
  // session. Report instead of failing open. No measured cost: 0 of 96 surveyed
  // real servers has any within-server canonical collision at all, so a THIRD
  // spelling stacked on a collided pair is not a shape legitimate servers reach.
  if (lookup.kind === "ambiguous") {
    return ambiguousPinFinding(serverName, toolName);
  }

  if (!pinned || pinned.current_hash === null) return null;
  // #26: also accept the pre-NFC hash, so pins written before NFC folding do not
  // read as drift on upgrade (a schema-side hash tiers as a hard block).
  if (pinStillMatches(pinned.current_hash, liveWhole, fields)) return null;

  // Tier the drift by field (cosmetic description-only → warn; schema /
  // annotations / coarse → block). Same finding shapes as drift.ts. For a
  // cosmetic warn, carry a sanitized + truncated NEW description so the
  // guard-events.jsonl entry is self-contained for review.
  const cls = classifyDrift(pinned, liveFields, legacyFieldHashCandidates(fields));
  // Name the STORED key when the live name only resolved canonically: the
  // remediation prints `accept-drift --tool <name>`, and that command looks the
  // key up exactly, so printing the look-alike would hand the user a command
  // that silently does nothing (review).
  return buildDriftFinding({
    cls,
    safeServer: sanitizeLabel(serverName),
    safeTool: sanitizeLabel(toolName),
    pinnedAs: lookup.kind === "canonical" ? sanitizeLabel(lookup.key) : undefined,
    expected: pinned.current_hash,
    actual: liveWhole,
    newDescriptionExcerpt,
  });
}

/**
 * TODOS #58 follow-up: the live tool name matches no pinned key exactly, and
 * more than one pinned key folds onto it. Blocking (rather than treating it as
 * an unpinned new tool) is what keeps a planted collision from permanently
 * disarming drift protection for that tool.
 */
function ambiguousPinFinding(serverName: string, toolName: string): InspectFinding {
  const safeTool = sanitizeLabel(toolName);
  return {
    signature_id: "schema-drift",
    category: "MCP-SCHEMA-DRIFT",
    severity: "critical",
    target: "tool_description",
    matched_text_excerpt: `${sanitizeLabel(serverName)}: ${safeTool} matches multiple pinned tool names`,
    remediation:
      `Tool "${safeTool}" matches no pinned tool exactly, and MORE THAN ONE pinned ` +
      `name for this server is visually indistinguishable from it after Unicode ` +
      `normalization. A server cannot be trusted to have done this by accident: it ` +
      `is how a look-alike name is made to read as a brand-new tool. Inspect the ` +
      `pinned names with \`mcpm guard status\`, and if the server is trusted, drop the ` +
      `stale entries with \`mcpm guard accept-drift --server <name> --remove --tool <tool>\` ` +
      `and let the next session re-pin.`,
  };
}

/** SECURITY F3: same-session double-tools/list rug-pull finding (critical block). */
function inSessionDriftFinding(
  serverName: string,
  toolName: string,
  firstSeen: string,
  liveWhole: string,
): InspectFinding {
  return {
    signature_id: "schema-drift-in-session",
    category: "OWASP-MCP-1",
    severity: "critical",
    target: "tool_description",
    matched_text_excerpt: `${sanitizeLabel(toolName)}: ${firstSeen.slice(7, 19)}… → ${liveWhole.slice(7, 19)}… (same session)`,
    remediation:
      `Server "${sanitizeLabel(serverName)}" delivered two different schemas for tool "${sanitizeLabel(toolName)}" ` +
      `in the same session. This is a rug-pull attempt; restart the IDE and reinspect ` +
      `the server's source.`,
  };
}

/** True if `msg` is a server→client `notifications/tools/list_changed`. */
export function isToolsListChangedNotification(msg: JSONRPCMessage): boolean {
  if (!("method" in msg)) return false;
  if ((msg as { method?: unknown }).method !== "notifications/tools/list_changed") return false;
  // A notification has no `result` (and no `id`); guard against a crafted frame
  // that pairs the method with a result.
  return !("result" in msg);
}

/**
 * Issue #27: true if `msg`'s tools/list result contains at least one entry
 * with a string `name` — i.e., inspectForDrift (drift.ts) will actually
 * attempt to pin something from this frame, rather than being a no-op
 * (`{tools:[]}`, or every entry missing a usable name). Only a frame that can
 * produce a pin is allowed to consume the one-shot session hold in
 * inspectChild — review found an empty/malformed first tools/list burned it
 * on nothing, leaving the REAL list that followed unprotected.
 */
export function hasNameableTool(msg: JSONRPCMessage): boolean {
  const result = (msg as { result?: { tools?: unknown } }).result;
  const tools = Array.isArray(result?.tools) ? result.tools : [];
  return tools.some(
    (t) => t !== null && typeof t === "object" && typeof (t as { name?: unknown }).name === "string",
  );
}

/**
 * Issue #27: true if every named tool in `msg`'s tools/list result now has a
 * non-null `current_hash` pin for `serverName` in `pins`. inspectForDrift's
 * own write is deliberately best-effort — it swallows a write failure so
 * drift detection degrades gracefully rather than blocking the session — but
 * that leaves the ONE caller that needs the guarantee (the held first
 * tools/list) with no way to tell "committed" from "silently didn't" without
 * this check.
 */
export function allNameableToolsPinned(msg: JSONRPCMessage, serverName: string, pins: PinsFile): boolean {
  const result = (msg as { result?: { tools?: unknown } }).result;
  const tools = Array.isArray(result?.tools) ? result.tools : [];
  const serverPins = Object.hasOwn(pins.servers, serverName) ? pins.servers[serverName] : undefined;
  for (const t of tools) {
    if (t === null || typeof t !== "object") continue;
    const name = (t as { name?: unknown }).name;
    if (typeof name !== "string") continue;
    const r = lookupToolPin(serverPins, name);
    const pinned = r.kind === "exact" || r.kind === "canonical" ? r.entry : undefined;
    if (!pinned || pinned.current_hash === null) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// H5: sync initialize-handshake drift inspection (no I/O).
// ---------------------------------------------------------------------------

/**
 * H5: true if `msg` is an MCP `initialize` RESULT. Discriminates on
 * `result.protocolVersion` being a string — the SAME reliable discriminator the
 * pattern engine's `initialize_instructions` case uses — NOT the presence of an
 * optional `instructions`/`capabilities` key (which a tools/call result could
 * also carry).
 */
export function isInitializeResult(msg: JSONRPCMessage): boolean {
  if (!("result" in msg)) return false;
  const result = (msg as { result?: { protocolVersion?: unknown } }).result;
  return result !== null && typeof result === "object" && typeof result.protocolVersion === "string";
}

/**
 * Sync, pure-ish (mutates only the session cache) handshake-drift inspection
 * against the FROZEN session-start `baseline`. WARN-tier only — never blocks.
 *
 *  - same-session guard: a SECOND differing initialize whole-hash → warn
 *    (`handshake-drift-in-session`); a second IDENTICAL one is a no-op.
 *  - no handshake pin in the baseline → pass (first session; the async path
 *    captures off-thread).
 *  - live whole-hash matches pinned.current_hash → pass. #26: "matches" means
 *    {@link handshakeStillMatches}, so a pre-NFC pin over the same text counts.
 *  - live whole-hash matches an entry in pinned.previous_hashes → pass
 *    (warn-once: already surfaced). Same predicate, so warn-once survives upgrade.
 *  - else → classify (with #26 per-dimension alternates) + build warn findings.
 */
export function inspectHandshakeDriftSync(
  msg: JSONRPCMessage,
  serverName: string,
  baseline: PinsFile,
  state: SessionDriftState,
): InspectResult {
  const result = (msg as { result?: { capabilities?: unknown; serverInfo?: { name?: unknown } } }).result;
  if (result === null || typeof result !== "object") return { action: "pass", findings: [] };

  const liveFields = handshakeFieldHashesOf(result);
  const liveCapKeys = handshakeCapabilityKeys(result);
  const liveWhole = hashHandshake(liveFields);

  // Same-session guard: initialize should happen once. A second, DIFFERING
  // initialize is anomalous → warn (never block). Record on first sight.
  const seen = state.handshakeSeenHash;
  if (seen !== null && seen !== liveWhole) {
    return warnResult(handshakeInSessionFinding(serverName, seen, liveWhole));
  }
  if (seen === null) state.handshakeSeenHash = liveWhole;

  const pinned = lookupHandshake(baseline, serverName);
  if (pinned === undefined) return { action: "pass", findings: [] };
  if (
    handshakeStillMatches(pinned.current_hash, liveWhole, result) ||
    pinned.previous_hashes.some((h) => handshakeStillMatches(h, liveWhole, result))
  ) {
    return { action: "pass", findings: [] };
  }

  const cls = classifyHandshakeDrift(pinned, liveFields, liveCapKeys, legacyHandshakeFieldCandidates(result));
  const findings = buildHandshakeDriftFinding({
    cls,
    safeServer: sanitizeLabel(serverName),
  });
  const action = worstAction(findings);
  return { action, findings };
}

function warnResult(finding: InspectFinding): InspectResult {
  return { action: defaultActionForFinding(finding), findings: [finding] };
}

/**
 * H5 same-session anomaly: two differing initialize results in one session. WARN
 * (severity high) — never block. Hashes are not attacker-named keys, safe to slice.
 */
function handshakeInSessionFinding(
  serverName: string,
  firstSeen: string,
  liveWhole: string,
): InspectFinding {
  return {
    signature_id: "handshake-drift-in-session",
    category: "OWASP-MCP-1",
    severity: "high",
    target: "initialize_instructions",
    matched_text_excerpt: `${sanitizeLabel(serverName)}: ${firstSeen.slice(7, 19)}… → ${liveWhole.slice(7, 19)}… (same session)`,
    remediation:
      `Server "${sanitizeLabel(serverName)}" delivered two different initialize handshakes ` +
      `in the same session — initialize should occur once. Inspect the wrapped command; ` +
      `this is a warn-only signal and does not block the session.`,
  };
}
