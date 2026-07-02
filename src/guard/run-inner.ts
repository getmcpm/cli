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
import { inspectMessage, defaultActionForFinding, ACTION_RANK } from "./patterns.js";
import { detectExfilParams } from "./exfil-params.js";
import { OWASP_MCP_TOP_10 } from "./signatures.js";
import { startRelay, buildSafeEnv, type GuardEvent } from "./relay.js";
import { inspectForDrift, inspectHandshakeForDrift, classifyDrift, buildDriftFinding } from "./drift.js";
import { readPins, writePins } from "./pins.js";
import { readPolicy, expireStale, PolicyIntegrityError, type GuardPolicyFile } from "./policy.js";
import { appendEvent } from "./event-log.js";
import { hashOriginalEntry } from "./wrap.js";
import { loadProfile } from "./confine/store.js";
import { isConfineBackendAvailable, wrapForConfinement } from "./confine/apply.js";
import { decideConfine } from "./confine/decide.js";
import type { ConfineProfile } from "./confine/profile.js";
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

export function mergeInspect(a: InspectResult, b: InspectResult): InspectResult {
  // Most-severe action wins; concat findings. Uses the shared ACTION_RANK scale
  // (pass < warn < block) instead of a local duplicate map.
  const action = ACTION_RANK[a.action] >= ACTION_RANK[b.action] ? a.action : b.action;
  // H7: carry replyToOrigin if EITHER side requested it (a server-initiated
  // sampling/elicitation block must not be stranded by merging with a benign
  // pattern/drift result). Only kept on a block action (see withReplyToOrigin).
  return withReplyToOrigin(
    { action, findings: [...a.findings, ...b.findings] },
    a.replyToOrigin === true || b.replyToOrigin === true,
  );
}

/**
 * Attach `replyToOrigin: true` to a result ONLY when it requested AND the result
 * is still a block. The flag is meaningless on warn/pass (you don't error-reply a
 * non-blocked request), so it must never survive onto a downgraded action.
 */
function withReplyToOrigin(result: InspectResult, replyToOrigin: boolean): InspectResult {
  if (replyToOrigin && result.action === "block") return { ...result, replyToOrigin: true };
  return result;
}

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

function hasToolsList(msg: JSONRPCMessage): boolean {
  if (!("result" in msg)) return false;
  const result = (msg as { result?: { tools?: unknown } }).result;
  return Array.isArray(result?.tools);
}

/**
 * H7: true if `msg` is a server-INITIATED `sampling/createMessage` REQUEST (has
 * an id). Fail-closed on the notification shape: a frame carrying the method but
 * NO id is NOT eligible for block-to-origin — you can't error-reply a
 * notification, so block-to-origin would strand it.
 */
export function isSamplingRequest(msg: JSONRPCMessage): boolean {
  return isServerRequestMethod(msg, "sampling/createMessage");
}

/** H7: true if `msg` is a server-INITIATED `elicitation/create` REQUEST (has an id). */
export function isElicitationRequest(msg: JSONRPCMessage): boolean {
  return isServerRequestMethod(msg, "elicitation/create");
}

function isServerRequestMethod(msg: JSONRPCMessage, method: string): boolean {
  if (!("method" in msg) || (msg as { method?: unknown }).method !== method) return false;
  // A request MUST carry an id; a notification-shaped frame (no id) is not
  // eligible for block-to-origin (no reply channel) — fail closed.
  return "id" in msg && (msg as { id?: unknown }).id !== undefined;
}

/** H7: a server-INITIATED sampling/elicitation method frame (id OR no-id — used
 * for content SCANNING; block-to-origin eligibility separately requires an id). */
function isServerInitiatedMethod(msg: JSONRPCMessage): boolean {
  if (!("method" in msg)) return false;
  const m = (msg as { method?: unknown }).method;
  return m === "sampling/createMessage" || m === "elicitation/create";
}

/**
 * H7: inspect a server-INITIATED sampling/elicitation request's server-authored
 * content for prompt-injection. Returns block (+ replyToOrigin when the frame can
 * be error-replied) on a detected injection, else null (benign / out of scope) →
 * caller forwards untouched. We gate the injection CONTENT, not the mechanism.
 *
 * The content is wrapped into a synthetic `prompts/get`-shaped frame so the
 * existing `prompt_content` array-content extraction (H1) scans it WITHOUT a new
 * targetSubtree case. But the findings are then RE-TAGGED to `sampling_prompt`:
 *   - `prompt_content` is a WARN_ONLY carrier (retrieved prompts/get data), so
 *     leaving the finding on it makes applyPolicy's defaultActionForFinding clamp
 *     the block back to WARN whenever guard-policy.yaml has ANY signature_override
 *     — silently forwarding the injection (CRITICAL, caught in review).
 *   - `sampling_prompt` is NOT warn-only, so the action derives from the finding's
 *     native severity (critical→block) and survives applyPolicy unclamped.
 * Content scanning covers BOTH id-bearing requests and no-id (notification-shaped)
 * frames; only an id-bearing block carries replyToOrigin (a no-id frame is still
 * dropped — makeBlockResponse returns null for it — but has no reply channel).
 */
export function inspectServerInitiated(msg: JSONRPCMessage): InspectResult | null {
  if (!isServerInitiatedMethod(msg)) return null;
  const contentLeaves = serverInitiatedContent(msg);
  if (contentLeaves.length === 0) return null;

  const synthetic = {
    jsonrpc: "2.0",
    id: 0, // dummy — the scan reads only the result subtree, never the id.
    result: { messages: contentLeaves.map((c) => ({ role: "user", content: c })) },
  } as JSONRPCMessage;

  const scan = inspectMessage(synthetic, OWASP_MCP_TOP_10);
  if (scan.findings.length === 0) return null;

  const findings: InspectFinding[] = scan.findings.map((f) => ({ ...f, target: "sampling_prompt" }));
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");

  const hasId = "id" in msg && (msg as { id?: unknown }).id !== undefined;
  return action === "block" && hasId
    ? { action, findings, replyToOrigin: true }
    : { action, findings };
}

/**
 * Extract the server-authored content leaves to scan from a sampling/elicitation
 * request: sampling → params.systemPrompt + params.messages[*].content;
 * elicitation → params.message plus the requestedSchema property descriptions.
 * Non-object/missing shapes yield an empty list (nothing to scan).
 */
function serverInitiatedContent(msg: JSONRPCMessage): unknown[] {
  const params = (msg as { params?: unknown }).params;
  if (params === null || typeof params !== "object") return [];
  const p = params as {
    messages?: unknown;
    message?: unknown;
    requestedSchema?: unknown;
    systemPrompt?: unknown;
  };
  const out: unknown[] = [];
  // systemPrompt is server-authored model context (MCP CreateMessageRequestParams)
  // and the highest-leverage sampling injection surface — scan it (review: HIGH).
  if (typeof p.systemPrompt === "string") out.push(p.systemPrompt);
  if (Array.isArray(p.messages)) {
    for (const m of p.messages) {
      if (m !== null && typeof m === "object" && "content" in m) out.push((m as { content: unknown }).content);
    }
  }
  if (typeof p.message === "string") out.push(p.message);
  if (p.requestedSchema !== null && typeof p.requestedSchema === "object") out.push(p.requestedSchema);
  return out;
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
  };

  // FROZEN session-start baseline. The off-thread refresh may keep reassigning
  // pinsSnapshot for its own fallback, but the sync classifier must compare
  // against the immutable session-start pins so a mid-session pin rewrite can't
  // retroactively launder a drift.
  const baselineForDrift = pinsSnapshot;

  const inspectChild = (msg: JSONRPCMessage): InspectResult => {
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
    const serverInitiated = inspectServerInitiated(msg);
    if (serverInitiated !== null) return applyPolicy(serverInitiated, policy);

    const patternResult = inspectMessage(msg, OWASP_MCP_TOP_10);
    let driftResult: InspectResult = { action: "pass", findings: [] };
    // F5: structural exfil-param key-name block on tools/list (the content-regex
    // pipeline can't see a property KEY). Pass on every non-tools/list frame.
    let exfilResult: InspectResult = { action: "pass", findings: [] };

    if (hasToolsList(msg)) {
      exfilResult = detectExfilParams(msg);
      driftResult = inspectForDriftSync(msg, parsed.serverName, baselineForDrift, sessionState);

      // Off-thread: refresh snapshot + apply first-session pin capture.
      void (async () => {
        await inspectForDrift(msg, parsed.serverName, {
          read: () => readPins().catch(() => pinsSnapshot),
          write: writePins,
          signatureListVersion: SIGNATURE_LIST_VERSION,
        });
        pinsSnapshot = await readPins().catch(() => pinsSnapshot);
      })();
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

    return applyPolicy(mergeInspect(mergeInspect(patternResult, driftResult), exfilResult), policy);
  };

  const inspectParent = (msg: JSONRPCMessage): InspectResult => {
    if (pausedUntilFuture) return { action: "pass", findings: [] };
    return applyPolicy(inspectMessage(msg, OWASP_MCP_TOP_10), policy);
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
  fieldHashesOf,
  handshakeFieldHashesOf,
  handshakeCapabilityKeys,
  hashHandshake,
  lookupHandshake,
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
 */
export interface SessionDriftState {
  firstHashes: Map<string, string>;
  revalidationArmed: boolean;
  handshakeSeenHash: string | null;
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

  const findings: InspectFinding[] = [];
  for (const rawTool of tools) {
    const finding = inspectToolDrift(rawTool, serverName, baseline, state, armed);
    if (finding !== null) findings.push(finding);
  }
  // Action = MAX over findings via defaultActionForFinding (no hardcoded block):
  // a cosmetic-only result is warn; any security finding makes it block.
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
  return { action, findings };
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
  const pinned = serverPins && Object.hasOwn(serverPins, toolName) ? serverPins[toolName] : undefined;

  // SECURITY F3: same-session bypass check. If we've already seen a hash for
  // (server, tool) this session, a subsequent differing tools/list is a rug-pull
  // attempt — UNLESS `armed` (an announced list_changed legitimately changes
  // definitions). When armed we skip F3 and rebaseline instead.
  const sessionKey = `${serverName}::${toolName}`;
  const firstSeen = state.firstHashes.get(sessionKey);
  if (!armed && firstSeen !== undefined && firstSeen !== liveWhole) {
    return inSessionDriftFinding(serverName, toolName, firstSeen, liveWhole);
  }
  // Record on first sight, or rebaseline when an announced list_changed armed us.
  if (firstSeen === undefined || armed) state.firstHashes.set(sessionKey, liveWhole);

  if (!pinned || pinned.current_hash === null) return null;
  if (liveWhole === pinned.current_hash) return null;

  // Tier the drift by field (cosmetic description-only → warn; schema /
  // annotations / coarse → block). Same finding shapes as drift.ts. For a
  // cosmetic warn, carry a sanitized + truncated NEW description so the
  // guard-events.jsonl entry is self-contained for review.
  const cls = classifyDrift(pinned, liveFields);
  const newDescriptionExcerpt =
    typeof tool.description === "string" ? sanitizeForTerminal(tool.description, 80) : undefined;
  return buildDriftFinding({
    cls,
    safeServer: sanitizeLabel(serverName),
    safeTool: sanitizeLabel(toolName),
    expected: pinned.current_hash,
    actual: liveWhole,
    newDescriptionExcerpt,
  });
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
 *  - live whole-hash === pinned.current_hash → pass.
 *  - live whole-hash ∈ pinned.previous_hashes → pass (warn-once: already surfaced).
 *  - else → classify + build warn findings.
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
  if (liveWhole === pinned.current_hash || pinned.previous_hashes.includes(liveWhole)) {
    return { action: "pass", findings: [] };
  }

  const cls = classifyHandshakeDrift(pinned, liveFields, liveCapKeys);
  const findings = buildHandshakeDriftFinding({
    cls,
    safeServer: sanitizeLabel(serverName),
  });
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
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
