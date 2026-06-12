/**
 * Direct tests for applyPolicy semantics (Step 7 security review F1 regression guard).
 *
 * The previous implementation had a critical bug: a `log_only` override on
 * any single finding silently downgraded the `block` action from ALL other
 * unmuted findings in the same result. These tests prove the fix.
 *
 * Since applyPolicy is module-private to run-inner.ts, we test through a
 * thin re-export to keep it isolated from the runInner spawn flow.
 */

import { describe, expect, test } from "vitest";
import type { InspectFinding, InspectResult, SignatureTarget } from "../types.js";
import type { GuardPolicyFile } from "../policy.js";
import { applyPolicy } from "../run-inner.js";

// applyPolicy is exported from run-inner.ts and tested directly here — NOT a
// local copy. A previous version of this test replicated the function inline,
// which made it structurally blind to behavioral changes in the real one (e.g.
// the warn-only carrier clamp). Import the production function so a regression
// in run-inner.ts is actually caught.

function finding(
  sigId: string,
  severity: InspectFinding["severity"] = "critical",
  target: SignatureTarget = "tool_response",
): InspectFinding {
  return {
    signature_id: sigId,
    category: "TEST",
    severity,
    target,
    matched_text_excerpt: `m-${sigId}`,
    remediation: `r-${sigId}`,
  };
}

describe("applyPolicy — security review F1 regression guard", () => {
  test("log_only override on ONE finding does NOT downgrade block from OTHER findings", () => {
    // This was the critical bug: any log_only mute silenced unrelated blocks.
    const result: InspectResult = {
      action: "block",
      findings: [finding("blocker", "critical"), finding("logger", "critical")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [{ id: "logger", action: "log_only" }],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("block"); // BUG would return "pass"
    expect(out.findings).toHaveLength(2);
  });

  test("log_only on ALL findings yields pass (intended behavior)", () => {
    const result: InspectResult = {
      action: "block",
      findings: [finding("a", "critical"), finding("b", "critical")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [
        { id: "a", action: "log_only" },
        { id: "b", action: "log_only" },
      ],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("pass");
    expect(out.findings).toHaveLength(2);
  });

  test("ignore drops the finding entirely", () => {
    const result: InspectResult = {
      action: "block",
      findings: [finding("muted", "critical"), finding("loud", "critical")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [{ id: "muted", action: "ignore" }],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("block");
    expect(out.findings.map((f) => f.signature_id)).toEqual(["loud"]);
  });

  test("warn override on a critical finding downgrades it to warn", () => {
    const result: InspectResult = {
      action: "block",
      findings: [finding("only", "critical")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [{ id: "only", action: "warn" }],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("warn");
  });

  test("block override on a low-severity finding upgrades it to block", () => {
    const result: InspectResult = {
      action: "pass",
      findings: [finding("escalate", "low")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [{ id: "escalate", action: "block" }],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("block");
  });

  test("no overrides → result passes through unchanged", () => {
    const result: InspectResult = {
      action: "block",
      findings: [finding("x", "critical")],
    };
    const out = applyPolicy(result, {});
    expect(out).toBe(result); // identity — fast path
  });

  test("all findings ignored → action pass + empty findings", () => {
    const result: InspectResult = {
      action: "block",
      findings: [finding("a"), finding("b")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [
        { id: "a", action: "ignore" },
        { id: "b", action: "ignore" },
      ],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("pass");
    expect(out.findings).toHaveLength(0);
  });

  test("warn-only carrier clamp: critical resource_content finding via non-matching policy → warn", () => {
    // Covers run-inner's `o === undefined → defaultActionForFinding(f)` clamp
    // line directly. A CRITICAL finding on a warn-only (retrieved-data) carrier
    // must degrade to `warn`, not re-block via a severity→action recompute.
    // The policy is non-empty (clears the early-return) but does NOT match the
    // finding's id, so the clamp branch runs. Reverting the clamp to the old
    // `severity==='critical'?'block'` recompute makes this assert "block" and fail.
    const result: InspectResult = {
      action: "warn",
      findings: [finding("res-crit", "critical", "resource_content")],
    };
    const policy: GuardPolicyFile = {
      signature_overrides: [{ id: "unrelated-id", action: "block" }],
    };
    const out = applyPolicy(result, policy);
    expect(out.action).toBe("warn");
    expect(out.findings).toHaveLength(1);
  });
});
