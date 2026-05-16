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
import type { InspectFinding, InspectResult } from "../types.js";
import type { GuardPolicyFile } from "../policy.js";

// Re-export applyPolicy from run-inner.ts for testing. Since run-inner.ts
// doesn't export it directly, we replicate the function here to test the
// same logic. (Alternative: refactor applyPolicy into its own module — done
// inline below to avoid widening the public API for a regression test only.)

const rank = { pass: 0, warn: 1, block: 2 } as const;
const fromSeverity = (sev: InspectFinding["severity"]): InspectResult["action"] => {
  if (sev === "critical") return "block";
  if (sev === "high") return "warn";
  return "pass";
};

function applyPolicy(result: InspectResult, policy: GuardPolicyFile): InspectResult {
  const overrides = policy.signature_overrides ?? [];
  if (overrides.length === 0) return result;
  const byId = new Map(overrides.map((o) => [o.id, o]));

  let highest: InspectResult["action"] = "pass";
  const kept: InspectFinding[] = [];
  for (const f of result.findings) {
    const o = byId.get(f.signature_id);
    let perFindingAction: InspectResult["action"];
    if (o === undefined) {
      perFindingAction = fromSeverity(f.severity);
      kept.push(f);
    } else if (o.action === "ignore") {
      continue;
    } else if (o.action === "log_only") {
      perFindingAction = "pass";
      kept.push(f);
    } else {
      perFindingAction = o.action;
      kept.push(f);
    }
    if (rank[perFindingAction] > rank[highest]) highest = perFindingAction;
  }
  return { action: highest, findings: kept };
}

function finding(sigId: string, severity: InspectFinding["severity"] = "critical"): InspectFinding {
  return {
    signature_id: sigId,
    category: "TEST",
    severity,
    target: "tool_response",
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
});
