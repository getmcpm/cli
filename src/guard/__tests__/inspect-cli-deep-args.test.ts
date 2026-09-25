/**
 * #104 — `mcpm guard inspect --json` used to ABORT the whole NDJSON run when
 * one frame's `tools/call` argument was nested deep enough in arrays to
 * overflow `stringArgLeaves`' old recursive walk: the verdict for frame 1
 * printed, then `Error: Maximum call stack size exceeded` and exit 1, with NO
 * verdict at all for frame 3 — violating the CLI's own documented contract
 * (`src/guard/inspect-cli.ts`'s header: one verdict per input frame, in input
 * order, and an unparseable/failing frame must read as "error", never as a
 * silent drop of everything after it).
 *
 * Two independent fixes are pinned separately, matching the two root causes:
 *   1. `stringArgLeaves` is now iterative (tool-call-args-walk.test.ts pins
 *      that directly) — so the reproduction below no longer throws at all,
 *      and this file pins the end-to-end NDJSON-stream behavior.
 *   2. `runInspectCommand` now wraps `inspectFrame` in a try/catch, so even an
 *      UNRELATED future throw from any other detector fails closed on just
 *      that one frame instead of losing every frame after it — pinned here by
 *      forcing `inspectFrame` itself to throw via a mock, independent of the
 *      depth fix.
 */

import { describe, expect, test, vi } from "vitest";

function verdictLines(out: string): Array<Record<string, unknown>> {
  return out
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe("guard inspect — a deeply nested tools/call argument (#104 reproduction)", () => {
  // Builds the FRAME'S JSON TEXT directly (string concatenation), the same
  // way the backlog #104 reproduction script does — NOT by JSON.stringify-ing
  // a JS value that already contains the deep nesting, which would just
  // reproduce the crash inside the test itself (`JSON.stringify` overflows
  // its own recursive path well before 50,000 levels; see
  // tool-call-args-walk.test.ts's module comment for the measured threshold).
  function deepToolsCallFrameText(id: number, depth: number): string {
    const argJson = "[".repeat(depth) + JSON.stringify("x") + "]".repeat(depth);
    return `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":"t","arguments":{"items":${argJson}}}}`;
  }

  test("3 frames in (ok, deeply-nested-array-arg, ok) yield 3 verdicts, in order, none lost", async () => {
    const { runInspectCommand } = await import("../inspect-cli.js");

    const ok1 = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "t", arguments: { name: "safe" } },
    });
    // The exact reproduction shape from backlog #104: an "items" argument
    // wrapped in 50,000 nested arrays around a single string leaf. "items"
    // does not canonicalize to an identifier-suffix key, so none of the three
    // structural arg detectors would flag it even if they could look — the
    // point here is only that looking at it must not crash the run.
    const deep = deepToolsCallFrameText(2, 50_000);
    const ok3 = JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "t", arguments: { name: "safe" } },
    });

    const source = [ok1, deep, ok3].join("\n");
    let out = "";
    const result = runInspectCommand({ source, json: true, write: (s) => (out += s) });

    const lines = verdictLines(out);
    expect(lines).toHaveLength(3);
    // None of the three frames carries an actual attack, and inspection now
    // completes on all three instead of crashing after the first.
    expect(lines.map((l) => l.action)).toEqual(["pass", "pass", "pass"]);
    expect(result).toEqual({ action: "pass", errors: 0, frames: 3 });
  });

  test("the same reproduction terminates promptly", async () => {
    const { runInspectCommand } = await import("../inspect-cli.js");

    const start = Date.now();
    runInspectCommand({ source: deepToolsCallFrameText(2, 50_000), json: true, write: () => {} });
    expect(Date.now() - start).toBeLessThan(5_000);
  });
});

describe("guard inspect — a detector throwing on one frame (backstop, independent of the depth fix)", () => {
  test("an inspectFrame throw yields an error verdict for THAT frame only; the run keeps going", async () => {
    vi.resetModules();
    vi.doMock("../inspect-frame.js", () => ({
      inspectFrame: (msg: { id?: number }) => {
        if (msg.id === 2) throw new Error("synthetic detector crash");
        return { action: "pass", findings: [] };
      },
    }));

    const { runInspectCommand } = await import("../inspect-cli.js");

    const frames = [
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 2, result: {} },
      { jsonrpc: "2.0", id: 3, result: {} },
    ];
    const source = frames.map((f) => JSON.stringify(f)).join("\n");
    let out = "";
    const result = runInspectCommand({ source, json: true, write: (s) => (out += s) });

    const lines = verdictLines(out);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toEqual({ action: "pass", findings: [] });
    expect(lines[1].action).toBe("error");
    expect(lines[1].error).toBe("inspection failed: synthetic detector crash");
    expect(lines[2]).toEqual({ action: "pass", findings: [] });

    // Counts like a parse error: contributes to `errors`, not to the pass/warn/block tally.
    expect(result).toEqual({ action: "pass", errors: 1, frames: 3 });

    vi.doUnmock("../inspect-frame.js");
    vi.resetModules();
  });

  test("human output reports the inspection failure visibly, sanitized, without aborting", async () => {
    vi.resetModules();
    vi.doMock("../inspect-frame.js", () => ({
      inspectFrame: () => {
        throw new Error("synthetic detector crash");
      },
    }));

    const { runInspectCommand } = await import("../inspect-cli.js");

    let out = "";
    const result = runInspectCommand({
      source: JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }),
      json: false,
      write: (s) => (out += s),
    });

    expect(out).toMatch(/error/i);
    expect(out).toContain("synthetic detector crash");
    expect(result).toEqual({ action: "pass", errors: 1, frames: 1 });

    vi.doUnmock("../inspect-frame.js");
    vi.resetModules();
  });
});
