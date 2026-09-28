/**
 * Wall-clock regressions for the three ReDoS fixes in `signatures.ts` (#113).
 *
 * Each shape here took SECONDS on the pre-fix regex (measured on the bare
 * regex, outside this suite, before the fix landed):
 *   - generic-bearer-token-disclosure: 4.40s at 32,700 chars
 *   - renderer-code-execution-in-response, shape 1 (attribute): 3.64s at 70KB
 *   - renderer-code-execution-in-response, shape 2 (<script>): ~1.0s at 64KB
 *
 * These run through the PUBLIC path (`inspectMessage`), not the bare regex,
 * so a future change to how signatures are invoked (a new wrapper, an added
 * normalization pass) stays covered. The bound is 250ms — large headroom over
 * the ~1-70ms this repo's own measurements show post-fix, because CI has
 * flaked on tight wall-clock asserts before (this project's own history: "314
 * to be less than 300").
 */
import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "../patterns.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";

const BOUND_MS = 250;

function toolResponse(text: string): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text }], isError: false },
  } as JSONRPCMessage;
}

function timeInspect(text: string): number {
  const msg = toolResponse(text);
  const t0 = process.hrtime.bigint();
  inspectMessage(msg, OWASP_MCP_TOP_10);
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / 1e6;
}

describe("signature-perf: generic-bearer-token-disclosure", () => {
  test("a 32,700-char token with no digit-boundary (the pre-fix pathological shape) inspects in well under 250ms", () => {
    const text = "Bearer " + "1".repeat(32700) + "...";
    const ms = timeInspect(text);
    expect(ms).toBeLessThan(BOUND_MS);
  });

  // `normalizeForMatch` windows any leaf over 32KB into a head+tail pair
  // joined by a NUL seam (MATCH_SEGMENT_CAP, patterns.ts) BEFORE any signature
  // runs, so a single continuous pathological run can reach at most ~32KB
  // (not the full 64KB window) before this signature ever sees it — a 64KB
  // input built the same way as the 32,700-char case above is actually FASTER
  // through `inspectMessage`, because the seam splits the "Bearer" prefix from
  // the trailing "..." into different segments and neither half alone is the
  // pathological shape. This test instead sits just under that 32KB split
  // point, the true worst case for this pattern.
  test("the same pathological shape just under the 32KB single-segment ceiling inspects in well under 250ms", () => {
    const text = "Bearer " + "1".repeat(32750) + "...";
    const ms = timeInspect(text);
    expect(ms).toBeLessThan(BOUND_MS);
  });
});

describe("signature-perf: renderer-code-execution-in-response, attribute shape", () => {
  test('"<a" + " onx=electron.mcp.activate(".repeat(1200), no closing \'>\' inspects in well under 250ms', () => {
    const text = "<a" + " onx=electron.mcp.activate(".repeat(1200);
    const ms = timeInspect(text);
    expect(ms).toBeLessThan(BOUND_MS);
  });

  test("the same shape scaled to the 64KB leaf window inspects in well under 250ms", () => {
    const text = "<a" + " onx=electron.mcp.activate(".repeat(2400);
    const ms = timeInspect(text);
    expect(ms).toBeLessThan(BOUND_MS);
  });
});

describe("signature-perf: renderer-code-execution-in-response, <script> shape", () => {
  test('"<script ".repeat(8000) (64KB, no closing \'>\') inspects in well under 250ms', () => {
    const text = "<script ".repeat(8000);
    const ms = timeInspect(text);
    expect(ms).toBeLessThan(BOUND_MS);
  });
});

describe("signature-perf: renderer-code-execution-in-response, mermaid/echarts fence shape (already fast, unchanged)", () => {
  test("backtick spam plus near-miss electron.mcp text inspects in well under 250ms", () => {
    const text = "```mermaid " + "electron.mcp.x(".repeat(4000);
    const ms = timeInspect(text);
    expect(ms).toBeLessThan(BOUND_MS);
  });
});
