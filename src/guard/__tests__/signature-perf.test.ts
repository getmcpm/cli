/**
 * Wall-clock regressions for the ReDoS rewrites in `signatures.ts` (#113).
 *
 * Each input below cost 0.6-3 s per leaf through `guard inspect` before #113
 * (Node 24.20.0, built binary, CLI start-up subtracted). They run through the
 * PUBLIC path (`inspectMessage`, every catalog signature) so a change to how
 * signatures are invoked stays covered. The 250 ms bound leaves wide headroom
 * over the post-fix cost (tens of ms at most) because CI has flaked on tight
 * wall-clock asserts before ("314 to be less than 300").
 */
import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "../patterns.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";

const BOUND_MS = 250;

function inspectMs(text: string): number {
  const msg = {
    jsonrpc: "2.0",
    id: 1,
    result: { content: [{ type: "text", text }], isError: false },
  } as JSONRPCMessage;
  const t0 = process.hrtime.bigint();
  inspectMessage(msg, OWASP_MCP_TOP_10);
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

describe("signature-perf (#113): pathological 32-64 KB leaves inspect in well under 250 ms", () => {
  test.each([
    // Kept just under the 32 KB head/tail split in normalizeForMatch, so the
    // "Bearer" prefix and the trailing "..." reach the regex in one piece.
    ["generic-bearer: an all-digit token ending in '...' (was ~2.9 s)", "Bearer " + "1".repeat(32750) + "..."],
    // NFKC runs AFTER the window is cut and folds U+249B to "20.", so the regex
    // is handed a 96,000-char token here, not 32 KB.
    ["generic-bearer: 32,000 x U+249B, tripled by NFKC (was ~16 s)", "Bearer " + "⒛".repeat(32000) + "…"],
    ["renderer shape 1: one tag, 2400 handlers, no '>' (was ~2.3 s)", "<a" + " onx=electron.mcp.activate(".repeat(2400)],
    ["renderer shape 1: a 64 KB hyphenated tag name (was ~1.1 s)", "<a" + "-a".repeat(32000)],
    ["renderer shape 2: '<script ' x 8000, no '>' (was ~0.74 s)", "<script ".repeat(8000)],
    ['renderer shape 2: \'<script "\' x 7000 (was ~0.6 s)', '<script "'.repeat(7000)],
  ])("%s", (_name, text) => {
    expect(inspectMs(text)).toBeLessThan(BOUND_MS);
  });
});
