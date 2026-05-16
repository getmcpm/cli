/**
 * False-positive rate measurement against the legitimate-session corpus
 * (v0.5.0 Next Step 9, design-doc Success Criterion: FP rate < 2%).
 *
 * Loads every .jsonl session under fixtures/legitimate-corpus/, replays each
 * message through inspectMessage(), and:
 *   - per-session: asserts the session-local FP rate is below threshold
 *   - aggregate:   emits a structured FP-RATE-REPORT line that CI parses
 *                  and surfaces in release notes
 *
 * The seed corpus is 5 synthetic-but-realistic sessions modeled on real
 * MCP server behaviors (filesystem, github, slack, postgres, fetch).
 * Hard adversarial-benign cases are baked in (issue title contains "ignore",
 * documentation page ABOUT prompt injection, etc.) — if these false-positive,
 * the engine is too sensitive to ship.
 *
 * Refresh the corpus per design doc Reviewer Concern #11 / TODOS #29.
 */

import { describe, expect, test } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "../patterns.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";
import type { InspectFinding } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS_ROOT = path.join(__dirname, "fixtures", "legitimate-corpus");

// Design-doc Success Criterion: < 2% on the full top-20 corpus. The 5-session
// seed should comfortably hit 0% — any non-zero rate here indicates the engine
// false-positives on shapes that are unambiguously legitimate.
//
// NOTE on threshold resolution: with the 24-message seed, 1 FP = ~4% — so the
// 2% threshold is effectively a 0-tolerance gate on the seed (any single FP
// fails the test). The threshold becomes meaningful at corpus sizes ≥ 50.
// See TODOS #29 for the full 20-server corpus expansion.
const FP_RATE_THRESHOLD = 0.02;

interface SessionStats {
  readonly file: string;
  readonly totalMessages: number;
  readonly falsePositives: number;
  readonly fpRate: number;
  readonly triggeredSignatures: ReadonlyArray<{
    readonly message_id: string | number | null;
    readonly signature_id: string;
    readonly matched_text_excerpt: string;
  }>;
}

function parseJsonl(text: string): JSONRPCMessage[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => JSON.parse(line) as JSONRPCMessage);
}

function loadSessions(): { file: string; messages: JSONRPCMessage[] }[] {
  return readdirSync(CORPUS_ROOT)
    .filter((f) => f.endsWith(".jsonl"))
    .map((f) => ({
      file: f,
      messages: parseJsonl(readFileSync(path.join(CORPUS_ROOT, f), "utf8")),
    }));
}

function evaluateSession(file: string, messages: JSONRPCMessage[]): SessionStats {
  let falsePositives = 0;
  const triggered: { message_id: string | number | null; signature_id: string; matched_text_excerpt: string }[] = [];
  for (const msg of messages) {
    const result = inspectMessage(msg, OWASP_MCP_TOP_10);
    if (result.findings.length > 0) {
      falsePositives++;
      for (const f of result.findings) triggered.push(messageTriggerRecord(msg, f));
    }
  }
  return {
    file,
    totalMessages: messages.length,
    falsePositives,
    fpRate: messages.length > 0 ? falsePositives / messages.length : 0,
    triggeredSignatures: triggered,
  };
}

function messageTriggerRecord(
  msg: JSONRPCMessage,
  finding: InspectFinding,
): { message_id: string | number | null; signature_id: string; matched_text_excerpt: string } {
  const id = "id" in msg && (typeof msg.id === "string" || typeof msg.id === "number") ? msg.id : null;
  return {
    message_id: id,
    signature_id: finding.signature_id,
    matched_text_excerpt: finding.matched_text_excerpt,
  };
}

const sessions = loadSessions().map(({ file, messages }) => evaluateSession(file, messages));

describe(`FP-rate corpus (${sessions.length} sessions, ${sessions.reduce((n, s) => n + s.totalMessages, 0)} messages)`, () => {
  for (const session of sessions) {
    test(`${session.file}: FP rate ${(session.fpRate * 100).toFixed(2)}% (${session.falsePositives}/${session.totalMessages})`, () => {
      const failureDetail = session.triggeredSignatures
        .map((t) => `  msg #${t.message_id}: ${t.signature_id} — "${t.matched_text_excerpt}"`)
        .join("\n");
      expect(
        session.fpRate,
        `expected FP rate < ${FP_RATE_THRESHOLD * 100}% in ${session.file}, got ${(session.fpRate * 100).toFixed(2)}%:\n${failureDetail}`,
      ).toBeLessThan(FP_RATE_THRESHOLD);
    });
  }

  test("aggregate FP rate across the corpus is below threshold", () => {
    const total = sessions.reduce((n, s) => n + s.totalMessages, 0);
    const fp = sessions.reduce((n, s) => n + s.falsePositives, 0);
    const aggregate = total > 0 ? fp / total : 0;
    // Emit the structured line CI parses + surfaces in release notes.
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({
      fp_rate_report: "v0.5.0",
      sessions: sessions.length,
      total_messages: total,
      false_positives: fp,
      fp_rate: aggregate,
      threshold: FP_RATE_THRESHOLD,
      per_session: sessions.map((s) => ({
        file: s.file,
        total: s.totalMessages,
        fp: s.falsePositives,
        rate: s.fpRate,
      })),
    }));
    expect(aggregate).toBeLessThan(FP_RATE_THRESHOLD);
  });
});
