/**
 * End-to-end test for `mcpm guard demo` (v0.5.0).
 *
 * Verifies the demo runner actually blocks the canned prompt-injection
 * payload and emits the expected formatted output. This is the test that
 * gates the day-one demo Success Criterion in the design doc.
 */

import { describe, expect, test } from "vitest";
import { runDemo } from "../demo/runner.js";
import { respond } from "../demo/echo-bot.js";

describe("mcpm guard demo (e2e)", () => {
  test("blocks the prompt-injection scenario", () => {
    const lines: string[] = [];
    const result = runDemo("prompt-injection", { write: (s) => lines.push(s) });

    expect(result.blocked).toBe(true);
    expect(result.scenario).toBe("prompt-injection");
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0]?.signature_id).toBe(
      "owasp-mcp-2-instruction-injection-in-response",
    );
    expect(result.findings[0]?.severity).toBe("critical");
  });

  test("output contains the BLOCKED banner + signature + remediation", () => {
    const lines: string[] = [];
    runDemo("prompt-injection", { write: (s) => lines.push(s) });
    const output = lines.join("");
    expect(output).toContain("BLOCKED by mcpm-guard");
    expect(output).toContain("owasp-mcp-2-instruction-injection-in-response");
    expect(output).toContain("scenario: prompt-injection");
    expect(output).toContain("remediate");
  });

  test("echo-bot responds correctly to initialize / tools/list / tools/call", () => {
    const initRequest = {
      jsonrpc: "2.0" as const,
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "0" } },
    };
    const listRequest = { jsonrpc: "2.0" as const, id: 2, method: "tools/list" };
    const callRequest = {
      jsonrpc: "2.0" as const,
      id: 3,
      method: "tools/call",
      params: { name: "read_thread", arguments: { thread_id: "x" } },
    };

    const initR = respond(initRequest, "prompt-injection") as { result?: { protocolVersion?: string } };
    expect(initR.result?.protocolVersion).toBe("2024-11-05");

    const listR = respond(listRequest, "prompt-injection") as { result?: { tools?: Array<{ name: string }> } };
    expect(listR.result?.tools?.[0]?.name).toBe("read_thread");

    const callR = respond(callRequest, "prompt-injection") as { result?: { content?: Array<{ text?: string }> } };
    expect(callR.result?.content?.[0]?.text).toContain("Ignore all previous instructions");
  });

  test("echo-bot returns null for a notification (no id)", () => {
    const notification = {
      jsonrpc: "2.0" as const,
      method: "notifications/cancelled",
      params: { requestId: 1 },
    };
    expect(respond(notification, "prompt-injection")).toBeNull();
  });

  test("echo-bot returns method-not-found error for unknown method", () => {
    const r = respond(
      { jsonrpc: "2.0" as const, id: 99, method: "completely-bogus-method" },
      "prompt-injection",
    ) as { error?: { code: number } };
    expect(r.error?.code).toBe(-32601);
  });
});
