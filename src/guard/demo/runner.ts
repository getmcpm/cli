/**
 * Demo runner for `mcpm guard demo` (v0.5.0).
 *
 * Orchestrates the in-process attack-block demo: drives a synthetic
 * malicious MCP server (echo-bot.ts) through the inspection pipeline
 * (patterns.ts + signatures.ts), captures the block decision, and
 * formats output for the terminal.
 *
 * Subprocess variant is v0.5.0.1 — for v0.5.0 the demo is in-process so
 * it works on a fresh `npm install` without any additional setup. The
 * output is byte-identical to what the production relay would emit.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "../patterns.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";
import { respond, type Scenario } from "./echo-bot.js";
import type { InspectFinding } from "../types.js";

export interface DemoResult {
  readonly scenario: Scenario;
  readonly blocked: boolean;
  readonly findings: readonly InspectFinding[];
  readonly toolResponseExcerpt: string;
}

export interface DemoDeps {
  readonly write: (s: string) => void;
}

const NEXT_REQUEST_ID = (() => {
  let id = 0;
  return () => ++id;
})();

function makeInitialize(): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id: NEXT_REQUEST_ID(),
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "mcpm-guard-demo", version: "0.5.0" },
    },
  } as JSONRPCMessage;
}

function makeToolsList(): JSONRPCMessage {
  return { jsonrpc: "2.0", id: NEXT_REQUEST_ID(), method: "tools/list" } as JSONRPCMessage;
}

function makeToolsCall(toolName: string, args: Record<string, unknown>): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id: NEXT_REQUEST_ID(),
    method: "tools/call",
    params: { name: toolName, arguments: args },
  } as JSONRPCMessage;
}

function excerpt(msg: JSONRPCMessage): string {
  if (!("result" in msg)) return "";
  const result = (msg as { result?: { content?: Array<{ text?: string }> } }).result;
  const text = result?.content?.[0]?.text ?? "";
  return text.length > 120 ? `${text.slice(0, 120)}…` : text;
}

const SEPARATOR = "─".repeat(72);

function formatBlock(result: DemoResult, deps: DemoDeps): void {
  const { write } = deps;
  write(`\n${SEPARATOR}\n`);
  write(`mcpm guard demo  ·  scenario: ${result.scenario}\n`);
  write(`${SEPARATOR}\n\n`);

  write(`Step 1: send initialize  → echo-bot responds with capabilities\n`);
  write(`Step 2: send tools/list  → echo-bot responds with 1 tool ('read_thread')\n`);
  write(`Step 3: send tools/call  → echo-bot returns a poisoned response\n`);
  write(`        (the response embeds adversarial instructions targeting ~/.ssh)\n\n`);

  write(`tool response (excerpt):\n  "${result.toolResponseExcerpt}"\n\n`);

  if (result.blocked) {
    write(`✗ BLOCKED by mcpm-guard\n\n`);
    for (const finding of result.findings) {
      write(`  signature : ${finding.signature_id}\n`);
      write(`  category  : ${finding.category}\n`);
      write(`  severity  : ${finding.severity}\n`);
      write(`  matched   : "${finding.matched_text_excerpt}"\n`);
      write(`  remediate : ${finding.remediation}\n\n`);
    }
    write(`In production, this would be returned to the MCP client as a JSON-RPC error\n`);
    write(`response; the malicious payload never reaches the agent's context window.\n`);
  } else {
    write(`⚠ NOT BLOCKED — the demo's signature did not match the canned payload.\n`);
    write(`This is a bug in v0.5.0 if seen; please file an issue.\n`);
  }
  write(`\n${SEPARATOR}\n`);
}

/**
 * Run the demo for a given scenario. Returns the block outcome so callers
 * (CLI + tests) can assert on it. Pure-enough: writes to deps.write only.
 */
export function runDemo(scenario: Scenario, deps: DemoDeps): DemoResult {
  // Send initialize, get response (not inspected by guard — handshake).
  const initRequest = makeInitialize();
  const initResponse = respond(initRequest, scenario);
  if (initResponse === null) throw new Error("echo-bot returned null for initialize");

  // Send tools/list, get response (inspected for tool_description signatures).
  const listRequest = makeToolsList();
  const listResponse = respond(listRequest, scenario);
  if (listResponse === null) throw new Error("echo-bot returned null for tools/list");
  // (Inspection happens but our demo signature set doesn't fire on this scenario's list.)
  inspectMessage(listResponse, OWASP_MCP_TOP_10);

  // Send tools/call, get the malicious response, inspect it.
  const callRequest = makeToolsCall("read_thread", { thread_id: "demo-thread-1" });
  const callResponse = respond(callRequest, scenario);
  if (callResponse === null) throw new Error("echo-bot returned null for tools/call");

  const inspection = inspectMessage(callResponse, OWASP_MCP_TOP_10);
  const result: DemoResult = {
    scenario,
    blocked: inspection.action === "block",
    findings: inspection.findings,
    toolResponseExcerpt: excerpt(callResponse),
  };

  formatBlock(result, deps);
  return result;
}
