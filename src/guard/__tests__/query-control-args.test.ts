/**
 * TODOS #51 — query-control-syntax-in-identifier-arg key classifier + detector tests.
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import {
  detectQueryControlArgs,
  isQueryScopedArgKey,
  QUERY_CONTROL_ARG_SIGNATURE_ID,
} from "../query-control-args.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";

describe("isQueryScopedArgKey — resource-noun / scalar-id keys (zero-FP on display names)", () => {
  const scoped = [
    "table_name", // CVE-2026-33980
    "tableName", // camelCase
    "table",
    "column_name",
    "field",
    "collection",
    "database",
    "schema",
    "index",
    "view",
    "dataset",
    "resource_id",
    "identifier",
    "uuid",
    "slug",
  ];
  for (const key of scoped) {
    test(`"${key}" is query-scoped`, () => expect(isQueryScopedArgKey(key)).toBe(true));
  }

  const notScoped = [
    "query", // meant to carry query syntax — out of scope
    "filter",
    "kql",
    "customer_name", // "name" alone stays excluded, same as #50
    "user_name",
    "name",
    "description",
    "message",
    "content",
    "grid", // single token, not a resource noun
  ];
  for (const key of notScoped) {
    test(`"${key}" is NOT query-scoped`, () => expect(isQueryScopedArgKey(key)).toBe(false));
  }
});

const toolCall = (name: string, args: Record<string, unknown>): JSONRPCMessage =>
  ({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) as JSONRPCMessage;

describe("detectQueryControlArgs", () => {
  test("CVE-2026-33980 shape: pipe re-scoping + trailing comment in table_name → block", () => {
    const r = detectQueryControlArgs(
      toolCall("get_table_schema", {
        table_name: "sensitive_data | project Secret, Password | take 100 //",
      }),
    );
    expect(r.action).toBe("block");
    expect(r.findings[0]?.signature_id).toBe(QUERY_CONTROL_ARG_SIGNATURE_ID);
    expect(r.findings[0]?.target).toBe("tool_call_args");
  });

  test("CVE-2026-33980 sibling shape: newline + .drop table → block", () => {
    const r = detectQueryControlArgs(
      toolCall("sample_table_data", { table_name: "mytable\n.drop table dropped_table" }),
    );
    expect(r.action).toBe("block");
    expect(r.findings[0]?.matched_text_excerpt).toContain("table_name");
  });

  test(";DROP statement-separator shape in a table key → block", () => {
    const r = detectQueryControlArgs(toolCall("t", { table: "orders;DROP TABLE orders" }));
    expect(r.action).toBe("block");
  });

  test("a benign simple table name → pass", () => {
    const r = detectQueryControlArgs(toolCall("get_table_schema", { table_name: "customers" }));
    expect(r.action).toBe("pass");
    expect(r.findings).toHaveLength(0);
  });

  test("a benign dot-namespaced table identifier → pass", () => {
    const r = detectQueryControlArgs(toolCall("get_table_schema", { table_name: "Security.SigninLogs" }));
    expect(r.action).toBe("pass");
  });

  test("a benign hyphenated database name → pass", () => {
    const r = detectQueryControlArgs(toolCall("t", { database: "prod-analytics-2026" }));
    expect(r.action).toBe("pass");
  });

  test("a benign MongoDB connection-string database value → pass (:// is a URI scheme, not a comment)", () => {
    const r = detectQueryControlArgs(toolCall("t", { database: "mongodb://localhost:27017/mydb" }));
    expect(r.action).toBe("pass");
  });

  test("a benign HTTPS storage-account database URI → pass (:// is a URI scheme, not a comment)", () => {
    const r = detectQueryControlArgs(
      toolCall("t", { database: "https://acct.blob.core.windows.net/container" }),
    );
    expect(r.action).toBe("pass");
  });

  test("a benign double-hyphen version-suffixed database name → pass (no whitespace before --)", () => {
    const r = detectQueryControlArgs(toolCall("t", { database: "analytics--eu-west" }));
    expect(r.action).toBe("pass");
  });

  test("query-control syntax in a NON-scoped key (query) → pass (key-scoping suppresses it)", () => {
    const r = detectQueryControlArgs(
      toolCall("run_query", { query: "sensitive_data | project Secret | take 100 //" }),
    );
    expect(r.action).toBe("pass");
    expect(r.findings).toHaveLength(0);
  });

  test("a display name containing '--' → pass (name deliberately excluded)", () => {
    const r = detectQueryControlArgs(toolCall("create_customer", { customer_name: "Acme -- Corp" }));
    expect(r.action).toBe("pass");
  });

  test("a bare pipe with no query verb in a table key → pass (FP-risk guard)", () => {
    const r = detectQueryControlArgs(toolCall("t", { table_name: "orders|archive" }));
    expect(r.action).toBe("pass");
  });

  test("nested one level deep (an options object) → block", () => {
    const r = detectQueryControlArgs(toolCall("t", { options: { column_name: "id; DROP TABLE users" } }));
    expect(r.action).toBe("block");
  });

  test("a batch-style array-of-objects argument is walked", () => {
    const r = detectQueryControlArgs(
      toolCall("batch_get_schema", { items: [{ table_name: "x; DROP TABLE x" }] }),
    );
    expect(r.action).toBe("block");
    expect(r.findings[0]?.matched_text_excerpt).toContain("table_name");
  });

  test("a tools/list response (not a call) → pass (no-op)", () => {
    const r = detectQueryControlArgs({ jsonrpc: "2.0", id: 2, result: { tools: [] } } as JSONRPCMessage);
    expect(r.action).toBe("pass");
  });

  test("a tools/call request with no arguments → pass (no crash)", () => {
    const r = detectQueryControlArgs({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "t" },
    } as JSONRPCMessage);
    expect(r.action).toBe("pass");
  });
});

// ───────────────────────── TODOS #55 — TAG-block decode-and-rescan ─────────────────────────

/** Encode ASCII into the tag block: U+E0020–U+E007E mirror 0x20–0x7E. */
const tag = (s: string): string =>
  [...s].map((c) => String.fromCodePoint((c.codePointAt(0) ?? 0) + 0xe0000)).join("");

describe("TAG-block decode-and-rescan (TODOS #55)", () => {
  test("a TAG-concealed pipe-rescope payload in table_name → block", () => {
    const r = detectQueryControlArgs(
      toolCall("get_table_schema", { table_name: `sensitive_data${tag(" | project Secret")}` }),
    );
    expect(r.action).toBe("block");
    expect(r.findings[0]?.signature_id).toBe(QUERY_CONTROL_ARG_SIGNATURE_ID);
    expect(r.findings[0]?.matched_text_excerpt).toContain("table_name");
    expect(r.findings[0]?.matched_text_excerpt).toContain("decoded:unicode-tag");
  });

  test("a concealed payload in a NON-scoped key (query) still passes", () => {
    const r = detectQueryControlArgs(toolCall("run_query", { query: tag(" | project Secret") }));
    expect(r.action).toBe("pass");
  });

  test("a benign hyphenated database name with an unrelated tag character → pass", () => {
    const scotlandFlag = `${"\u{1F3F4}"}${tag("gbsct")}${"\u{E007F}"}`;
    const r = detectQueryControlArgs(toolCall("t", { database: `prod-${scotlandFlag}-eu-west` }));
    expect(r.action).toBe("pass");
  });

  test("a benign table name with no tag characters is unaffected", () => {
    const r = detectQueryControlArgs(toolCall("get_table_schema", { table_name: "customers" }));
    expect(r.action).toBe("pass");
  });

  test("a visible query-control match AND a separately-concealed one are BOTH reported", () => {
    const r = detectQueryControlArgs(
      toolCall("t", { table: `orders;DROP TABLE orders${tag(" | project Secret")}` }),
    );
    expect(r.action).toBe("block");
    expect(r.findings.length).toBeGreaterThanOrEqual(2);
    expect(r.findings.some((f) => f.matched_text_excerpt.includes("decoded:unicode-tag"))).toBe(true);
  });
});

describe("catalog wiring", () => {
  test("query-control-syntax-in-identifier-arg is in the catalog with empty patterns", () => {
    const entry = OWASP_MCP_TOP_10.find((s) => s.id === QUERY_CONTROL_ARG_SIGNATURE_ID);
    expect(entry).toBeDefined();
    expect(entry?.patterns).toHaveLength(0);
    expect(entry?.target).toBe("tool_call_args");
  });
});
