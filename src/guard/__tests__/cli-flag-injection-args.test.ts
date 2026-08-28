/**
 * TODOS #52 — cli-flag-injection-in-identifier-arg key classifier + detector tests.
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import {
  CLI_FLAG_INJECTION_ARG_SIGNATURE_ID,
  detectCliFlagInjectionArgs,
  isFlagInjectionScopedArgKey,
} from "../cli-flag-injection-args.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";

describe("isFlagInjectionScopedArgKey — namespace/id keys (name is deliberately excluded)", () => {
  const scoped = [
    "namespace", // CVE-2026-39884
    "id",
    "resource_id",
    "identifier",
    "uuid",
    "slug",
  ];
  for (const key of scoped) {
    test(`"${key}" is flag-injection-scoped`, () => expect(isFlagInjectionScopedArgKey(key)).toBe(true));
  }

  const notScoped = [
    "resourceName", // CVE-2026-39884's own PoC arg — excluded, see TODOS #57 (known gap)
    "resource_name",
    "name",
    "customer_name",
    "task_name",
    "flag_name", // compound *_name key that is itself a CLI-passthrough field
    "option_name",
    "script_name",
    "command", // meant to carry CLI-shaped text — out of scope
    "args",
    "config",
    "description",
    "message",
    "content",
    "query",
  ];
  for (const key of notScoped) {
    test(`"${key}" is NOT flag-injection-scoped`, () => expect(isFlagInjectionScopedArgKey(key)).toBe(false));
  }
});

const toolCall = (name: string, args: Record<string, unknown>): JSONRPCMessage =>
  ({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) as JSONRPCMessage;

describe("detectCliFlagInjectionArgs", () => {
  test("CVE-2026-39884 shape: an embedded --address flag in namespace → block", () => {
    const r = detectCliFlagInjectionArgs(toolCall("port_forward", { namespace: "default --address=0.0.0.0" }));
    expect(r.action).toBe("block");
    expect(r.findings[0]?.signature_id).toBe(CLI_FLAG_INJECTION_ARG_SIGNATURE_ID);
    expect(r.findings[0]?.target).toBe("tool_call_args");
  });

  test("an embedded flag with no '=value' (a bare --verbose) → block", () => {
    const r = detectCliFlagInjectionArgs(toolCall("port_forward", { namespace: "default --verbose" }));
    expect(r.action).toBe("block");
    expect(r.findings[0]?.matched_text_excerpt).toContain("namespace");
  });

  test("the advisory's own literal PoC via resourceName → pass (documented gap, TODOS #57)", () => {
    const r = detectCliFlagInjectionArgs(
      toolCall("port_forward", { resourceName: "my-database --address=0.0.0.0" }),
    );
    expect(r.action).toBe("pass");
  });

  test("a benign plain namespace → pass", () => {
    const r = detectCliFlagInjectionArgs(toolCall("port_forward", { namespace: "kube-system" }));
    expect(r.action).toBe("pass");
    expect(r.findings).toHaveLength(0);
  });

  test("a benign double-hyphen version-suffixed identifier → pass (no whitespace before --)", () => {
    const r = detectCliFlagInjectionArgs(toolCall("t", { resource_id: "svc--v2" }));
    expect(r.action).toBe("pass");
  });

  test("a benign UUID → pass", () => {
    const r = detectCliFlagInjectionArgs(toolCall("t", { uuid: "550e8400-e29b-41d4-a716-446655440000" }));
    expect(r.action).toBe("pass");
  });

  // The five false-positive shapes a pre-merge adversarial review reproduced
  // against an earlier version of this detector that included `name` in
  // scope — each is now excluded at the KEY-classification stage, before the
  // value pattern is ever tested. Kept as explicit regression tests, not just
  // key-classifier tests, so a future re-widening of the suffix set is caught
  // here even if the classifier tests are edited independently.
  describe("regression: five FP shapes a *_name-scoped design would have hard-blocked", () => {
    test("a ticket/PR/task title mentioning a flag by name → pass", () => {
      const r = detectCliFlagInjectionArgs(
        toolCall("create_task", { task_name: "Add --dry-run support to sync command" }),
      );
      expect(r.action).toBe("pass");
    });

    test("a compound *_name key that is itself a CLI-passthrough field → pass", () => {
      const r = detectCliFlagInjectionArgs(toolCall("run", { flag_name: "--dry-run" }));
      expect(r.action).toBe("pass");
    });

    test("a freeform cloud-resource Name tag with an appended operational note → pass", () => {
      const r = detectCliFlagInjectionArgs(toolCall("tag_resource", { resource_name: "prod-db-01 --do-not-delete" }));
      expect(r.action).toBe("pass");
    });

    test("npm's own documented '<script> -- <flags>' passthrough under a *_name key → pass", () => {
      const r = detectCliFlagInjectionArgs(toolCall("run_npm", { script_name: "test -- --coverage --watch" }));
      expect(r.action).toBe("pass");
    });

    test("a filesystem file_name containing descriptive text mentioning a flag → pass", () => {
      const r = detectCliFlagInjectionArgs(toolCall("write_file", { file_name: "notes on --verbose logging.md" }));
      expect(r.action).toBe("pass");
    });
  });

  test("a flag-shaped token in a NON-scoped key (command) → pass (key-scoping suppresses it)", () => {
    const r = detectCliFlagInjectionArgs(toolCall("run", { command: "kubectl get pods --address=0.0.0.0" }));
    expect(r.action).toBe("pass");
    expect(r.findings).toHaveLength(0);
  });

  test("nested one level deep (an options object) → block", () => {
    const r = detectCliFlagInjectionArgs(toolCall("t", { options: { namespace: "svc --address=0.0.0.0" } }));
    expect(r.action).toBe("block");
  });

  test("a batch-style array-of-objects argument is walked", () => {
    const r = detectCliFlagInjectionArgs(
      toolCall("batch_forward", { items: [{ namespace: "x --address=0.0.0.0" }] }),
    );
    expect(r.action).toBe("block");
    expect(r.findings[0]?.matched_text_excerpt).toContain("namespace");
  });

  test("a tools/list response (not a call) → pass (no-op)", () => {
    const r = detectCliFlagInjectionArgs({ jsonrpc: "2.0", id: 2, result: { tools: [] } } as JSONRPCMessage);
    expect(r.action).toBe("pass");
  });

  test("a tools/call request with no arguments → pass (no crash)", () => {
    const r = detectCliFlagInjectionArgs({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "t" },
    } as JSONRPCMessage);
    expect(r.action).toBe("pass");
  });
});

describe("catalog wiring", () => {
  test("cli-flag-injection-in-identifier-arg is in the catalog with empty patterns", () => {
    const entry = OWASP_MCP_TOP_10.find((s) => s.id === CLI_FLAG_INJECTION_ARG_SIGNATURE_ID);
    expect(entry).toBeDefined();
    expect(entry?.patterns).toHaveLength(0);
    expect(entry?.target).toBe("tool_call_args");
  });
});
