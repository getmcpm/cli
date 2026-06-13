/**
 * Tests for run-inner.ts fail-safe loading + the SECURITY F3 same-session
 * drift guard.
 *
 *  - Fix 2: a pins-read error (PinsIntegrityError / I/O) must FAIL CLOSED —
 *    write a PINS-READ-ERROR to stderr and process.exit(1) rather than start
 *    the relay with rug-pull protection silently off.
 *  - Fix 3: a PolicyIntegrityError must be surfaced on stderr before falling
 *    back to the safe `{}` policy (full enforcement).
 *  - Fix 2 (MED): a generic non-ENOENT policy read error (EACCES/EMFILE) must
 *    be surfaced as POLICY-READ-ERROR before the same safe `{}` fallback.
 *  - Fix 7a: inspectForDriftSync's same-session guard (SECURITY F3).
 */

import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectForDriftSync, isToolsListChangedNotification, type SessionDriftState } from "../run-inner.js";
import {
  hashToolDefinition,
  fieldHashesOf,
  emptyPinsFile,
  upsertToolPin,
  type PinsFile,
} from "../pins.js";

// ──────────────────────── helpers ────────────────────────

const toolsListMsg = (
  toolName: string,
  description: string,
  extra: { inputSchema?: unknown; annotations?: unknown } = {},
): JSONRPCMessage =>
  ({
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: toolName, description, ...extra }] },
  }) as JSONRPCMessage;

const freshState = (): SessionDriftState => ({
  firstHashes: new Map<string, string>(),
  revalidationArmed: false,
});

// ─────────────── Fix 7a: same-session drift guard (SECURITY F3) ───────────────

describe("inspectForDriftSync — same-session guard (SECURITY F3)", () => {
  test("first tools/list passes and records its hash; second matching hash passes", () => {
    const pins = emptyPinsFile();
    const state = freshState();

    const first = inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    expect(first.action).toBe("pass");
    // The hash was recorded for the (server, tool) pair.
    expect(state.firstHashes.get("srv::read")).toBe(hashToolDefinition({ description: "v1" }));

    const secondSame = inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    expect(secondSame.action).toBe("pass");
  });

  test("a second tools/list with a DIFFERENT hash in the same session blocks", () => {
    const pins = emptyPinsFile();
    const state = freshState();

    inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    const drifted = inspectForDriftSync(toolsListMsg("read", "v2-POISONED"), "srv", pins, state);

    expect(drifted.action).toBe("block");
    expect(drifted.findings).toHaveLength(1);
    expect(drifted.findings[0]?.signature_id).toBe("schema-drift-in-session");
  });

  test("two different server names are independent (no cross-server bleed)", () => {
    const pins = emptyPinsFile();
    const state = freshState();

    inspectForDriftSync(toolsListMsg("read", "v1"), "alpha", pins, state);
    // beta sends a different schema for the same tool name — must NOT block,
    // because the session key is namespaced by server name.
    const beta = inspectForDriftSync(toolsListMsg("read", "totally-different"), "beta", pins, state);
    expect(beta.action).toBe("pass");
    expect(state.firstHashes.get("alpha::read")).toBeDefined();
    expect(state.firstHashes.get("beta::read")).toBeDefined();
  });
});

// ─────────────── H4: list_changed re-validation arm + tiered drift ───────────────

describe("inspectForDriftSync — H4 tiered drift against a pin", () => {
  // Pin against the SAME normalized fields the runtime will derive from the
  // tools/list frame (it reads inputSchema as the schema field).
  const pinnedForTool = (
    description: string,
    inputSchema?: unknown,
    annotations?: unknown,
  ): PinsFile => {
    const fields = { description, schema: inputSchema, annotations };
    return upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: hashToolDefinition(fields),
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: fieldHashesOf(fields),
    });
  };

  test("description-only drift vs pin → WARN (schema-drift-cosmetic)", () => {
    const pins = pinnedForTool("old", { type: "object" });
    const state = freshState();
    const msg = toolsListMsg("read", "new wording", { inputSchema: { type: "object" } });
    const result = inspectForDriftSync(msg, "srv", pins, state);
    expect(result.action).toBe("warn");
    expect(result.findings[0]?.signature_id).toBe("schema-drift-cosmetic");
    expect(result.findings[0]?.matched_text_excerpt).toContain("description");
  });

  test("schema drift vs pin → BLOCK (schema-drift)", () => {
    const pins = pinnedForTool("d", { type: "object" });
    const state = freshState();
    const msg = toolsListMsg("read", "d", { inputSchema: { type: "string" } });
    const result = inspectForDriftSync(msg, "srv", pins, state);
    expect(result.action).toBe("block");
    expect(result.findings[0]?.signature_id).toBe("schema-drift");
  });
});

describe("inspectForDriftSync — single-shot re-validation arm", () => {
  test("when armed, an in-session schema change is NOT F3-blocked, but classified vs pin", () => {
    // Pin description="old"; same-session first list seeds description="v1".
    const pins = pinnedFor("old");
    const state = freshState();
    // Seed the same-session hash with the first list.
    inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    // Arm re-validation (as a list_changed notification would).
    state.revalidationArmed = true;
    // A different description arrives → would normally F3-block; armed lets it
    // through F3 and classifies against the pin (description-only → cosmetic warn).
    const result = inspectForDriftSync(toolsListMsg("read", "v2-rebaselined"), "srv", pins, state);
    expect(result.findings.some((f) => f.signature_id === "schema-drift-in-session")).toBe(false);
    expect(result.action).toBe("warn");
    expect(result.findings[0]?.signature_id).toBe("schema-drift-cosmetic");
    // The arm was consumed (single-shot).
    expect(state.revalidationArmed).toBe(false);
  });

  test("single-shot: a SECOND changed frame after consuming the arm reverts to F3 block", () => {
    const pins = emptyPinsFile();
    const state = freshState();
    inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    state.revalidationArmed = true;
    // First changed frame consumes the arm (rebaselines, no F3 block).
    const first = inspectForDriftSync(toolsListMsg("read", "v2"), "srv", pins, state);
    expect(first.findings.some((f) => f.signature_id === "schema-drift-in-session")).toBe(false);
    // Second changed frame in the same chunk → arm already consumed → F3 block.
    const second = inspectForDriftSync(toolsListMsg("read", "v3-POISON"), "srv", pins, state);
    expect(second.action).toBe("block");
    expect(second.findings[0]?.signature_id).toBe("schema-drift-in-session");
  });

  test("no preceding list_changed: a changed second list is still F3-blocked (unchanged)", () => {
    const pins = emptyPinsFile();
    const state = freshState();
    inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    const drifted = inspectForDriftSync(toolsListMsg("read", "v2-POISON"), "srv", pins, state);
    expect(drifted.action).toBe("block");
    expect(drifted.findings[0]?.signature_id).toBe("schema-drift-in-session");
  });

  function pinnedFor(description: string): PinsFile {
    return upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: hashToolDefinition({ description }),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: fieldHashesOf({ description }),
    });
  }
});

// ─────────────── Fix 2 + 3: fail-safe loading in runInner ───────────────

describe("runInner fail-safe loading", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
      throw new Error("__EXIT__");
    }) as never);
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    stderrSpy.mockRestore();
    vi.resetModules();
    vi.doUnmock("../pins.js");
    vi.doUnmock("../policy.js");
  });

  const runInnerArgs = {
    serverName: "victim",
    command: "true",
    args: [] as string[],
    declaredEnvKeys: [] as string[],
  };

  test("Fix 2: a pins-read error fails closed (PINS-READ-ERROR + exit 1)", async () => {
    vi.resetModules();
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return {
        ...actual,
        readPins: async () => {
          throw new actual.PinsIntegrityError("tampered sidecar");
        },
      };
    });

    const { runInner } = await import("../run-inner.js");
    await expect(runInner(runInnerArgs)).rejects.toThrow("__EXIT__");
    expect(exitSpy).toHaveBeenCalledWith(1);
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] PINS-READ-ERROR:");
    expect(stderr).toContain("guard-events.jsonl");
    expect(stderr).toContain("mcpm guard reset-integrity");
  });

  test("H9: pins structural corruption (generic Error) also fails closed (exit 1)", async () => {
    vi.resetModules();
    // A non-PinsIntegrityError (e.g. Zod-shape failure / corrupt JSON) thrown by
    // readPins must ALSO fail closed — refusing to start the relay with drift
    // protection silently off. Pins exits (unlike policy, whose {} fallback is
    // the safe state); an empty pins snapshot is the UNSAFE state.
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return {
        ...actual,
        readPins: async () => {
          throw new Error("pins.json has an invalid structure: servers: Expected object");
        },
      };
    });

    const { runInner } = await import("../run-inner.js");
    await expect(runInner(runInnerArgs)).rejects.toThrow("__EXIT__");
    expect(exitSpy).toHaveBeenCalledWith(1);
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] PINS-READ-ERROR:");
  });

  test("Fix 3: a PolicyIntegrityError is surfaced on stderr, then falls back to {}", async () => {
    vi.resetModules();
    // pins reads fine (empty), so the relay would otherwise proceed.
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return { ...actual, readPins: async (): Promise<PinsFile> => actual.emptyPinsFile() };
    });
    // Policy read throws a PolicyIntegrityError.
    vi.doMock("../policy.js", async () => {
      const actual = await vi.importActual<typeof import("../policy.js")>("../policy.js");
      return {
        ...actual,
        readPolicy: async () => {
          throw new actual.PolicyIntegrityError("guard-policy.yaml integrity check failed");
        },
      };
    });
    // Avoid spawning a real subprocess: stub the relay to resolve immediately.
    vi.doMock("../relay.js", async () => {
      const actual = await vi.importActual<typeof import("../relay.js")>("../relay.js");
      return {
        ...actual,
        startRelay: () => ({ child: {} as never, exit: Promise.resolve(0) }),
      };
    });

    const { runInner } = await import("../run-inner.js");
    const code = await runInner(runInnerArgs);
    expect(code).toBe(0); // fell back to full enforcement, relay started
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] POLICY-INTEGRITY-ERROR:");
    // Did NOT fail closed for a policy error (the {} fallback is the safe state).
    expect(exitSpy).not.toHaveBeenCalled();
  });

  test("Fix 2 (MED): a generic policy read error (EACCES) is surfaced as POLICY-READ-ERROR, then falls back to {}", async () => {
    vi.resetModules();
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return { ...actual, readPins: async (): Promise<PinsFile> => actual.emptyPinsFile() };
    });
    // Policy read throws a generic (non-PolicyIntegrityError, non-ENOENT) I/O error.
    vi.doMock("../policy.js", async () => {
      const actual = await vi.importActual<typeof import("../policy.js")>("../policy.js");
      return {
        ...actual,
        readPolicy: async () => {
          const e = new Error("EACCES: permission denied, open '~/.mcpm/guard-policy.yaml'");
          (e as NodeJS.ErrnoException).code = "EACCES";
          throw e;
        },
      };
    });
    vi.doMock("../relay.js", async () => {
      const actual = await vi.importActual<typeof import("../relay.js")>("../relay.js");
      return {
        ...actual,
        startRelay: () => ({ child: {} as never, exit: Promise.resolve(0) }),
      };
    });

    const { runInner } = await import("../run-inner.js");
    const code = await runInner(runInnerArgs);
    expect(code).toBe(0); // fell back to full enforcement, relay started
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] POLICY-READ-ERROR:");
    expect(stderr).toContain("EACCES");
    // Must NOT mislabel a generic I/O error as an integrity tamper.
    expect(stderr).not.toContain("POLICY-INTEGRITY-ERROR:");
    // The {} fallback is the safe state — do NOT fail closed.
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

// ─────────────── H4: list_changed arm predicate + spoof guard ───────────────

describe("isToolsListChangedNotification (H4 list_changed arm predicate)", () => {
  test("a real notifications/tools/list_changed → true", () => {
    expect(
      isToolsListChangedNotification({
        jsonrpc: "2.0",
        method: "notifications/tools/list_changed",
      } as JSONRPCMessage),
    ).toBe(true);
  });

  test("SPOOF GUARD: method paired with a result is NOT a notification → false", () => {
    // A crafted frame pairing the notification method with a result must NOT arm
    // re-validation — otherwise an attacker frame could relax the F3 same-session guard.
    expect(
      isToolsListChangedNotification({
        jsonrpc: "2.0",
        method: "notifications/tools/list_changed",
        result: { tools: [] },
      } as unknown as JSONRPCMessage),
    ).toBe(false);
  });

  test("a different notification method → false", () => {
    expect(
      isToolsListChangedNotification({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      } as JSONRPCMessage),
    ).toBe(false);
  });

  test("a tools/list response (no method) → false", () => {
    expect(
      isToolsListChangedNotification({
        jsonrpc: "2.0",
        id: 1,
        result: { tools: [] },
      } as JSONRPCMessage),
    ).toBe(false);
  });

  test("arming wiring: a real notification arms; the announced list isn't F3-blocked; single-shot reverts", () => {
    const pins = emptyPinsFile();
    const state: SessionDriftState = { firstHashes: new Map(), revalidationArmed: false };
    // First list establishes the same-session baseline.
    inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, state);
    // A real list_changed arrives → arm (exactly what inspectChild does on a true predicate).
    const notif = { jsonrpc: "2.0", method: "notifications/tools/list_changed" } as JSONRPCMessage;
    if (isToolsListChangedNotification(notif)) state.revalidationArmed = true;
    // The announced follow-up legitimately differs → classified (no pin here), NOT F3-blocked.
    const followup = inspectForDriftSync(toolsListMsg("read", "v2"), "srv", pins, state);
    expect(followup.action).toBe("pass");
    expect(followup.findings).toHaveLength(0);
    // Single-shot: a SECOND unannounced change reverts to the strict F3 block.
    const second = inspectForDriftSync(toolsListMsg("read", "v3"), "srv", pins, state);
    expect(second.action).toBe("block");
    expect(second.findings[0]?.signature_id).toBe("schema-drift-in-session");
  });
});
