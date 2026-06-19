/**
 * F2 — cross-server tool-name-collision detector tests (pure, no I/O).
 */

import { describe, expect, test } from "vitest";
import type { PinsFile } from "../pins.js";
import {
  detectNameCollisions,
  buildInventoryFromPins,
  serversWithoutBaseline,
} from "../shadow.js";

// Build a PinsFile whose per-server records carry the given tool NAMES as keys.
// buildInventoryFromPins / serversWithoutBaseline read keys only, so the pin
// values are irrelevant — a current_hash:null placeholder is realistic.
function pinsOf(servers: Record<string, string[]>): PinsFile {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [name, tools] of Object.entries(servers)) {
    out[name] = Object.fromEntries(tools.map((t) => [t, { current_hash: null }]));
  }
  return { format_version: 1, servers: out } as unknown as PinsFile;
}

const inv = (m: Record<string, string[]>): Map<string, string[]> => new Map(Object.entries(m));

describe("detectNameCollisions", () => {
  test("two servers sharing one tool name → one finding, servers sorted", () => {
    const f = detectNameCollisions(inv({ notes: ["send_email"], gmail: ["send_email", "list"] }));
    expect(f).toEqual([{ toolName: "send_email", servers: ["gmail", "notes"] }]);
  });

  test("three servers sharing one name → one finding with all three", () => {
    const f = detectNameCollisions(inv({ a: ["x"], b: ["x"], c: ["x"] }));
    expect(f).toHaveLength(1);
    expect(f[0]!.servers).toEqual(["a", "b", "c"]);
  });

  test("no overlap → empty", () => {
    expect(detectNameCollisions(inv({ a: ["x"], b: ["y", "z"] }))).toEqual([]);
  });

  test("a single-owner tool never flags", () => {
    expect(detectNameCollisions(inv({ a: ["read", "write"] }))).toEqual([]);
  });

  test("exact-match only: 'send_email' vs 'Send_Email' do NOT collide (v1 boundary)", () => {
    expect(detectNameCollisions(inv({ a: ["send_email"], b: ["Send_Email"] }))).toEqual([]);
  });

  test("a server listed with an empty tool set contributes nothing", () => {
    expect(detectNameCollisions(inv({ a: [], b: [] }))).toEqual([]);
  });

  test("deterministic ordering: multiple collisions sorted by tool name", () => {
    const f = detectNameCollisions(inv({ a: ["zebra", "apple"], b: ["apple", "zebra"] }));
    expect(f.map((x) => x.toolName)).toEqual(["apple", "zebra"]);
  });
});

describe("buildInventoryFromPins", () => {
  test("reads tool names (keys) per requested server", () => {
    const pins = pinsOf({ gmail: ["send_email", "list"], notes: ["send_email"] });
    const inventory = buildInventoryFromPins(pins, ["gmail", "notes"]);
    expect(inventory.get("gmail")).toEqual(["send_email", "list"]);
    expect(inventory.get("notes")).toEqual(["send_email"]);
  });

  test("a server absent from pins contributes [] (no crash)", () => {
    const pins = pinsOf({ gmail: ["send_email"] });
    expect(buildInventoryFromPins(pins, ["gmail", "never_guarded"]).get("never_guarded")).toEqual([]);
  });

  test("a current_hash:null placeholder pin still contributes its tool name (keys-only)", () => {
    const pins = pinsOf({ s: ["t1"] });
    expect(buildInventoryFromPins(pins, ["s"]).get("s")).toEqual(["t1"]);
  });

  test("end-to-end: pins → inventory → collision", () => {
    const pins = pinsOf({ gmail: ["send_email"], notes: ["send_email"] });
    const f = detectNameCollisions(buildInventoryFromPins(pins, ["gmail", "notes"]));
    expect(f).toEqual([{ toolName: "send_email", servers: ["gmail", "notes"] }]);
  });
});

describe("serversWithoutBaseline", () => {
  test("flags servers with no pin entry or an empty one", () => {
    const pins = pinsOf({ gmail: ["x"], empty: [] });
    expect(serversWithoutBaseline(pins, ["gmail", "empty", "missing"]).sort()).toEqual([
      "empty",
      "missing",
    ]);
  });

  test("all pinned → none missing", () => {
    expect(serversWithoutBaseline(pinsOf({ a: ["x"], b: ["y"] }), ["a", "b"])).toEqual([]);
  });
});
