/**
 * Tests for src/commands/init.ts
 *
 * `init` scaffolds a starter mcpm.yaml (the curated PACKS were removed because
 * their registry IDs no longer resolve). Tests cover: scaffolding when absent,
 * not clobbering an existing file, --force overwrite, the legacy-pack-arg note,
 * and that the scaffolded content is valid against the real stack schema.
 */

import { describe, it, expect, vi } from "vitest";
import { parse as parseYaml } from "yaml";
import { handleInit, STARTER_STACK } from "../../commands/init.js";
import type { InitDeps } from "../../commands/init.js";
import { StackFileSchema } from "../../stack/schema.js";

function makeDeps(overrides: Partial<InitDeps> = {}): InitDeps {
  return {
    fileExists: vi.fn().mockResolvedValue(false),
    writeFile: vi.fn().mockResolvedValue(undefined),
    output: vi.fn(),
    ...overrides,
  };
}

describe("handleInit — scaffolding", () => {
  it("writes the starter stack file when none exists", async () => {
    const deps = makeDeps();
    await handleInit(undefined, {}, deps);
    expect(deps.writeFile).toHaveBeenCalledWith("mcpm.yaml", STARTER_STACK);
  });

  it("prints a created message and next-step guidance", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit(undefined, {}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/created mcpm\.yaml/i);
    expect(out).toMatch(/mcpm search/i);
    expect(out).toMatch(/mcpm up/i);
  });

  it("honours a custom stackPath", async () => {
    const deps = makeDeps({ stackPath: "custom.yaml" });
    await handleInit(undefined, {}, deps);
    expect(deps.writeFile).toHaveBeenCalledWith("custom.yaml", STARTER_STACK);
  });
});

describe("handleInit — existing file safety", () => {
  it("does NOT overwrite an existing stack file without --force", async () => {
    const deps = makeDeps({ fileExists: vi.fn().mockResolvedValue(true) });
    await handleInit(undefined, {}, deps);
    expect(deps.writeFile).not.toHaveBeenCalled();
  });

  it("reports that the file was left untouched", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      fileExists: vi.fn().mockResolvedValue(true),
      output: (t) => lines.push(t),
    });
    await handleInit(undefined, {}, deps);
    expect(lines.join("\n")).toMatch(/already exists/i);
  });

  it("overwrites an existing file when force is set", async () => {
    const deps = makeDeps({ fileExists: vi.fn().mockResolvedValue(true) });
    await handleInit(undefined, { force: true }, deps);
    expect(deps.writeFile).toHaveBeenCalledWith("mcpm.yaml", STARTER_STACK);
  });
});

describe("handleInit — legacy pack argument", () => {
  it("prints a removal note when a pack name is passed, then still scaffolds", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit("developer", {}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/starter packs were removed/i);
    expect(deps.writeFile).toHaveBeenCalledWith("mcpm.yaml", STARTER_STACK);
  });

  it("does not print the removal note for the no-arg form", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit(undefined, {}, deps);
    expect(lines.join("\n")).not.toMatch(/starter packs were removed/i);
  });
});

describe("STARTER_STACK", () => {
  it("is valid against the real StackFileSchema (lock/up will accept it)", () => {
    const parsed = StackFileSchema.parse(parseYaml(STARTER_STACK));
    expect(parsed.version).toBe("1");
    expect(parsed.servers).toEqual({});
  });
});
