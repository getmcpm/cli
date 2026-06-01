/**
 * Tests for src/commands/secrets.ts — written FIRST per TDD (Red → Green).
 *
 * Handlers take an injected SecretsDeps object, so these tests never touch the
 * real keychain, filesystem, or interactive prompts. A key invariant under
 * test: list/set output never contains decrypted secret VALUES.
 */

import { describe, it, expect, vi } from "vitest";
import { Command } from "commander";
import {
  handleSecretsSet,
  handleSecretsList,
  handleSecretsGet,
  handleSecretsRemove,
  registerSecretsCommand,
  type SecretsDeps,
} from "../../commands/secrets.js";

function makeDeps(overrides: Partial<SecretsDeps> = {}): {
  deps: SecretsDeps;
  out: string[];
  store: Record<string, string>;
} {
  const store: Record<string, string> = {};
  const out: string[] = [];
  const deps: SecretsDeps = {
    setSecret: vi.fn(async (s: string, k: string, v: string) => {
      store[`${s}/${k}`] = v;
    }),
    getSecret: vi.fn(async (s: string, k: string) => store[`${s}/${k}`] ?? null),
    deleteSecret: vi.fn(async (s: string, k: string) => {
      delete store[`${s}/${k}`];
    }),
    listAll: vi.fn(async () => {
      const grouped: Record<string, string[]> = {};
      for (const composite of Object.keys(store)) {
        const slash = composite.indexOf("/");
        const server = composite.slice(0, slash);
        const key = composite.slice(slash + 1);
        (grouped[server] ??= []).push(key);
      }
      return grouped;
    }),
    promptValue: vi.fn(async () => "prompted-secret"),
    confirmRemove: vi.fn(async () => true),
    output: (t: string) => out.push(t),
    ...overrides,
  };
  return { deps, out, store };
}

describe("mcpm secrets — set", () => {
  it("prompts for the value, stores it, and echoes the placeholder (not the value)", async () => {
    const { deps, out, store } = makeDeps({ promptValue: vi.fn(async () => "sk-supersecret") });
    await handleSecretsSet("gh", "TOKEN", deps);
    expect(store["gh/TOKEN"]).toBe("sk-supersecret");
    expect(deps.promptValue).toHaveBeenCalledTimes(1);
    const printed = out.join("\n");
    expect(printed).toContain("mcpm:keychain:gh/TOKEN");
    expect(printed).not.toContain("sk-supersecret");
  });

  it("rejects an empty value", async () => {
    const { deps } = makeDeps({ promptValue: vi.fn(async () => "") });
    await expect(handleSecretsSet("gh", "TOKEN", deps)).rejects.toThrow(/empty/i);
  });
});

describe("mcpm secrets — list", () => {
  it("lists keys grouped by server and never prints values", async () => {
    const { deps, out } = makeDeps();
    await deps.setSecret("gh", "TOKEN", "supersecret");
    await deps.setSecret("db", "PASSWORD", "p@ss");
    await handleSecretsList(undefined, deps);
    const printed = out.join("\n");
    expect(printed).toContain("gh");
    expect(printed).toContain("TOKEN");
    expect(printed).toContain("db");
    expect(printed).not.toContain("supersecret");
    expect(printed).not.toContain("p@ss");
  });

  it("filters by server when one is given", async () => {
    const { deps, out } = makeDeps();
    await deps.setSecret("gh", "TOKEN", "x");
    await deps.setSecret("db", "PASSWORD", "y");
    await handleSecretsList("gh", deps);
    const printed = out.join("\n");
    expect(printed).toContain("TOKEN");
    expect(printed).not.toContain("PASSWORD");
  });

  it("reports when no secrets are stored", async () => {
    const { deps, out } = makeDeps();
    await handleSecretsList(undefined, deps);
    expect(out.join("\n")).toMatch(/no secrets/i);
  });
});

describe("mcpm secrets — get", () => {
  it("refuses to print a secret without --reveal", async () => {
    const { deps } = makeDeps();
    await deps.setSecret("gh", "TOKEN", "sk");
    await expect(
      handleSecretsGet("gh", "TOKEN", { reveal: false }, deps)
    ).rejects.toThrow(/reveal/i);
  });

  it("prints the decrypted value with --reveal", async () => {
    const { deps, out } = makeDeps();
    await deps.setSecret("gh", "TOKEN", "sk-123");
    await handleSecretsGet("gh", "TOKEN", { reveal: true }, deps);
    expect(out.join("\n")).toContain("sk-123");
  });

  it("errors when the secret does not exist", async () => {
    const { deps } = makeDeps();
    await expect(
      handleSecretsGet("gh", "MISSING", { reveal: true }, deps)
    ).rejects.toThrow(/no secret/i);
  });
});

describe("mcpm secrets — rm", () => {
  it("deletes after confirmation", async () => {
    const { deps, store } = makeDeps();
    await deps.setSecret("gh", "TOKEN", "x");
    await handleSecretsRemove("gh", "TOKEN", { yes: false }, deps);
    expect(store["gh/TOKEN"]).toBeUndefined();
    expect(deps.confirmRemove).toHaveBeenCalledTimes(1);
  });

  it("skips confirmation with --yes", async () => {
    const { deps, store } = makeDeps();
    await deps.setSecret("gh", "TOKEN", "x");
    await handleSecretsRemove("gh", "TOKEN", { yes: true }, deps);
    expect(store["gh/TOKEN"]).toBeUndefined();
    expect(deps.confirmRemove).not.toHaveBeenCalled();
  });

  it("aborts (keeps the secret) when confirmation is declined", async () => {
    const { deps, store } = makeDeps({ confirmRemove: vi.fn(async () => false) });
    await deps.setSecret("gh", "TOKEN", "x");
    await handleSecretsRemove("gh", "TOKEN", { yes: false }, deps);
    expect(store["gh/TOKEN"]).toBe("x");
  });
});

describe("registerSecretsCommand", () => {
  it("registers a `secrets` command with set/list/get/rm subcommands", () => {
    const program = new Command();
    registerSecretsCommand(program);
    const secrets = program.commands.find((c) => c.name() === "secrets");
    expect(secrets).toBeDefined();
    const subs = secrets!.commands.map((c) => c.name()).sort();
    expect(subs).toEqual(["get", "list", "rm", "set"]);
  });

  it("gives `get` a --reveal flag and `rm` a --yes flag", () => {
    const program = new Command();
    registerSecretsCommand(program);
    const secrets = program.commands.find((c) => c.name() === "secrets")!;
    const get = secrets.commands.find((c) => c.name() === "get")!;
    const rm = secrets.commands.find((c) => c.name() === "rm")!;
    expect(get.options.some((o) => o.long === "--reveal")).toBe(true);
    expect(rm.options.some((o) => o.long === "--yes")).toBe(true);
  });
});
