import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { ClaudeCodeAdapter } from "../../../config/adapters/claude-code.js";
import { wrapEntry, rewrapEntry, unwrapEntry } from "../../../guard/wrap.js";
import { runEnableCommand } from "../../../guard/cli.js";
import { _resetCachedStorePath } from "../../../store/index.js";
import { planClaudePolicyChange } from "../../../config/claude-policy.js";

let root: string;
let home: string;
let managed: string;
let config: string;
const original = { command: "node", args: ["fixture.js"], env: { TOKEN: "CANARY_SECRET" }, disabled: true };
const wrapped = () => wrapEntry("fixture", original, { mcpmBinary: "/fixture/mcpm" });
const context = () => ({ home, root, managedDirectory: managed, platform: "linux" as const, env: { HOME: home } });
async function settings(value: unknown, scope: "user" | "project" | "local" | "managed" = "managed") {
  const file = scope === "managed" ? path.join(managed, "managed-settings.json") :
    path.join(scope === "user" ? home : root, ".claude", scope === "local" ? "settings.local.json" : "settings.json");
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(value));
}
async function plan(entry = wrapped()) { return planClaudePolicyChange(config, "fixture", entry, context()); }
beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "mcpm-policy-"));
  home = path.join(root, "home"); managed = path.join(root, "managed"); config = path.join(home, ".claude.json");
  await mkdir(home); await mkdir(managed);
  await writeFile(config, JSON.stringify({ mcpServers: { fixture: original }, nativePermissions: ["preserve"] }));
});
afterEach(async () => { await rm(root, { recursive: true, force: true }); });

describe("Claude Code file policy preflight", () => {
  it("reproduces original-command deny bypass through replaceServer, before any writes", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] });
    const before = await readFile(config, "utf8");
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped())).rejects.toThrow(/underlying.*denied/i);
    expect(await readFile(config, "utf8")).toBe(before);
    expect((await readdir(home)).sort()).toEqual([".claude.json"]);
  });
  it("blocks wrapped update/up/install addServer as well as guard replaceServer", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "new.js"] }] });
    await writeFile(config, JSON.stringify({ mcpServers: { fixture: wrapped() } }));
    await expect(new ClaudeCodeAdapter(context()).addServer(config, "fixture", rewrapEntry(wrapped(), { ...original, args: ["new.js"] }), { force: true })).rejects.toThrow(/underlying.*denied/i);
  });
  it("reports unset policy as local allow with explicit host uncertainty and preserves metadata", async () => {
    const result = await plan();
    expect(result.original.decision).toBe("allowed"); expect(result.proposed.decision).toBe("allowed");
    expect(result.filePolicy).toBe("preserved"); expect(result.hostPolicy).toBe("unknown");
    expect(result.coverage.join(" ")).toMatch(/server-managed/i);
    await new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped());
    const saved = JSON.parse(await readFile(config, "utf8"));
    expect(saved.nativePermissions).toEqual(["preserve"]); expect(saved.mcpServers.fixture).toEqual(wrapped());
  });
  it("blocks empty allow and command allowlists broken by wrapper argv", async () => {
    await settings({ allowedMcpServers: [] }); expect((await plan()).proposed.decision).toBe("denied");
    await settings({ allowedMcpServers: [{ serverName: "fixture" }, { serverCommand: ["node", "fixture.js"] }] });
    const result = await plan(); expect(result.original.decision).toBe("allowed"); expect(result.proposed.decision).toBe("denied");
  });
  it("accepts exact wrapper argv when both original and wrapper are allowed, and deny wins", async () => {
    const allow = [{ serverCommand: ["node", "fixture.js"] }, { serverCommand: [wrapped().command!, ...wrapped().args!] }];
    await settings({ allowedMcpServers: allow }); expect((await plan()).filePolicy).toBe("preserved");
    await settings({ allowedMcpServers: allow, deniedMcpServers: [{ serverName: "fixture" }] });
    expect((await plan()).filePolicy).toBe("blocked");
  });
  it("merges lists across scopes and respects managed-only allow lock", async () => {
    await settings({ allowedMcpServers: [{ serverName: "fixture" }] }, "user");
    await settings({ allowedMcpServers: [] }); expect((await plan()).filePolicy).toBe("preserved");
    await settings({ allowedMcpServers: [], allowManagedMcpServersOnly: true }); expect((await plan()).filePolicy).toBe("blocked");
    await settings({ deniedMcpServers: [{ serverName: "fixture" }] }, "local"); expect((await plan()).original.decision).toBe("denied");
  });
  it("expands command variables/defaults without disclosing values", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["${BIN:-node}", "${FILE}"] }], env: { FILE: "fixture.js" } });
    expect((await plan()).original.decision).toBe("denied");
    const result = await plan(); expect(JSON.stringify(result)).not.toContain("CANARY_SECRET"); expect(JSON.stringify(result)).not.toContain("fixture.js");
  });
  it("refuses unexpandable and malformed policy, duplicate decoded keys and unknown sources", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["${MISSING}"] }] }); expect((await plan()).filePolicy).toBe("unknown");
    await settings({ allowedMcpServers: [{ serverName: "fixture", serverCommand: ["node"] }] }); expect((await plan()).filePolicy).toBe("unknown");
    await writeFile(path.join(managed, "managed-settings.json"), '{"allowedMcpServers":[],"allowedMcpServer\\u0073":[]}'); expect((await plan()).filePolicy).toBe("unknown");
    await rm(path.join(managed, "managed-settings.json")); await mkdir(path.join(managed, "managed-settings.d"));
    await writeFile(path.join(managed, "managed-settings.d", "policy.json"), "{}"); expect((await plan()).filePolicy).toBe("unknown");
  });
  it("refuses unreadable/non-file policy and managed exclusive control", async () => {
    await mkdir(path.join(managed, "managed-settings.json")); expect((await plan()).filePolicy).toBe("unknown");
    await rm(path.join(managed, "managed-settings.json"), { recursive: true });
    await writeFile(path.join(managed, "managed-mcp.json"), JSON.stringify({ mcpServers: {} }));
    expect((await plan()).filePolicy).toBe("blocked");
  });
  it("keeps malformed current-config parse values out of shared adapter errors", async () => {
    await writeFile(config, "CANARY_SECRET_INVALID_JSON");
    const error = await new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped()).catch(error => error as Error);
    expect(error).toBeInstanceOf(Error);
    if (!(error instanceof Error)) throw new Error("Expected configuration refusal");
    expect(error.message).not.toContain("CANARY");
    expect(error.message).toMatch(/unknown.*malformed/i);
    vi.stubEnv("HOME", home); vi.spyOn(process, "cwd").mockReturnValue(root);
    try {
      const out: string[] = [];
      await expect(runEnableCommand({ client: "claude-code", dryRun: true, write: text => out.push(text) })).rejects.toThrow(/refused/);
      await expect(runEnableCommand({ client: "claude-code", server: "fixture", write: text => out.push(text) })).rejects.toThrow(/file policy refused/);
      expect(out.join("")).not.toContain("CANARY");
      expect(await readdir(home)).toEqual([".claude.json"]);
    } finally { vi.unstubAllEnvs(); vi.restoreAllMocks(); }
  });
  it("does not write malformed wrappers or expose raw parser/argv/environment errors", async () => {
    const bad = wrapped(); bad.args![bad.args!.length - 1] = "CANARY_SECRET";
    const result = await plan(bad); expect(result.filePolicy).toBe("unknown"); expect(JSON.stringify(result)).not.toContain("CANARY_SECRET");
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", bad)).rejects.toThrow(/unknown/i);
  });
  it("refuses managed exceptions for user-global shadowed entries without granting their exemption", async () => {
    await settings({ allowedMcpServers: [], managedMcpServers: { fixture: { type: "http", url: "https://managed.invalid" } } });
    expect((await plan()).reason).toMatch(/shadowed/);
    await settings({ managedMcpServers: { other: { type: "http", url: "https://managed.invalid" } } });
    expect((await plan()).filePolicy).toBe("preserved");
  });
  it("keeps policy expansion pinned while live settings affect the configured command", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["${BIN}", "fixture.js"] }] });
    await settings({ env: { BIN: "evil" } }, "project");
    const changed = { ...original, command: "${BIN}" };
    await writeFile(config, JSON.stringify({ mcpServers: { fixture: changed } }));
    const result = await planClaudePolicyChange(config, "fixture", wrapEntry("fixture", changed, { mcpmBinary: "/fixture/mcpm" }), { ...context(), env: { BIN: "node" } });
    expect(result.original.decision).toBe("allowed");
    await settings({ env: { BIN: "node" } }, "project");
    expect((await planClaudePolicyChange(config, "fixture", wrapped(), { ...context(), env: { BIN: "node" } })).original.decision).toBe("denied");
  });
  it("refuses platform policy helper payloads before backups or configuration writes", async () => {
    await settings({ policyHelpers: { default: { deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] } } });
    const before = await readFile(config, "utf8");
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped())).rejects.toThrow(/unsupported selection controls/);
    expect(await readFile(config, "utf8")).toBe(before);
    expect(await readdir(home)).toEqual([".claude.json"]);
  });
  it("refuses legacy global environment selection rather than misprojecting a default command", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] });
    const configured = { ...original, command: "${LEGACY_BIN:-false}" };
    await writeFile(config, JSON.stringify({ env: { LEGACY_BIN: "node" }, mcpServers: { fixture: configured } }));
    const proposed = wrapEntry("fixture", configured, { mcpmBinary: "/fixture/mcpm" });
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", proposed)).rejects.toThrow(/Legacy global configuration environment/);
    expect((await readdir(home)).filter(name => /bak|tmp/.test(name))).toEqual([]);
  });
  it("refuses native-filtered environment references instead of permitting a filtered deny bypass", async () => {
    await settings({ env: { NO_COLOR: "different" }, deniedMcpServers: [{ serverCommand: ["${NO_COLOR:-node}", "fixture.js"] }] });
    expect((await plan()).filePolicy).toBe("unknown");
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped())).rejects.toThrow(/native-filtered environment/);
  });
  it("treats inherited object-property names as unset expansion variables", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["${constructor:-node}", "fixture.js"] }] });
    expect((await plan()).original.decision).toBe("denied");
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped())).rejects.toThrow(/underlying.*denied/i);
  });
  it("uses explicit expansion defaults before user-settings fallback when startup is unset", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["${BIN:-node}", "fixture.js"] }] });
    await settings({ env: { BIN: "different" } }, "user");
    expect((await plan()).original.decision).toBe("denied");
    await expect(new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", wrapped())).rejects.toThrow(/underlying.*denied/i);
    await settings({ deniedMcpServers: [{ serverCommand: ["${BIN}", "fixture.js"] }] });
    await settings({ env: { BIN: "node" } }, "user");
    expect((await plan()).original.decision).toBe("denied");
  });
  it("does not confuse command prefixes/argument differences with an exact deny match", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js", "--extra"] }] });
    expect((await plan()).filePolicy).toBe("preserved");
  });
  it("reports ancestor settings and alternate source selection as unknown", async () => {
    await settings({}, "project");
    const child = path.join(root, "subdir"); await mkdir(child);
    expect((await planClaudePolicyChange(config, "fixture", wrapped(), { ...context(), root: child })).filePolicy).toBe("unknown");
    expect((await planClaudePolicyChange(config, "fixture", wrapped(), { ...context(), env: { CLAUDE_CONFIG_DIR: "other" } })).filePolicy).toBe("unknown");
    expect((await planClaudePolicyChange(config, "fixture", wrapped(), { ...context(), platform: "win32" })).filePolicy).toBe("unknown");
  });
  it("guard dry-run and confine refuse the same original denial without config/backups/profile files", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] }, "user");
    vi.stubEnv("HOME", home); vi.spyOn(process, "cwd").mockReturnValue(root); _resetCachedStorePath();
    try {
      const before = await readFile(config, "utf8");
      const out: string[] = [];
      await expect(runEnableCommand({ client: "claude-code", dryRun: true, write: text => out.push(text) })).rejects.toThrow(/refused/);
      expect(out.join("")).toMatch(/would wrap 0/); expect(out.join("")).toMatch(/underlying denied/);
      await expect(runEnableCommand({ client: "claude-code", confine: "standard", write: text => out.push(text) })).rejects.toThrow(/refused/);
      expect(out.join("")).toMatch(/confinement aborted/);
      expect(await readFile(config, "utf8")).toBe(before);
      expect((await readdir(home, { recursive: true })).filter(name => /bak|guard-confine|^\.mcpm/.test(name))).toEqual([]);
    } finally { vi.unstubAllEnvs(); vi.restoreAllMocks(); _resetCachedStorePath(); }
  });

  it("reports an already-wrapped legacy deny bypass during enable previews without changing it", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] }, "user");
    await writeFile(config, JSON.stringify({ mcpServers: { fixture: wrapped() } }));
    vi.stubEnv("HOME", home); vi.spyOn(process, "cwd").mockReturnValue(root); _resetCachedStorePath();
    try {
      const before = await readFile(config, "utf8");
      const out: string[] = [];
      await expect(runEnableCommand({ client: "claude-code", dryRun: true, write: text => out.push(text) })).rejects.toThrow(/refused/);
      expect(out.join("")).toMatch(/underlying denied/);
      expect(await readFile(config, "utf8")).toBe(before);
      expect((await readdir(home, { recursive: true })).filter(name => /bak|^\.mcpm/.test(name))).toEqual([]);
    } finally { vi.unstubAllEnvs(); vi.restoreAllMocks(); _resetCachedStorePath(); }
  });
  it("restores native denial when disabling an exact legacy bypass wrapper", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] });
    await writeFile(config, JSON.stringify({ mcpServers: { fixture: wrapped() } }));
    const unwrapped = unwrapEntry(wrapped())!;
    const result = await plan(unwrapped);
    expect(result.filePolicy).toBe("preserved"); expect(result.proposed.decision).toBe("denied");
    expect(result.reason).toMatch(/teardown/);
    await new ClaudeCodeAdapter(context()).replaceServer(config, "fixture", unwrapped);
    expect(JSON.parse(await readFile(config, "utf8")).mcpServers.fixture).toEqual(unwrapped);
  });
  it("allows an authorized replacement of a denied old command with an allowed new command", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["node", "fixture.js"] }] });
    const replacement = { ...original, args: ["new.js"] };
    const result = await plan(replacement);
    expect(result.original.decision).toBe("denied"); expect(result.proposed.decision).toBe("allowed");
    await new ClaudeCodeAdapter(context()).addServer(config, "fixture", replacement, { force: true });
  });
  it("preserves ordinary direct HTTP installs outside the stdio projection", async () => {
    const adapter = new ClaudeCodeAdapter(context());
    await adapter.addServer(config, "http", { url: "https://fixture.invalid/mcp" });
    const result = await adapter.planServerChange(config, "http", { command: "node", args: ["new.js"] });
    expect(result.original.decision).toBe("unknown"); expect(result.proposed.decision).toBe("allowed");
    expect(result.filePolicy).toBe("preserved");
    await adapter.addServer(config, "http", { command: "node", args: ["new.js"] }, { force: true });
    await expect(adapter.addServer(config, "mixed", { command: "node", url: "https://fixture.invalid" })).rejects.toThrow(/unknown/);
  });

  it("distinguishes empty from unset expansion and only user/managed fallback pins deny", async () => {
    await settings({ deniedMcpServers: [{ serverCommand: ["${BIN:-node}", "fixture.js"] }] });
    expect((await planClaudePolicyChange(config, "fixture", wrapped(), { ...context(), env: { BIN: "" } })).original.decision).toBe("allowed");
    expect((await plan()).original.decision).toBe("denied");
    await settings({ deniedMcpServers: [{ serverCommand: ["${BIN}", "fixture.js"] }] });
    await settings({ env: { BIN: "node" } }, "project");
    expect((await plan()).filePolicy).toBe("unknown");
    await settings({ env: { BIN: "node" } }, "user");
    expect((await plan()).original.decision).toBe("denied");
  });

});
