import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { handleAudit, registerAuditCommand, type AuditDeps } from "../../commands/audit.js";
import { readAuditInventory } from "../../store/audit-inventory.js";
import { computeTrustScore } from "../../scanner/trust-score.js";
import { scanTier1 } from "../../scanner/tier1.js";
import { scanTier2 } from "../../scanner/tier2.js";
import { NetworkError, NotFoundError, ValidationError } from "../../registry/errors.js";
import type { ServerEntry } from "../../registry/types.js";

const row = { name: "io.github.test/server-a", version: "1.0.0", clients: ["claude-code"], installedAt: "2026-01-01T00:00:00Z" };
const entry = { server: { name: row.name, version: "2.0.0", description: "test", packages: [], remotes: [] }, _meta: {} } as ServerEntry;
const homes: string[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(homes.splice(0).map((home) => rm(home, { recursive: true, force: true }))); });

async function fixture(raw?: string) {
  const home = await mkdtemp(path.join(os.tmpdir(), "mcpm-audit-report-"));
  homes.push(home);
  vi.spyOn(os, "homedir").mockReturnValue(home);
  if (raw !== undefined) { await mkdir(path.join(home, ".mcpm")); await writeFile(path.join(home, ".mcpm/servers.json"), raw); }
  return home;
}
function deps(overrides: Partial<AuditDeps> = {}): AuditDeps {
  return {
    getInstalledServers: vi.fn().mockResolvedValue([]), getServer: vi.fn().mockResolvedValue(entry),
    scanTier1, checkScannerAvailable: vi.fn().mockResolvedValue(false), scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore, output: vi.fn(), getAdapter: vi.fn(), getConfigPath: vi.fn(), removeFromStore: vi.fn(), confirm: vi.fn(),
    scannerConfigured: () => false, ...overrides,
  };
}
async function report(d = deps()) {
  const code = await handleAudit({ reportJson: true }, d);
  return { code, model: JSON.parse(vi.mocked(d.output).mock.calls[0][0]) };
}

describe("audit --report-json", () => {
  it("distinguishes missing and explicit empty inventory without creating state", async () => {
    const home = await fixture();
    const missing = await report();
    expect(missing).toMatchObject({ code: 0, model: { schemaVersion: 1, source: "mcpm-store", outcome: "empty_inventory", inventory: { state: "empty", presence: "missing", total: 0 } } });
    await expect(readFile(path.join(home, ".mcpm/servers.json"))).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(path.join(home, ".mcpm"))).rejects.toMatchObject({ code: "ENOENT" });
    await fixture("[]");
    expect((await report()).model.inventory).toMatchObject({ state: "empty", presence: "present" });
  });
  it.each(["null", "{}", '{"mcpmSchemaVersion":3,"servers":[]}', '{"mcpmSchemaVersion":2,"servers":"secret-value"}', "{ secret-value"])("rejects malformed/unsupported store %s", async (raw) => {
    await fixture(raw);
    const { code, model } = await report();
    expect(code).toBe(1); expect(model.outcome).toBe("incomplete_assessment");
    expect(model.inventory.state).toBe("incomplete"); expect(JSON.stringify(model)).not.toContain("secret-value");
  });
  it("retains valid mixed rows and marks invalid/duplicate rows as uncovered", async () => {
    await fixture(JSON.stringify({ mcpmSchemaVersion: 2, servers: [row, { ...row, name: "secret\u001b[31m" }, row] }));
    const { code, model } = await report();
    expect(code).toBe(1); expect(model.inventory).toMatchObject({ total: 3, accepted: 1, issues: [{ code: "invalid-row", index: 1 }, { code: "duplicate-name", index: 2 }] });
    expect(model.summary).toMatchObject({ assessed: 1, unassessed: 2 }); expect(model.servers).toHaveLength(1);
    expect(JSON.stringify(model)).not.toContain("secret");
  });
  it("reports no findings only for the bounded selected checks", async () => {
    await fixture(JSON.stringify([row]));
    const d = deps(); const { model, code } = await report(d);
    expect(code).toBe(0); expect(model).toMatchObject({ outcome: "no_findings", assessmentComplete: true, metadataSelector: "latest", scope: { selectedChecks: ["registry", "static"], excludes: ["health", "installed-bytes", "client-configuration", "native-activation"] }, summary: { assessed: 1, unassessed: 0 } });
    expect(model.servers[0]).toMatchObject({ checks: { registry: { state: "performed" }, static: { state: "performed" }, external: { state: "not_run" }, health: { state: "not_run" } } });
    expect(d.getInstalledServers).not.toHaveBeenCalled(); expect(d.checkScannerAvailable).not.toHaveBeenCalled(); expect(d.removeFromStore).not.toHaveBeenCalled();
  });
  it("does not attribute another registry server's metadata to the installed name", async () => {
    await fixture(JSON.stringify([row]));
    const d = deps({ getServer: vi.fn().mockResolvedValue({ ...entry, server: { ...entry.server, name: "io.github.other/server-b" } }) });
    const { code, model } = await report(d);
    expect(code).toBe(1); expect(model.servers[0]).toMatchObject({ score: null, checks: { registry: { state: "failed", reason: "identity-mismatch" }, static: { state: "not_run" } } });
    expect(d.checkScannerAvailable).not.toHaveBeenCalled();
  });
  it("reports configured scanner unavailability as incomplete rather than passed", async () => {
    await fixture(JSON.stringify([row]));
    const { code, model } = await report(deps({ scannerConfigured: () => true }));
    expect(code).toBe(1); expect(model.servers[0].checks.external.state).toBe("unavailable"); expect(model.assessmentComplete).toBe(false);
  });
  it.each(["", "not-json", '{"findings":{}}'])("reports malformed scanner output without value leaks", async (stdout) => {
    await fixture(JSON.stringify([row]));
    const { code, model } = await report(deps({ scannerConfigured: () => true, checkScannerAvailable: vi.fn().mockResolvedValue(true), scanTier2: (name) => scanTier2(name, { env: { MCPM_EXTERNAL_SCANNER: "fixture-scanner" }, execImpl: async () => ({ stdout, exitCode: 0 }) }) }));
    expect(code).toBe(1); expect(model.servers[0].checks.external.state).toBe("failed"); expect(model.servers[0].score.maxPossible).toBe(80);
    expect(model.servers[0].findings).toEqual([]);
  });
  it.each([new NetworkError("secret", new Error("secret")), new NotFoundError("secret"), new ValidationError("secret"), new Error("secret")])("classifies registry failures and retains successful sibling findings", async (error) => {
    await fixture(JSON.stringify([row, { ...row, name: "io.github.test/server-b" }]));
    const d = deps({ getServer: vi.fn().mockResolvedValueOnce(entry).mockRejectedValueOnce(error), scanTier1: () => [{ severity: "high", type: "secrets", source: "static", message: "secret", location: "secret" }] });
    const { model, code } = await report(d);
    expect(code).toBe(1); expect(model.outcome).toBe("incomplete_assessment"); expect(model.servers[0].findings).toEqual([{ severity: "high", type: "secrets", source: "static" }]);
    expect(model.servers[1].score).toBeNull(); expect(model.summary).toMatchObject({ assessed: 1, unassessed: 1 });
    expect(JSON.stringify(model)).not.toContain('"secret"');
  });
  it("uses valid external findings on nonzero exit without leaking scanner values", async () => {
    await fixture(JSON.stringify([row]));
    const { code, model } = await report(deps({ scannerConfigured: () => true, checkScannerAvailable: vi.fn().mockResolvedValue(true), scanTier2: (name) => scanTier2(name, { env: { MCPM_EXTERNAL_SCANNER: "fixture-scanner" }, execImpl: async () => ({ stdout: JSON.stringify({ findings: [{ severity: "novel", description: "private-value", location: "private-value" }] }), exitCode: 1 }) }) }));
    expect(code).toBe(0); expect(model).toMatchObject({ assessmentComplete: true, outcome: "findings", scope: { selectedChecks: ["registry", "static", "external"] } });
    expect(model.servers[0]).toMatchObject({ findings: [{ severity: "high", type: "prompt-injection", source: "external" }], checks: { external: { state: "performed" } }, score: { maxPossible: 100 } });
    expect(JSON.stringify(model)).not.toContain("private-value");
  });
  it("retains all-invalid inventory counts instead of reporting empty", async () => {
    await fixture(JSON.stringify([null, { ...row, version: "invalid\u001bvalue" }]));
    const { code, model } = await report();
    expect(code).toBe(1); expect(model).toMatchObject({ outcome: "incomplete_assessment", inventory: { total: 2, accepted: 0 }, summary: { assessed: 0, unassessed: 2 } });
  });
  it("keeps findings separate from coverage and never emits raw finding values", async () => {
    await fixture(JSON.stringify([row]));
    const { code, model } = await report(deps({ scanTier1: () => [{ severity: "low", type: "secrets", message: "private-value", location: "private-value" }] }));
    expect(code).toBe(0); expect(model.outcome).toBe("findings"); expect(model.assessmentComplete).toBe(true); expect(JSON.stringify(model)).not.toContain("private-value");
  });
  it.each([{ json: true }, { sarif: true }, { fix: true }, { minTrust: 0 }, { yes: true }])("rejects incompatible flags before reads: %j", async (options) => {
    const d = deps(); await expect(handleAudit({ reportJson: true, ...options }, d)).rejects.toThrow("--report-json"); expect(d.getInstalledServers).not.toHaveBeenCalled();
  });
  it("registers the explicit CLI opt-in", () => { const program = new Command(); registerAuditCommand(program); expect(program.commands[0].options.some((option) => option.long === "--report-json")).toBe(true); });
  it("preserves legacy empty JSON and human output", async () => {
    for (const options of [{}, { json: true }]) { const d = deps(); expect(await handleAudit(options, d)).toBe(0); expect(d.output).toHaveBeenCalledExactlyOnceWith("No servers installed. Install one first: mcpm install <name>"); }
  });
  it("bounds store reads and refuses symlinks and duplicate JSON keys", async () => {
    const home = await fixture(JSON.stringify([row]));
    const file = path.join(home, ".mcpm/servers.json");
    await writeFile(file, " ".repeat(1024 * 1024 + 1));
    expect((await report()).model.inventory.issues).toEqual([{ code: "too-large" }]);
    await writeFile(file, Buffer.from([0xff]));
    expect((await report()).model.inventory.issues).toEqual([{ code: "malformed-json" }]);
    await rm(file); await symlink(path.join(home, "missing"), file);
    expect((await report()).model.inventory.issues).toEqual([{ code: "symlink-skipped" }]);
    await rm(file); await mkdir(file);
    expect((await report()).model.inventory.issues).toEqual([{ code: "not-file" }]);
    await fixture('{"mcpmSchemaVersion":3,"mcpmSchemaVersion":2,"servers":[]}');
    expect((await report()).model.inventory.issues).toEqual([{ code: "malformed-json" }]);
  });
  it("keeps static failures incomplete without a fabricated score", async () => {
    await fixture(JSON.stringify([row]));
    const { code, model } = await report(deps({ scanTier1: () => { throw new Error("private-value"); } }));
    expect(code).toBe(1); expect(model.servers[0]).toMatchObject({ score: null, checks: { static: { state: "failed" } } });
    expect(JSON.stringify(model)).not.toContain("private-value");
  });
  it("classifies store I/O failures without parser or OS details", async () => {
    await fixture(); const inventory = await readAuditInventory(async () => { throw Object.assign(new Error("private-path private-value"), { code: "EACCES" }); });
    expect(inventory).toMatchObject({ state: "incomplete", issues: [{ code: "unreadable" }] }); expect(JSON.stringify(inventory)).not.toContain("private-");
  });
});
