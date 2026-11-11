/** Opt-in bounded evidence; legacy audit scoring, JSON and MCP stay separate. */
import type { AuditDeps } from "./audit.js";
import { readAuditInventory } from "../store/audit-inventory.js";
import { describeRegistryError } from "../registry/errors.js";
import { resolveScannerCommand } from "../scanner/tier2.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore } from "../scanner/trust-score.js";
import { extractRegistryMeta } from "../utils/format-trust.js";

type Check = { state: "performed" | "not_run" | "unavailable" | "failed"; reason?: string };
interface ReportRow {
  name: string;
  score: TrustScore | null;
  findings: Pick<Finding, "severity" | "type" | "source">[];
  checks: Record<"registry" | "static" | "external" | "health", Check>;
}

export async function handleAuditReport(deps: AuditDeps): Promise<number> {
  const { servers, ...inventory } = await (deps.getAuditInventory ?? readAuditInventory)();
  const configured = (deps.scannerConfigured ?? (() => resolveScannerCommand().status !== "disabled"))();
  let available: boolean | undefined;
  const results: ReportRow[] = [];
  for (const server of servers) {
    const row: ReportRow = {
      name: server.name, score: null, findings: [],
      checks: {
        registry: { state: "not_run" }, static: { state: "not_run", reason: "registry-required" },
        external: { state: "not_run", reason: configured ? "prior-check-required" : "not-configured" },
        health: { state: "not_run", reason: "outside-audit-scope" },
      },
    };
    results.push(row);
    let entry;
    try { entry = await deps.getServer(server.name); }
    catch (error) {
      const kind = describeRegistryError(error).kind;
      row.checks.registry = { state: kind === "unavailable" ? "unavailable" : "failed", reason: kind };
      continue;
    }
    if (entry.server.name !== server.name) {
      row.checks.registry = { state: "failed", reason: "identity-mismatch" };
      continue;
    }
    row.checks.registry = { state: "performed" };
    let findings: Finding[];
    try { findings = deps.scanTier1(entry); row.checks.static = { state: "performed" }; }
    catch { row.checks.static = { state: "failed", reason: "static-scan-failed" }; continue; }
    if (configured) {
      if (available === undefined) {
        try { available = await deps.checkScannerAvailable(); }
        catch { available = false; }
      }
      if (!available) row.checks.external = { state: "unavailable", reason: "scanner-unavailable" };
      else {
        try {
          const external = await deps.scanTier2(server.name);
          const failed = external.some((finding) => finding.type === "scanner-error");
          row.checks.external = failed ? { state: "failed", reason: "scanner-failed" } : { state: "performed" };
          findings = [...findings, ...external];
        } catch { row.checks.external = { state: "failed", reason: "scanner-failed" }; }
      }
    }
    row.findings = findings.filter((finding) => finding.type !== "scanner-error").map((finding) => ({ severity: finding.severity, type: finding.type, source: finding.source ?? "static" }));
    row.score = deps.computeTrustScore({ findings, healthCheckPassed: null, hasExternalScanner: row.checks.external.state === "performed", registryMeta: { ...extractRegistryMeta(entry), downloadCount: undefined } });
  }
  const assessed = results.filter((row) => row.checks.registry.state === "performed" && row.checks.static.state === "performed" && (!configured || row.checks.external.state === "performed")).length;
  const assessmentComplete = inventory.state !== "incomplete" && assessed === results.length;
  const findingCount = results.reduce((count, row) => count + row.findings.length, 0);
  const outcome = !assessmentComplete ? "incomplete_assessment" : inventory.state === "empty" ? "empty_inventory" : findingCount > 0 ? "findings" : "no_findings";
  deps.output(JSON.stringify({
    schemaVersion: 1, source: "mcpm-store", metadataSelector: "latest",
    scope: { selectedChecks: ["registry", "static", ...(configured ? ["external"] : [])], excludes: ["health", "installed-bytes", "client-configuration", "native-activation"] },
    inventory,
    assessmentComplete, outcome,
    summary: { assessed, unassessed: inventory.total === null ? null : inventory.total - assessed, findingCount },
    servers: results,
  }, null, 2));
  return !assessmentComplete || results.some((row) => row.score?.level === "risky") ? 1 : 0;
}
