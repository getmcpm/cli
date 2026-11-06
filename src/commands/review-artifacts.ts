import type { Command } from "commander";
import { buildArtifactReview, PROFILES, type ArtifactReview } from "../artifacts/review.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import { stdoutOutput } from "../utils/output.js";
export { buildArtifactReview } from "../artifacts/review.js";

export function renderArtifactReview(report: ArtifactReview): string {
  const lines = [`Artifact review (${report.profile})`, `Byte inventory: ${report.byteInventoryComplete ? "complete" : "incomplete"}; declaration coverage: ${report.declarationCoverageComplete ? "complete" : "incomplete"}`, "Configured / cached / loaded / enforced: unknown"];
  for (const side of ["before", "after"] as const) {
    const value = report[side];
    lines.push(`${side}: ${value.source.path} (${value.source.state}); SHA-256 ${value.source.sha256 ?? "unavailable"}`);
    for (const gap of value.gaps) lines.push(`  gap: ${gap.code} ${gap.source}`);
  }
  for (const file of report.changedFiles) lines.push(`${file.change}: ${file.path} [${file.roles.join(", ") || "resource"}] ${file.beforeSha256 ?? "unavailable"} -> ${file.afterSha256 ?? "unavailable"}`);
  return [...lines, ...report.interpretationLimits].map(line => sanitizeForTerminal(line)).join("\n");
}
export function registerReviewArtifactsCommand(program: Command): void {
  program.command("review-artifacts <before.tar> <after.tar>")
    .description("Compare explicit local USTAR skill/plugin snapshots without extraction or execution")
    .requiredOption("--profile <profile>", PROFILES.join(" | "))
    .option("--withhold <paths...>", "Exclude member paths/subtrees from interpretation and member hashes (archive bytes are still read)")
    .option("--json", "Output the versioned review receipt")
    .action(async (before: string, after: string, options: { profile: string; withhold?: string[]; json?: boolean }) => {
      const report = await buildArtifactReview(before, after, options);
      stdoutOutput(options.json ? JSON.stringify(report, null, 2) : renderArtifactReview(report));
      if (!report.byteInventoryComplete || !report.declarationCoverageComplete) process.exitCode = 1;
    });
}
