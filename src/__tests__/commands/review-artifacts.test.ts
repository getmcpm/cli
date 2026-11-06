import { afterEach, expect, it, vi } from "vitest";
import { mkdtemp, writeFile, symlink, rm, realpath } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { Command } from "commander";
import { buildArtifactReview, registerReviewArtifactsCommand, renderArtifactReview } from "../../commands/review-artifacts.js";
import { ustar } from "./ustar-fixture.js";

vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
const roots: string[] = [];
const profile = "claude-plugin-2026-11-06";
const skill = "---\nname: sample\ndescription: Review a sample.\n---\n";
async function fixture(files: Record<string, string | Buffer>) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "mcpm-artifact-test-")));
  roots.push(root);
  const file = path.join(root, "snapshot.tar");
  await writeFile(file, ustar(Object.entries(files).map(([name, body]) => ({ name, body }))));
  return file;
}
const plugin = (extra = {}) => JSON.stringify({ name: "sample", version: "1.0.0", ...extra });
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true }))); });

it("finds executable byte changes beyond version-only manifests without reporting credential values", async () => {
  const before = await fixture({ ".claude-plugin/plugin.json": plugin(), "hooks/hooks.json": '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"node ${CLAUDE_PLUGIN_ROOT}/scripts/check.js SECRET_COMMAND","timeout":5}]}]}}', "scripts/check.js": "OLD_SECRET_SOURCE", "asset.bin": Buffer.from([255]) });
  const after = await fixture({ ".claude-plugin/plugin.json": plugin({ version: "1.0.1" }), "hooks/hooks.json": '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"node ${CLAUDE_PLUGIN_ROOT}/scripts/check.js SECRET_COMMAND","timeout":15}]}]}}', "scripts/check.js": "NEW_SECRET_SOURCE", "asset.bin": Buffer.from([255]) });
  const report = await buildArtifactReview(before, after, { profile });
  expect(report.byteInventoryComplete).toBe(true);
  expect(report.changedFiles.map(f => f.path)).toEqual([".claude-plugin/plugin.json", "hooks/hooks.json", "scripts/check.js"]);
  expect(report.after.references).toContainEqual(expect.objectContaining({ target: "scripts/check.js", source: "hooks/hooks.json", kind: "literal-local" }));
  expect(report.after.components).toContainEqual(expect.objectContaining({ kind: "hook", source: "hooks/hooks.json", handlerType: "command", timeout: 15 }));
  const bytes = Buffer.from("NEW_SECRET_SOURCE");
  expect(report.after.files.find(f => f.path === "scripts/check.js")?.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
  expect(JSON.stringify(report)).not.toMatch(/SECRET_|node \$|OLD_SECRET|NEW_SECRET/);
  expect(report.after.host).toEqual({ configured: "unknown", cached: "unknown", loaded: "unknown", enforced: "unknown", version: "unknown" });
  expect(renderArtifactReview(report)).toContain("Artifact review (claude-plugin-2026-11-06)");
  expect(renderArtifactReview(report)).toContain("modified: scripts/check.js");
  expect(renderArtifactReview(report)).not.toMatch(/SECRET_/);
});

it("supports alternate paths, inline commands and hooks arrays without equating them with loaded components", async () => {
  const root = await fixture({ ".claude-plugin/plugin.json": plugin({ skills: ["./extra"], commands: { about: { content: "SECRET_INLINE" }, status: { source: "./custom/status.md" } }, hooks: ["./custom/hooks.json", { Stop: [{ hooks: [{ type: "command", command: "node -e 'SECRET_JS'" }] }] }] }), "extra/sample/SKILL.md": skill, "custom/status.md": "SECRET_PROMPT", "custom/hooks.json": '{"hooks":{}}' });
  const report = await buildArtifactReview(root, root, { profile });
  expect(report.byteInventoryComplete).toBe(true);
  expect(report.after.components).toContainEqual(expect.objectContaining({ kind: "command", name: "about", form: "inline" }));
  expect(report.after.components).toContainEqual(expect.objectContaining({ kind: "skill", name: "sample", source: "extra/sample/SKILL.md" }));
  expect(report.interpretationLimits.join(" ")).toContain("node -e");
  expect(JSON.stringify(report)).not.toMatch(/SECRET_/);
});

it("keeps unknown modules and other host manifests outside the selected dialect", async () => {
  const root = await fixture({ ".claude-plugin/plugin.json": plugin({ hooks: ["./hooks/claude-band.json"], futureField: {} }), "hooks/claude-band.json": '{"modules":["${CLAUDE_PLUGIN_ROOT}/band/register.tsx"]}', "band/register.tsx": "SECRET_CODE", ".codex-plugin/plugin.json": '{"name":"SECRET_OTHER_HOST"}' });
  const report = await buildArtifactReview(root, root, { profile });
  expect(report.byteInventoryComplete).toBe(true);
  expect(report.declarationCoverageComplete).toBe(false);
  expect(report.after.gaps.map(g => g.code)).toEqual(expect.arrayContaining(["unknown-manifest-field", "unsupported-hook-shape", "other-host-manifest"]));
  expect(report.after.components.some(c => c.source === "band/register.tsx")).toBe(false);
  expect(JSON.stringify(report)).not.toMatch(/SECRET_/);
});

it("does not read outside roots through traversal, symlinks, or sensitive resources", async () => {
  const outside = await fixture({ "secret": "SECRET_OUTSIDE" });
  const root = await fixture({ ".claude-plugin/plugin.json": plugin({ hooks: "./../secret" }), ".env": "SECRET_ENV", "private.txt": "SECRET_WITHHELD" });
  const report = await buildArtifactReview(root, root, { profile, withhold: ["private.txt"] });
  expect(report.byteInventoryComplete).toBe(false);
  expect(report.after.gaps.map(g => g.code)).toEqual(expect.arrayContaining(["outside-root", "withheld"]));
  for (const file of [".env", "private.txt"]) expect(report.after.files.find(f => f.path === file)?.sha256).toBeUndefined();
  const link = path.join(path.dirname(root), "linked.tar"); await symlink(outside, link);
  expect((await buildArtifactReview(link, root, { profile })).before.source.state).toBe("symlink-skipped");
  const archiveLink = path.join(path.dirname(root), "member-link.tar"); await writeFile(archiveLink, ustar([{ name: "linked", type: "2" }]));
  expect((await buildArtifactReview(archiveLink, root, { profile })).before.gaps.map(g => g.code)).toContain("unsupported-record");
  expect(JSON.stringify(report)).not.toMatch(/SECRET_/);
});

it("reports missing skill resources, duplicate names, unknown versions and incomplete manifests", async () => {
  const root = await fixture({ ".claude-plugin/plugin.json": plugin({ skills: "./extra", manifestVersion: 999 }), "skills/sample/SKILL.md": skill + "[guide](references/missing.md)\n`scripts/missing.js`", "extra/sample/SKILL.md": skill });
  const report = await buildArtifactReview(root, root, { profile });
  expect(report.declarationCoverageComplete).toBe(false);
  expect(report.after.gaps.map(g => g.code)).toEqual(expect.arrayContaining(["missing-resource", "duplicate-component", "unknown-manifest-version"]));
  const malformed = await fixture({ ".claude-plugin/plugin.json": '{"name":"x","name":"y"}' });
  expect((await buildArtifactReview(malformed, malformed, { profile })).after.gaps.map(g => g.code)).toContain("malformed-manifest");
  const absent = await fixture({ "README.md": "No declared manifest" });
  expect((await buildArtifactReview(absent, absent, { profile })).declarationCoverageComplete).toBe(false);
  expect((await buildArtifactReview(root, root, { profile: "future-version" })).byteInventoryComplete).toBe(false);
});

it("marks modification during the scan incomplete rather than mixing findings and hashes", async () => {
  const root = await fixture({ ".claude-plugin/plugin.json": plugin(), "scripts/change.js": "before" });
  const after = await fixture({ ".claude-plugin/plugin.json": plugin() });
  const actualOpen = fs.open;
  let changed = false;
  vi.spyOn(fs, "open").mockImplementation(async (...args) => {
    if (!changed && args[0] === after) {
      changed = true;
      await writeFile(root, ustar([{ name: ".claude-plugin/plugin.json", body: plugin({ name: "changed" }) }]));
    }
    return actualOpen(...args);
  });
  const report = await buildArtifactReview(root, after, { profile });
  expect(report.byteInventoryComplete).toBe(false);
  expect(report.before.gaps.map(g => g.code)).toContain("snapshot-changed");
});

it("runs the registered CLI path and exits nonzero for incomplete coverage", async () => {
  const root = await fixture({ "SKILL.md": skill + "[missing](references/missing.md)" });
  const output = vi.spyOn(process.stdout, "write").mockReturnValue(true);
  const previous = process.exitCode;
  try {
    const program = new Command(); registerReviewArtifactsCommand(program);
    await program.parseAsync(["review-artifacts", root, root, "--profile", "agent-skills-2026-11-06", "--json"], { from: "user" });
    expect(process.exitCode).toBe(1);
    const report = JSON.parse(String(output.mock.calls[0][0]));
    expect(report.schemaVersion).toBe(1);
    expect(report.declarationCoverageComplete).toBe(false);
  } finally { process.exitCode = previous; }
});

it("records withheld omissions as gaps and still focuses known byte changes", async () => {
  const before = await fixture({ ".claude-plugin/plugin.json": plugin(), "hooks/check.js": "before", "same.txt": "same" });
  const after = await fixture({ ".claude-plugin/plugin.json": plugin(), "hooks/check.js": "after", "same.txt": "same", "new.txt": "new" });
  const report = await buildArtifactReview(before, after, { profile, withhold: [".git"] });
  expect(report.byteInventoryComplete).toBe(false);
  expect(report.before.gaps).toContainEqual({ code: "withheld-omitted", source: ".git" });
  expect(report.changedFiles).toContainEqual(expect.objectContaining({ path: "hooks/check.js", change: "modified" }));
  expect(report.changedFiles).toContainEqual(expect.objectContaining({ path: "new.txt", change: "unknown" }));
  expect(report.changedFiles.some(f => f.path === "same.txt")).toBe(false);
});

it("does not lose chmod-only changes or invent absence from invalid archives", async () => {
  const before = await fixture({ ".claude-plugin/plugin.json": plugin() });
  const after = await fixture({ ".claude-plugin/plugin.json": plugin() });
  await writeFile(before, ustar([{ name: ".claude-plugin/plugin.json", body: plugin() }, { name: "run.sh", body: "same", mode: 0o644 }]));
  await writeFile(after, ustar([{ name: ".claude-plugin/plugin.json", body: plugin() }, { name: "run.sh", body: "same", mode: 0o755 }]));
  const report = await buildArtifactReview(before, after, { profile });
  expect(report.changedFiles).toContainEqual(expect.objectContaining({ path: "run.sh", change: "modified", beforeMode: 0o644, afterMode: 0o755 }));
  expect(report.changedFiles[0].beforeSha256).toBe(report.changedFiles[0].afterSha256);
  await writeFile(after, ustar([{ name: "link", type: "2" }]));
  const incomplete = await buildArtifactReview(before, after, { profile });
  expect(incomplete.changedFiles.every(f => f.change === "unknown")).toBe(true);
  expect(incomplete.after.files).toEqual([]);
});

it("rejects directories and unknown profiles without opening children or inputs", async () => {
  const archive = await fixture({ ".claude-plugin/plugin.json": plugin() });
  const spy = vi.spyOn(fs, "open");
  const report = await buildArtifactReview(path.dirname(archive), path.dirname(archive), { profile });
  expect(report.byteInventoryComplete).toBe(false);
  expect(report.before.source.state).toBe("not-file");
  expect(spy).not.toHaveBeenCalled();
  await buildArtifactReview(archive, archive, { profile: "future" });
  expect(spy).not.toHaveBeenCalled();
});

it("retains no healthy profile result for empty snapshots or malformed skill metadata", async () => {
  for (const files of [{}, { "SKILL.md": "---\nname: sample\nname: duplicate\ndescription: test\n---\n" }, { "SKILL.md": "---\nname: sample\ndescription: test\nmetadata:\n  version: 4\n---\n" }]) {
    const archive = await fixture(files);
    expect((await buildArtifactReview(archive, archive, { profile: "agent-skills-2026-11-06" })).declarationCoverageComplete).toBe(false);
  }
});

it("finds root skill fallback and command resources while unsupported bundles/defaults remain gaps", async () => {
  const root = await fixture({ ".claude-plugin/plugin.json": plugin({ mcpServers: "./server.mcpb" }), "SKILL.md": skill, "commands/review.md": "Read [guide](references/guide.md) and `scripts/check.js`.", "references/guide.md": "guide", "scripts/check.js": "source", "server.mcpb": Buffer.from([255]), "settings.json": "{}", "bin/tool": "source" });
  const report = await buildArtifactReview(root, root, { profile });
  expect(report.after.components).toContainEqual(expect.objectContaining({ kind: "skill", source: "SKILL.md" }));
  expect(report.after.references.map(r => r.target)).toEqual(expect.arrayContaining(["references/guide.md", "scripts/check.js"]));
  expect(report.after.gaps.map(g => g.code)).toEqual(expect.arrayContaining(["unsupported-component-format", "unsupported-default-component"]));
  expect(report.after.gaps.some(g => g.source === "server.mcpb" && g.code === "malformed-manifest")).toBe(false);
});

it.each([
  { hooks: "./custom" }, { mcpServers: "./custom" }, { lspServers: "./custom" },
  { commands: { run: { source: "./custom" } } }, { skills: "./custom/readme.md" },
])("does not claim complete coverage when a declared component has the wrong path kind: %j", async extra => {
  const archive = await fixture({ ".claude-plugin/plugin.json": plugin(extra), "custom/readme.md": "data" });
  const report = await buildArtifactReview(archive, archive, { profile });
  expect(report.declarationCoverageComplete).toBe(false);
  expect(report.after.gaps.map(g => g.code)).toContain("wrong-component-path-kind");
});

it("accepts an explicitly declared empty directory instead of inventing a missing resource", async () => {
  const archive = await fixture({});
  await writeFile(archive, ustar([{ name: ".claude-plugin/plugin.json", body: plugin({ commands: "./empty" }) }, { name: "empty/", type: "5" }]));
  const report = await buildArtifactReview(archive, archive, { profile });
  expect(report.declarationCoverageComplete).toBe(true);
});

it("recognizes explicit and implied resource directories without treating withheld directories as covered", async () => {
  const archive = await fixture({});
  await writeFile(archive, ustar([{ name: "SKILL.md", body: skill + "[empty](references/) [scripts](scripts/)" }, { name: "references/", type: "5" }, { name: "scripts/check.py", body: "pass" }]));
  const report = await buildArtifactReview(archive, archive, { profile: "agent-skills-2026-11-06" });
  expect(report.declarationCoverageComplete).toBe(true);
  expect(report.after.references.every(reference => reference.state === "present")).toBe(true);
  const withheld = await buildArtifactReview(archive, archive, { profile: "agent-skills-2026-11-06", withhold: ["references"] });
  expect(withheld.after.references).toContainEqual(expect.objectContaining({ target: "references", state: "withheld" }));
});

it("uses resolvable JSON pointers for singleton, array and wrapped declarations", async () => {
  const manifest = plugin({ hooks: { Stop: [{ hooks: [{ type: "command", command: "echo ok" }] }] }, commands: { "about/~": { content: "Hello" } }, mcpServers: [{ "inline/~": { command: "node" } }] });
  const serverFile = JSON.stringify({ mcpServers: { "file/~": { command: "node" } } });
  const archive = await fixture({ ".claude-plugin/plugin.json": manifest, ".mcp.json": serverFile });
  const report = await buildArtifactReview(archive, archive, { profile });
  const resolve = (source: string, pointer: string) => pointer.split("/").slice(1).reduce((value, part) => value[part.replaceAll("~1", "/").replaceAll("~0", "~")], JSON.parse(source));
  for (const component of report.after.components.filter(c => c.pointer)) {
    expect(resolve(component.source === ".mcp.json" ? serverFile : manifest, component.pointer!)).toBeDefined();
  }
});

it("omits credential-bearing Markdown query and fragment values from both report formats", async () => {
  const archive = await fixture({ "SKILL.md": skill + "[run](scripts/run.py?api_key=SECRET_QUERY#SECRET_FRAGMENT)", "scripts/run.py": "pass" });
  const report = await buildArtifactReview(archive, archive, { profile: "agent-skills-2026-11-06" });
  expect(JSON.stringify(report)).not.toMatch(/SECRET_|api_key/);
  expect(renderArtifactReview(report)).not.toMatch(/SECRET_|api_key/);
  expect(report.after.references).toContainEqual(expect.objectContaining({ target: "scripts/run.py", state: "present" }));
  expect(report.after.gaps.map(g => g.code)).toContain("reference-query-not-evaluated");
});

it("keeps unsupported hook fields and unvalidated server entries as coverage gaps", async () => {
  const archive = await fixture({ ".claude-plugin/plugin.json": plugin({ hooks: { Stop: [{ hooks: [{ type: "command", command: "node", args: ["${CLAUDE_PLUGIN_ROOT}/scripts/missing.js"] }] }] }, mcpServers: { empty: {} }, lspServers: { empty: {} } }) });
  const report = await buildArtifactReview(archive, archive, { profile });
  expect(report.declarationCoverageComplete).toBe(false);
  expect(report.after.gaps.map(g => g.code)).toContain("unsupported-hook-field");
  expect(report.after.gaps.map(g => g.code)).toContain("unsupported-server-shape");
});

it("scans commands declared at the archive root and does not call binary Markdown covered", async () => {
  const archive = await fixture({ ".claude-plugin/plugin.json": plugin({ commands: "./" }), "root.md": Buffer.from([255]) });
  const report = await buildArtifactReview(archive, archive, { profile });
  expect(report.after.components).toContainEqual(expect.objectContaining({ kind: "command", source: "root.md" }));
  expect(report.after.gaps.map(g => g.code)).toContain("invalid-component-text");
  expect(report.declarationCoverageComplete).toBe(false);
});

it.each([{ command: "node", type: "future" }, { command: "node", url: "https://example.test" }, { type: "stdio", url: "https://example.test" }])("keeps contradictory or unsupported MCP declarations incomplete: %j", async entry => {
  const archive = await fixture({ ".claude-plugin/plugin.json": plugin({ mcpServers: { sample: entry } }) });
  const report = await buildArtifactReview(archive, archive, { profile });
  expect(report.declarationCoverageComplete).toBe(false);
  expect(report.after.gaps.map(g => g.code)).toContain("unsupported-server-shape");
});

it("does not amplify an oversized hook event name into every handler pointer", async () => {
  const event = "A".repeat(100_000);
  const archive = await fixture({ ".claude-plugin/plugin.json": plugin({ hooks: { [event]: [{ hooks: Array.from({ length: 20 }, () => ({ type: "command", command: "echo ok" })) }] } }) });
  const report = await buildArtifactReview(archive, archive, { profile });
  expect(report.declarationCoverageComplete).toBe(false);
  expect(JSON.stringify(report).length).toBeLessThan(20_000);
  expect(report.after.gaps.map(g => g.code)).toContain("unsupported-hook-event");
});

it.each(["[".repeat(1024 * 1024), "[run](".repeat(150_000)])("scans large unterminated Markdown labels and targets without backtracking", async malformed => {
  const archive = await fixture({ "SKILL.md": skill + malformed + "\n[guide](references/guide.md?api_key=SECRET_QUERY#SECRET_FRAGMENT)", "references/guide.md": "Guide" });
  const report = await buildArtifactReview(archive, archive, { profile: "agent-skills-2026-11-06" });
  expect(report.after.references).toEqual([expect.objectContaining({ target: "references/guide.md", state: "present" })]);
  expect(report.after.gaps.map(g => g.code)).toContain("reference-query-not-evaluated");
  expect(JSON.stringify(report)).not.toMatch(/SECRET_|api_key/);
});
