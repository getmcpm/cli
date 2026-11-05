/** Read-only, bounded Claude Code configuration inventory; never host activation evidence. */
import { isUtf8 } from "node:buffer";
import { constants } from "node:fs";
import { lstat, open, realpath, access } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseTree, type Node, type ParseError } from "jsonc-parser";
import type { Command } from "commander";
import type { McpServerEntry } from "../config/adapters/index.js";
import { McpServerEntrySchema } from "../config/adapters/base.js";
import { classifyWrap } from "../guard/wrap.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import { stdoutOutput } from "../utils/output.js";

type Scope = "local" | "project" | "user" | "managed";
type FileState = "present" | "missing" | "unreadable" | "symlink-skipped" | "not-file" | "too-large" | "malformed";
interface Source { path: string; scope: Scope; state: FileState; }
interface Instruction { path: string; scope: "ancestor" | "project" | "user" | "managed"; state: FileState; applicability: "unknown"; }
interface Server {
  name: string;
  scope: Scope;
  source: string;
  configured: true;
  declaration: "object" | "malformed";
  guardForm: "recognized" | "ambiguous" | "not-recognized" | "unknown";
  possibleShadowedBy: Scope[];
  effective: "unknown";
}
export interface ScopeModel {
  schemaVersion: 1;
  client: "claude-code";
  hostVersion: "unknown";
  root: { path: string; state: "directory" | "missing" | "unreadable" | "not-directory" };
  inventoryComplete: boolean;
  effective: "unknown";
  loaded: "unknown";
  enforced: "unknown";
  sources: Source[];
  servers: Server[];
  instructions: Instruction[];
  coverage: string[];
}
interface ScopeDeps { home?: string; managedDirectory?: string; }
const MAX_CONFIG_BYTES = 1024 * 1024;
const own = (o: Record<string, unknown>, key: string): unknown => Object.hasOwn(o, key) ? o[key] : undefined;
const object = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const code = (error: unknown): string | undefined => (error as NodeJS.ErrnoException)?.code;
const missing = (error: unknown) => code(error) === "ENOENT";

/** Reject every symlink component, including dangling links, before opening a fixed candidate. */
async function inspect(file: string): Promise<FileState> {
  try {
    const parsed = path.parse(file);
    let current = parsed.root;
    const components = file.slice(parsed.root.length).split(path.sep).filter(Boolean);
    for (let i = 0; i < components.length; i++) {
      current = path.join(current, components[i]);
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) return "symlink-skipped";
      if (i < components.length - 1 && !stat.isDirectory()) return "not-file";
      if (i === components.length - 1 && !stat.isFile()) return "not-file";
    }
    await access(file, constants.R_OK);
    return "present";
  } catch (error) {
    return missing(error) ? "missing" : "unreadable";
  }
}

function duplicateKeys(node: Node): boolean {
  if (node.type === "object") {
    const names = node.children?.map(property => property.children?.[0].value) ?? [];
    if (new Set(names).size !== names.length) return true;
  }
  return node.children?.some(duplicateKeys) ?? false;
}

async function readConfig(file: string): Promise<{ state: FileState; value?: Record<string, unknown> }> {
  const state = await inspect(file);
  if (state !== "present") return { state };
  try {
    // Do not follow a final symlink or block if a regular file was replaced by a FIFO.
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) return { state: "not-file" };
      if (stat.size > MAX_CONFIG_BYTES) return { state: "too-large" };
      const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length > MAX_CONFIG_BYTES) return { state: "too-large" };
      const bytes = buffer.subarray(0, length);
      if (!isUtf8(bytes)) return { state: "malformed" };
      const raw = bytes.toString("utf8");
      const errors: ParseError[] = [];
      const tree = parseTree(raw, errors, { disallowComments: true, allowTrailingComma: false });
      if (!tree || errors.length || duplicateKeys(tree)) return { state: "malformed" };
      const value: unknown = JSON.parse(raw);
      return object(value) ? { state: "present", value } : { state: "malformed" };
    } finally { await handle.close(); }
  } catch (error) {
    return { state: code(error) === "ELOOP" ? "symlink-skipped" : "unreadable" };
  }
}

function guardForm(entry: Record<string, unknown>): Server["guardForm"] {
  if (typeof entry.command !== "string" || (entry.args !== undefined &&
      (!Array.isArray(entry.args) || !entry.args.every(a => typeof a === "string")))) return "unknown";
  // Only this branch of the shared recognizer is filesystem-free. Never probe configured node scripts.
  if (/^mcpm(?:\.cmd|\.exe)?$/i.test(path.win32.basename(entry.command))) {
    if (entry.env !== undefined && (!object(entry.env) || !Object.values(entry.env).every(v => typeof v === "string"))) return "unknown";
    const state = classifyWrap(entry as McpServerEntry);
    return state === "plain" ? "not-recognized" : state;
  }
  return /^node(?:\.exe)?$/i.test(path.win32.basename(entry.command)) ? "unknown" : "not-recognized";
}

const COVERAGE = [
  "Configuration snapshot only; configured does not mean active. Host version, effective selection, loading and enforcement are unknown.",
  "Possible shadowing compares declarations using documented Claude Code CLI order local > project > user; no effective winner is inferred. Managed configuration is inventoried, not evaluated as policy.",
  "Fixed instruction candidates from the explicit root through filesystem root combine rather than shadow; contents, imports, rules, nested/on-demand files and additional workspace directories are not read or discovered. AGENTS.md applicability depends on host version and settings.",
  "Settings, approvals, exclusions, plugins, connectors, session flags, environment overrides (including CLAUDE_CONFIG_DIR), alternate project-key spellings and remote/registry-managed policy are not resolved.",
  "No commands, hooks, servers, credential helpers or clients execute. Values and placeholders are neither expanded nor output. Guard form is static metadata, not binary authentication or protection evidence; node launcher identity is unknown.",
  "Symlink file/directory components are skipped; an explicitly selected root is canonicalized. Reads are bounded to 1 MiB per config. Filesystem metadata is a snapshot, not an atomic directory-tree view.",
];

export async function buildScopeModel(projectRoot: string, deps: ScopeDeps = {}): Promise<ScopeModel> {
  const requested = projectRoot === "" ? "" : path.resolve(projectRoot);
  const model: ScopeModel = {
    schemaVersion: 1, client: "claude-code", hostVersion: "unknown",
    root: { path: requested, state: "unreadable" }, inventoryComplete: false,
    effective: "unknown", loaded: "unknown", enforced: "unknown", sources: [], servers: [], instructions: [], coverage: [...COVERAGE],
  };
  if (requested === "") { model.root.state = "not-directory"; return model; }
  try {
    const canonical = await realpath(requested);
    if (!(await lstat(canonical)).isDirectory()) { model.root.state = "not-directory"; return model; }
    model.root = { path: canonical, state: "directory" };
  } catch (error) {
    model.root.state = missing(error) ? "missing" : code(error) === "ENOTDIR" ? "not-directory" : "unreadable";
    return model;
  }
  const root = model.root.path;
  // Home itself may be an OS alias; individual config components must still be real files.
  const home = path.resolve(deps.home ?? os.homedir());
  const managed = path.resolve(deps.managedDirectory ?? (process.platform === "darwin" ? "/Library/Application Support/ClaudeCode" : process.platform === "win32" ? "C:\\Program Files\\ClaudeCode" : "/etc/claude-code"));
  const userPath = path.join(home, ".claude.json");
  const user = await readConfig(userPath);
  function addSource(file: string, scope: Scope, result: Awaited<ReturnType<typeof readConfig>>, container: unknown): void {
    const source: Source = { path: file, scope, state: result.state };
    model.sources.push(source);
    if (source.state !== "present") return;
    if (container === undefined) return;
    if (!object(container)) { source.state = "malformed"; return; }
    for (const [name, entry] of Object.entries(container)) {
      const valid = McpServerEntrySchema.safeParse(entry).success;
      if (!valid) source.state = "malformed";
      model.servers.push({ name, scope, source: file, configured: true, declaration: valid ? "object" : "malformed",
        guardForm: valid && object(entry) ? guardForm(entry) : "unknown", possibleShadowedBy: [], effective: "unknown" });
    }
  }
  let local: unknown;
  let localResult = user;
  if (user.value && own(user.value, "projects") !== undefined) {
    const projects = own(user.value, "projects");
    if (!object(projects)) localResult = { state: "malformed" };
    else {
      // Canonical and explicitly supplied spelling are both candidates, never merged silently.
      const keys = [...new Set([root, requested])].filter(key => Object.hasOwn(projects, key));
      if (keys.length > 1) localResult = { state: "malformed" };
      else if (keys.length) {
        const project = own(projects, keys[0]);
        if (!object(project)) localResult = { state: "malformed" };
        else local = own(project, "mcpServers");
      }
    }
  }
  addSource(userPath, "local", localResult, local);
  const projectPath = path.join(root, ".mcp.json");
  const project = await readConfig(projectPath);
  addSource(projectPath, "project", project, project.value && own(project.value, "mcpServers"));
  addSource(userPath, "user", user, user.value && own(user.value, "mcpServers"));
  const managedPath = path.join(managed, "managed-mcp.json");
  const managedResult = await readConfig(managedPath);
  addSource(managedPath, "managed", managedResult, managedResult.value && own(managedResult.value, "mcpServers"));
  const order: Scope[] = ["local", "project", "user"];
  const namesByScope = new Map(order.map(scope => [scope, new Set(model.servers.filter(s => s.scope === scope).map(s => s.name))]));
  for (const server of model.servers) {
    if (server.scope === "managed") continue;
    server.possibleShadowedBy = order.slice(0, order.indexOf(server.scope)).filter(scope =>
      namesByScope.get(scope)!.has(server.name));
  }
  async function instruction(file: string, scope: Instruction["scope"]): Promise<void> {
    if (model.instructions.some(i => i.path === file)) return;
    model.instructions.push({ path: file, scope, state: await inspect(file), applicability: "unknown" });
  }
  await instruction(path.join(managed, "CLAUDE.md"), "managed");
  await instruction(path.join(home, ".claude", "CLAUDE.md"), "user");
  const ancestors = [];
  for (let dir = root; ; dir = path.dirname(dir)) {
    ancestors.unshift(dir);
    if (path.dirname(dir) === dir) break;
  }
  for (const dir of ancestors) {
    for (const name of ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude/AGENTS.md"]) {
      await instruction(path.join(dir, name), dir === root ? "project" : "ancestor");
    }
  }
  model.inventoryComplete = [...model.sources, ...model.instructions].every(s => s.state === "present" || s.state === "missing");
  return model;
}

export function renderScope(model: ScopeModel): string {
  const safe = (value: string) => sanitizeForTerminal(value);
  return [
    `Claude Code scope inventory: ${safe(model.root.path)} (${model.root.state})`,
    `Fixed-source inventory: ${model.inventoryComplete ? "complete" : "incomplete"}; effective / loaded / enforced: unknown`,
    ...model.sources.map(s => `  ${s.scope}: ${safe(s.path)} (${s.state})`),
    ...model.servers.map(s => `  ${safe(s.name)} [${s.scope}]: ${s.declaration}; guard form: ${s.guardForm}; possible shadowed by: ${s.possibleShadowedBy.join(", ") || "none observed"}; effective: unknown`),
    "Instruction candidates (applicability unknown):",
    ...model.instructions.map(i => `  ${i.scope}: ${safe(i.path)} (${i.state})`),
    ...model.coverage,
  ].join("\n");
}

export function registerScopeCommand(program: Command): void {
  program.command("scope <project-root>")
    .description("Inventory fixed Claude Code project/user sources without executing clients")
    .option("--json", "Output the inventory as JSON")
    .action(async (root: string, options: { json?: boolean }) => {
      const model = await buildScopeModel(root);
      stdoutOutput(options.json ? JSON.stringify(model, null, 2) : renderScope(model));
      if (!model.inventoryComplete) process.exitCode = 1;
    });
}
