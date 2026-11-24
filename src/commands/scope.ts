/** Read-only, bounded client configuration inventories; never host activation evidence. */
import { lstat, realpath } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readConfig, inspect, type FileState } from "../config/read-bounded-json.js";
import { Option, type Command } from "commander";
import type { McpServerEntry } from "../config/adapters/index.js";
import { McpServerEntrySchema } from "../config/adapters/base.js";
import { classifyWrap } from "../guard/wrap.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import { stdoutOutput } from "../utils/output.js";

type Scope = "local" | "project" | "user" | "managed";

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
type VSCodeOrigin = "vscode-project" | "copilot-project" | "vscode-user" | "copilot-user";
interface VSCodeSource extends Source {
  origin: VSCodeOrigin;
  format: "vscode" | "copilot-portable";
  container: "servers" | "mcpServers" | "bare";
  uninterpretedRootFields: boolean | "unknown";
}
interface VSCodeServer extends Omit<Server, "possibleShadowedBy"> {
  origin: VSCodeOrigin;
  format: VSCodeSource["format"];
  sameNameIn: { origin: VSCodeOrigin; source: string }[];
}
export interface VSCodeScopeModel extends Omit<ScopeModel, "client" | "sources" | "servers"> {
  client: "vscode";
  sources: VSCodeSource[];
  servers: VSCodeServer[];
}
interface ScopeDeps { home?: string; managedDirectory?: string; }
const own = (o: Record<string, unknown>, key: string): unknown => Object.hasOwn(o, key) ? o[key] : undefined;
const object = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const code = (error: unknown): string | undefined => (error as NodeJS.ErrnoException)?.code;
const missing = (error: unknown) => code(error) === "ENOENT";

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

const VSCODE_COVERAGE = [
  "Fixed local configuration candidates only. Host version, selected user profile/harness, effective selection, forwarding, loading and enforcement are unknown.",
  "VS Code servers and portable Copilot mcpServers are separate formats/origins. Same-name declarations are duplication, not precedence or an effective winner. Eligible VS Code forwarding depends on the harness and interactive inputs.",
  "Only the default Code/User and ~/.copilot fallback locations are candidates. Named profiles, Insiders, portable/user-data-dir installations, remote configuration, COPILOT_HOME/XDG_CONFIG_HOME overrides, settings and automatic discovery are not resolved.",
  "The explicit directory is one folder, not a discovered workspace. .code-workspace mcp settings, extra workspace folders/URIs, dev containers, managed policy, trust, approvals, exclusions, plugins and connectors are unexamined.",
  "Known server field shapes are checked, not complete native schema/format acceptance. uninterpretedRootFields marks extra root fields without exposing values. Unsupported fields and transport/cwd/envFile/input/environment semantics are not resolved. Portable workspace and user capabilities differ; neither is normalized into VS Code configuration.",
  "Fixed root/ancestor and harness-user instruction candidates are metadata only; applicability is unknown and no instruction precedence is inferred. Local profile instructions, recursive *.instructions.md/rules, nested/on-demand files, custom locations, imports, CODEX_HOME and parent-repository settings are unexamined.",
  "No commands, hooks, servers, credential helpers or clients execute. Values/placeholders and instruction contents are neither expanded nor output. Guard form is static metadata, not authentication or protection evidence; node launcher identity is unknown.",
  "Symlink components are skipped; an explicitly selected root is canonicalized. Config reads are bounded to 1 MiB, reject duplicate keys and invalid UTF-8, and remain filesystem snapshots rather than atomic tree views.",
];
const ScopeEntryWithoutEnvSchema = McpServerEntrySchema.omit({ env: true });

/** Separate fixed VS Code/Copilot candidates, without changing the Claude default. */
export async function buildVSCodeScopeModel(projectRoot: string, deps: { home?: string; platform?: NodeJS.Platform } = {}): Promise<VSCodeScopeModel> {
  const requested = projectRoot === "" ? "" : path.resolve(projectRoot);
  const model: VSCodeScopeModel = {
    schemaVersion: 1, client: "vscode", hostVersion: "unknown", root: { path: requested, state: "unreadable" },
    inventoryComplete: false, effective: "unknown", loaded: "unknown", enforced: "unknown",
    sources: [], servers: [], instructions: [], coverage: [...VSCODE_COVERAGE],
  };
  if (!requested) { model.root.state = "not-directory"; return model; }
  try {
    const canonical = await realpath(requested);
    if (!(await lstat(canonical)).isDirectory()) { model.root.state = "not-directory"; return model; }
    model.root = { path: canonical, state: "directory" };
  } catch (error) {
    model.root.state = missing(error) ? "missing" : code(error) === "ENOTDIR" ? "not-directory" : "unreadable";
    return model;
  }
  const root = model.root.path, home = path.resolve(deps.home ?? os.homedir()), platform = deps.platform ?? process.platform;
  // An injected home keeps fixture reads inside that home; runtime Windows uses APPDATA like the existing adapter.
  const appData = platform === "darwin" ? path.join(home, "Library", "Application Support") : platform === "win32"
    ? (!deps.home && process.env.APPDATA && path.win32.isAbsolute(process.env.APPDATA) ? process.env.APPDATA : home) : path.join(home, ".config");
  const candidates: { path: string; scope: "project" | "user"; origin: VSCodeOrigin; format: VSCodeSource["format"] }[] = [
    { path: path.join(root, ".vscode", "mcp.json"), scope: "project", origin: "vscode-project", format: "vscode" },
    { path: path.join(root, ".mcp.json"), scope: "project", origin: "copilot-project", format: "copilot-portable" },
    { path: path.join(appData, "Code", "User", "mcp.json"), scope: "user", origin: "vscode-user", format: "vscode" },
    { path: path.join(home, ".copilot", "mcp-config.json"), scope: "user", origin: "copilot-user", format: "copilot-portable" },
  ];
  for (const candidate of candidates) {
    const expected = candidate.format === "vscode" ? "servers" : "mcpServers";
    const result = await readConfig(candidate.path, { jsonc: candidate.origin !== "copilot-user" });
    const source: VSCodeSource = { ...candidate, state: result.state, container: expected, uninterpretedRootFields: "unknown" };
    model.sources.push(source);
    if (!result.value) continue;
    const rootKeys = candidate.format === "vscode" ? ["servers", "inputs", "sandbox"] : ["mcpServers"];
    source.uninterpretedRootFields = Object.keys(result.value).some(key => !rootKeys.includes(key));
    const wrong = expected === "servers" ? "mcpServers" : "servers";
    let container = own(result.value, expected);
    const wrongValue = own(result.value, wrong);
    if (candidate.origin === "copilot-project" && !Object.hasOwn(result.value, "mcpServers")) {
      // The pinned parser treats every bare root key as an independent declaration, even "servers".
      source.container = "bare"; source.uninterpretedRootFields = false; container = result.value;
    } else if (wrongValue !== undefined) source.state = "malformed";
    if (container === undefined) continue;
    if (!object(container)) { source.state = "malformed"; continue; }
    for (const [name, entry] of Object.entries(container)) {
      const env = object(entry) ? entry.env : undefined;
      const valid = object(entry) && ScopeEntryWithoutEnvSchema.safeParse(entry).success &&
        (source.container !== "bare" || typeof entry.command === "string" || typeof entry.url === "string") &&
        (env === undefined || (object(env) && Object.values(env).every(value => value === null || typeof value === "string" || (typeof value === "number" && Number.isFinite(value))))) &&
        ["type", "transport", "cwd", "envFile"].every(key => entry[key] === undefined || typeof entry[key] === "string");
      if (!valid) source.state = "malformed";
      model.servers.push({ name, scope: source.scope, source: source.path, origin: source.origin, format: source.format,
        configured: true, declaration: valid ? "object" : "malformed", guardForm: valid && object(entry) ? guardForm(entry) : "unknown",
        sameNameIn: [], effective: "unknown" });
    }
  }
  const names = new Map<string, VSCodeServer[]>();
  for (const server of model.servers) { const peers = names.get(server.name) ?? []; peers.push(server); names.set(server.name, peers); }
  for (const server of model.servers) server.sameNameIn = names.get(server.name)!.filter(peer => peer !== server).map(peer => ({ origin: peer.origin, source: peer.source }));
  async function instruction(file: string, scope: Instruction["scope"]): Promise<void> {
    if (!model.instructions.some(row => row.path === file)) model.instructions.push({ path: file, scope, state: await inspect(file), applicability: "unknown" });
  }
  for (const file of [".copilot/copilot-instructions.md", ".claude/CLAUDE.md", ".codex/AGENTS.md"]) await instruction(path.join(home, file), "user");
  const ancestors = [];
  for (let dir = root; ; dir = path.dirname(dir)) { ancestors.unshift(dir); if (path.dirname(dir) === dir) break; }
  for (const dir of ancestors) for (const file of [".github/copilot-instructions.md", "AGENTS.md", "CLAUDE.md", ".claude/CLAUDE.md"]) await instruction(path.join(dir, file), dir === root ? "project" : "ancestor");
  model.inventoryComplete = [...model.sources, ...model.instructions].every(source => source.state === "present" || source.state === "missing");
  return model;
}

export function renderScope(model: ScopeModel | VSCodeScopeModel): string {
  const safe = (value: string) => sanitizeForTerminal(value);
  if (model.client === "vscode") return [
    `VS Code scope inventory: ${safe(model.root.path)} (${model.root.state})`,
    `Fixed-source inventory: ${model.inventoryComplete ? "complete" : "incomplete"}; effective / loaded / enforced: unknown`,
    ...model.sources.map(source => `  ${source.origin} [${source.format}, ${source.container}]: ${safe(source.path)} (${source.state}); uninterpreted root fields: ${source.uninterpretedRootFields}`),
    ...model.servers.map(server => `  ${safe(server.name)} [${server.origin}]: ${server.declaration}; guard form: ${server.guardForm}; same name in: ${server.sameNameIn.map(peer => peer.origin).join(", ") || "none observed"}; effective: unknown`),
    "Instruction candidates (applicability unknown):",
    ...model.instructions.map(instruction => `  ${instruction.scope}: ${safe(instruction.path)} (${instruction.state})`),
    ...model.coverage,
  ].join("\n");
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
    .description("Inventory fixed project/user sources without executing clients (Claude Code by default)")
    .addOption(new Option("--client <client>", "Client inventory profile").choices(["claude-code", "vscode"]).default("claude-code"))
    .option("--json", "Output the inventory as JSON")
    .action(async (root: string, options: { json?: boolean; client: "claude-code" | "vscode" }) => {
      const model = options.client === "vscode" ? await buildVSCodeScopeModel(root) : await buildScopeModel(root);
      stdoutOutput(options.json ? JSON.stringify(model, null, 2) : renderScope(model));
      if (!model.inventoryComplete) process.exitCode = 1;
    });
}
