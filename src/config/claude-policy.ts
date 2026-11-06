/** Claude Code 2.1.296 stdio file-policy projection; never an effective-host permission claim. */
import os from "node:os";
import { isDeepStrictEqual } from "node:util";
import path from "node:path";
import { lstat, realpath } from "node:fs/promises";
import { z } from "zod";
import { readConfig, inspect } from "./read-bounded-json.js";
import { McpServerEntrySchema } from "./adapters/base.js";
import type { McpServerEntry } from "./adapters/index.js";
import { classifyWrap, unwrapEntry } from "../guard/wrap.js";

export interface ClaudePolicyContext {
  home?: string;
  root?: string;
  managedDirectory?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}
type Decision = { decision: "allowed" | "denied" | "unknown" | "absent"; reason: string };
export interface ClaudePolicyPlan {
  schemaVersion: 1;
  profile: "claude-code-2.1.296-stdio-files";
  filePolicy: "preserved" | "blocked" | "unknown";
  hostPolicy: "unknown";
  original: Decision;
  originalUnderlying: Decision;
  proposed: Decision;
  proposedUnderlying: Decision;
  reason: string;
  sources: { scope: string; state: string }[];
  coverage: string[];
}
const Rule = z.union([
  z.strictObject({ serverName: z.string().min(1).refine(value => value.trim() === value) }),
  z.strictObject({ serverCommand: z.array(z.string()).min(1) }),
  z.strictObject({ serverUrl: z.string().min(1) }),
]);
type Rule = z.infer<typeof Rule>;
const Settings = z.looseObject({
  allowedMcpServers: z.array(Rule).optional(),
  deniedMcpServers: z.array(Rule).optional(),
  allowManagedMcpServersOnly: z.boolean().optional(),
  env: z.record(z.string(), z.string()).optional(),
  managedMcpServers: z.record(z.string(), z.unknown()).optional(),
});
const unknown = (reason: string): Decision => ({ decision: "unknown", reason });
export const CLAUDE_POLICY_COVERAGE = [
  "Local stdio file-policy projection for Claude Code 2.1.296; host version, effective selection and native enforcement are unknown.",
  "Server-managed policy, MDM/registry, embedding hosts, session flags, alternate settings sources, other projects and future launches are not observed. They can change the native decision; this is not permission to bypass them.",
  "No client, command, hook, credential helper or server executes. Policy controls are never edited. Managed drop-in directories and unsupported local controls refuse the transformation.",
];

class PolicyUnknown extends Error {}

function expand(value: string, env: NodeJS.ProcessEnv, fallbackEnv: NodeJS.ProcessEnv = {}): string {
  const result = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_match, key: string, fallback: string | undefined) => {
    // Native credential, provider and runtime filtering is outside this projection.
    if (/^(?:INPUT_)?(?:_?CLAUDE_|ANTHROPIC_|OTEL_|AGENT_PROXY_|AWS_|GOOGLE_|GCLOUD_|GCE_|NODE_|BUN_|PYTHON|LD_|DYLD_|GIT_|NO_COLOR$|FORCE_COLOR$)/i.test(key)) {
      throw new PolicyUnknown("Unsupported native-filtered environment reference");
    }
    const pinned = Object.hasOwn(env, key) ? env[key] : undefined;
    const resolved = pinned ?? fallback ?? (Object.hasOwn(fallbackEnv, key) ? fallbackEnv[key] : undefined);
    if (resolved === undefined) throw new PolicyUnknown("Unresolved environment expansion");
    return resolved;
  });
  if (result.includes("${")) throw new PolicyUnknown("Unsupported environment expansion");
  return result;
}
function evaluate(name: string, entry: McpServerEntry, allow: Rule[] | undefined, deny: Rule[], live: NodeJS.ProcessEnv, pinnedAllow: NodeJS.ProcessEnv, fallbackDeny: NodeJS.ProcessEnv): Decision {
  if (!entry.command || entry.url) return unknown("Unsupported or ambiguous transport");
  const command = [entry.command, ...(entry.args ?? [])].map(v => expand(v, live));
  function match(rule: Rule, fallbackEnv: NodeJS.ProcessEnv = {}): boolean {
    if ("serverName" in rule) return rule.serverName === name;
    if ("serverUrl" in rule) return false;
    const candidate = rule.serverCommand.map(v => expand(v, pinnedAllow, fallbackEnv));
    return candidate.length === command.length && candidate.every((v, i) => v === command[i]);
  }
  const denied = deny.findIndex(rule => match(rule, fallbackDeny));
  if (denied >= 0) return { decision: "denied", reason: `deniedMcpServers[${denied}] matches` };
  if (allow === undefined) return { decision: "allowed", reason: "allowedMcpServers unset; no file deny matches" };
  const commandsOnly = allow.some(rule => "serverCommand" in rule);
  const allowed = allow.findIndex(rule => (!commandsOnly || "serverCommand" in rule) && match(rule));
  return allowed >= 0 ? { decision: "allowed", reason: `allowedMcpServers[${allowed}] matches` } :
    { decision: "denied", reason: commandsOnly ? "No exact command allowlist match (name cannot rescue stdio)" : "No allowlist match (empty allows none)" };
}

export async function planClaudePolicyChange(configPath: string, name: string, proposed: McpServerEntry, context: ClaudePolicyContext = {}): Promise<ClaudePolicyPlan> {
  const plan: ClaudePolicyPlan = {
    schemaVersion: 1, profile: "claude-code-2.1.296-stdio-files", filePolicy: "unknown", hostPolicy: "unknown",
    original: unknown("Current entry not evaluated"), originalUnderlying: unknown("Current entry not evaluated"),
    proposed: unknown("Not evaluated"), proposedUnderlying: unknown("Not evaluated"), reason: "Not evaluated",
    sources: [], coverage: [...CLAUDE_POLICY_COVERAGE],
  };
  function refuse(reason: string, state: "blocked" | "unknown" = "unknown"): ClaudePolicyPlan {
    plan.filePolicy = state; plan.reason = reason;
    if (state === "unknown") { plan.proposed = unknown(reason); plan.proposedUnderlying = unknown(reason); }
    return plan;
  }
  try {
    const platform = context.platform ?? process.platform;
    if (platform !== "linux" && platform !== "darwin") return refuse("Unsupported platform/registry managed policy projection");
    const startup = { ...(context.env ?? process.env) };
    if (startup.CLAUDE_CONFIG_DIR || startup.CLAUDE_CODE_SETTINGS_PATH || startup.WSL_DISTRO_NAME || startup.WSL_INTEROP) return refuse("Unsupported alternate configuration or WSL policy source");
    const home = await realpath(context.home ?? os.homedir());
    const root = await realpath(context.root ?? process.cwd());
    const managedCandidate = context.managedDirectory ?? (platform === "darwin" ? "/Library/Application Support/ClaudeCode" : "/etc/claude-code");
    const managed = await realpath(managedCandidate).catch(() => managedCandidate);
    // A present drop-in directory is deliberately unknown until its merge semantics are supported.
    for (const unsupported of [path.join(managed, "managed-settings.d"), ...(platform === "darwin" ? ["/Library/Managed Preferences/com.anthropic.claudecode.plist", path.join(home, "Library/Preferences/com.anthropic.claudecode.plist")] : [])]) {
      try { await lstat(unsupported); return refuse("Unsupported local managed policy source present"); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") return refuse("Unsupported local managed policy source unreadable"); }
    }
    const files = [
      { scope: "user", path: path.join(home, ".claude/settings.json") },
      { scope: "project", path: path.join(root, ".claude/settings.json") },
      { scope: "local", path: path.join(root, ".claude/settings.local.json") },
      { scope: "managed", path: path.join(managed, "managed-settings.json") },
    ];
    for (let ancestor = path.dirname(root); ; ancestor = path.dirname(ancestor)) {
      for (const name of ["settings.json", "settings.local.json"]) {
        const candidate = path.join(ancestor, ".claude", name);
        if (candidate === files[0].path) continue;
        const state = await inspect(candidate);
        if (state !== "missing") return refuse("Ancestor project settings require unsupported root/selection resolution");
      }
      if (ancestor === path.dirname(ancestor)) break;
    }
    try {
      if ((await lstat(path.join(root, ".git"))).isFile()) return refuse("Worktree project-local settings selection is unsupported");
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") return refuse("Project root selection unreadable"); }
    const documents: z.infer<typeof Settings>[] = [];
    for (const file of files) {
      const read = await readConfig(file.path);
      plan.sources.push({ scope: file.scope, state: read.state });
      if (read.state !== "present" && read.state !== "missing") return refuse(`${file.scope} policy ${read.state}`);
      const parsed = Settings.safeParse(read.value ?? {});
      if (!parsed.success) return refuse(`${file.scope} policy has unsupported or malformed rule shapes`);
      if (parsed.data.allowedMcpServers?.some(rule => "serverName" in rule && !/^[A-Za-z0-9_-]+$/.test(rule.serverName))) return refuse(`${file.scope} allowlist name outside supported schema`);
      const raw = read.value ?? {};
      if (raw.managedSourcesBehavior !== undefined || raw.strictPluginOnlyCustomization !== undefined || raw.parentSettings !== undefined || raw.policyHelper !== undefined || raw.policyHelpers !== undefined || raw.wslInheritsWindowsSettings !== undefined) return refuse(`${file.scope} policy uses unsupported selection controls`);
      if (file.scope !== "managed" && parsed.data.allowManagedMcpServersOnly !== undefined) return refuse(`${file.scope} managed-only lock is outside the supported profile`);
      documents.push(parsed.data);
    }
    const managedSettings = documents[3];
    const exclusive = await readConfig(path.join(managed, "managed-mcp.json"));
    plan.sources.push({ scope: "managed-mcp", state: exclusive.state });
    if (exclusive.state !== "missing") return refuse(exclusive.state === "present" ? "managed-mcp exclusive control: user-global definitions are not selected" : `managed-mcp policy ${exclusive.state}`, exclusive.state === "present" ? "blocked" : "unknown");
    if (managedSettings.managedMcpServers && Object.hasOwn(managedSettings.managedMcpServers, name)) return refuse("managedMcpServers supplies this name; user-global definition is shadowed", "blocked");
    const configDirectory = await realpath(path.dirname(configPath)).catch(() => path.dirname(configPath));
    const current = await readConfig(path.join(configDirectory, path.basename(configPath)), { allowEmpty: true });
    if (current.state !== "missing" && current.state !== "present") return refuse(`Current configuration ${current.state}`);
    if (current.value?.env !== undefined) return refuse("Legacy global configuration environment is outside the supported profile");
    const serverMap = current.value?.mcpServers;
    if (serverMap !== undefined && (serverMap === null || typeof serverMap !== "object" || Array.isArray(serverMap))) return refuse("Current server map malformed");
    const original = serverMap && Object.hasOwn(serverMap, name) ? (serverMap as Record<string, McpServerEntry>)[name] : undefined;
    const allowDocuments = managedSettings.allowManagedMcpServersOnly ? [managedSettings] : documents;
    const allow = allowDocuments.some(doc => doc.allowedMcpServers !== undefined) ? allowDocuments.flatMap(doc => doc.allowedMcpServers ?? []) : undefined;
    const deny = documents.flatMap(doc => doc.deniedMcpServers ?? []);
    const live = Object.assign({}, startup, ...documents.map(doc => doc.env ?? {}));
    const pinnedAllow = { ...startup, ...managedSettings.env };
    const fallbackDeny = { ...documents[0].env };
    function check(entry: McpServerEntry): { launch: Decision; underlying: Decision } {
      if (!McpServerEntrySchema.safeParse(entry).success) throw new PolicyUnknown("Malformed launch entry");
      if (classifyWrap(entry) === "ambiguous") throw new PolicyUnknown("Ambiguous guard wrapper");
      const underlying = classifyWrap(entry) === "recognized" ? unwrapEntry(entry)! : entry;
      return { launch: evaluate(name, entry, allow, deny, live, pinnedAllow, fallbackDeny), underlying: evaluate(name, underlying, allow, deny, live, pinnedAllow, fallbackDeny) };
    }
    if (original) { const checked = check(original); plan.original = checked.launch; plan.originalUnderlying = checked.underlying; }
    else { plan.original = { decision: "absent", reason: "No current entry" }; plan.originalUnderlying = { ...plan.original }; }
    const checked = check(proposed); plan.proposed = checked.launch; plan.proposedUnderlying = checked.underlying;
    // Restoring the exact original removes a legacy wrapper bypass; native denial is the desired outcome.
    if (original && classifyWrap(original) === "recognized" && isDeepStrictEqual(unwrapEntry(original), proposed)) {
      if (plan.proposed.decision === "unknown") return refuse(`proposed: ${plan.proposed.reason}`);
      plan.filePolicy = "preserved";
      plan.reason = "Exact wrapper teardown restores the original native launch decision; no permission is granted";
      return plan;
    }
    for (const [label, decision] of [["proposed", plan.proposed], ["proposed underlying", plan.proposedUnderlying]] as const) {
      if (decision.decision === "unknown") return refuse(`${label}: ${decision.reason}`);
      if (decision.decision === "denied") return refuse(`${label} denied: ${decision.reason}`, "blocked");
    }
    plan.filePolicy = "preserved"; plan.reason = "Proposed and underlying launches pass the supported file-policy projection; current decisions are retained for comparison and overall host policy remains unknown";
    return plan;
  } catch (error) {
    return refuse(error instanceof PolicyUnknown ? error.message : "Policy evaluation unknown: source or launch could not be read safely");
  }
}

export function describeClaudePolicyPlan(plan: ClaudePolicyPlan): string {
  return `current=${plan.original.decision} (${plan.original.reason}); current underlying=${plan.originalUnderlying.decision} (${plan.originalUnderlying.reason}); proposed=${plan.proposed.decision} (${plan.proposed.reason}); proposed underlying=${plan.proposedUnderlying.decision} (${plan.proposedUnderlying.reason})`;
}

export function assertClaudePolicyPlan(plan: ClaudePolicyPlan): void {
  if (plan.filePolicy !== "preserved") throw new Error(`Claude Code file policy ${plan.filePolicy}: ${plan.reason}. ${describeClaudePolicyPlan(plan)}. No configuration write permitted.`);
}
