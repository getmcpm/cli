import path from "node:path";
import { realpath } from "node:fs/promises";
import { readConfig } from "../read-bounded-json.js";
import { BaseAdapter } from "./base.js";
import type { McpServerEntry } from "./index.js";
import { assertClaudePolicyPlan, describeClaudePolicyPlan, planClaudePolicyChange, type ClaudePolicyContext } from "../claude-policy.js";
import type { ClientId } from "../paths.js";

/**
 * Claude Code (the CLI/IDE agent) — user-global MCP config at `~/.claude.json`.
 *
 * Servers live under the top-level `mcpServers` key, so BaseAdapter handles this
 * verbatim; it also preserves every other key in the file (Claude Code stores a
 * lot of unrelated state there — `numStartups`, `oauthAccount`, `projects`, …),
 * since addServer/removeServer read-modify-write and only touch `mcpServers`.
 *
 * Scope: user-global only. Per-project servers (`projects[<abs-path>].mcpServers`)
 * are deliberately not managed here — that nested shape doesn't fit the single
 * top-level rootKey model, and cross-project writes are a separate feature.
 *
 * Distinct from ClaudeDesktopAdapter: different app, different file
 * (`~/Library/Application Support/Claude/claude_desktop_config.json`).
 */
export class ClaudeCodeAdapter extends BaseAdapter {
  constructor(private readonly policyContext: ClaudePolicyContext = {}) { super(); }

  protected override async readRaw(configPath: string): Promise<Record<string, unknown>> {
    const directory = await realpath(path.dirname(configPath)).catch(() => path.dirname(configPath));
    const read = await readConfig(path.join(directory, path.basename(configPath)));
    if (read.state !== "present" && read.state !== "missing") {
      throw new Error(`Claude Code file policy unknown: Current configuration ${read.state}`);
    }
    const raw = read.value ?? {};
    const servers = raw.mcpServers;
    if (servers !== undefined && (servers === null || typeof servers !== "object" || Array.isArray(servers))) {
      throw new Error("Claude Code file policy unknown: Current server map malformed");
    }
    return raw;
  }

  async planServerChange(configPath: string, name: string, entry: McpServerEntry) {
    return planClaudePolicyChange(configPath, name, entry, this.policyContext);
  }

  protected override async writeAtomic(configPath: string, data: Record<string, unknown>, name: string): Promise<void> {
    const entry = (data.mcpServers as Record<string, McpServerEntry>)[name];
    if (entry?.command) {
      const plan = await this.planServerChange(configPath, name, entry);
      assertClaudePolicyPlan(plan);
      process.stderr.write(`mcpm: Claude Code file policy preserved (${plan.reason}): ${describeClaudePolicyPlan(plan)}; overall host policy UNKNOWN (server-managed/MDM/registry/session/other projects unobserved).\n`);
    }
    await super.writeAtomic(configPath, data, name);
  }

  readonly clientId: ClientId = "claude-code";
  protected readonly rootKey = "mcpServers";
}
