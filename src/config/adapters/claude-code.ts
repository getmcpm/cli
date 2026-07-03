import { BaseAdapter } from "./base.js";
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
  readonly clientId: ClientId = "claude-code";
  protected readonly rootKey = "mcpServers";
}
