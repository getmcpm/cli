import { BaseAdapter } from "./base.js";
import type { ClientId } from "../paths.js";

/**
 * Gemini CLI (Google's terminal agent) — user-global MCP config at
 * `~/.gemini/settings.json`.
 *
 * Servers live under the top-level `mcpServers` key, so BaseAdapter handles this
 * verbatim; it also preserves every other key in the file (Gemini CLI stores
 * unrelated settings there — theme, auth, tool config, …), since
 * addServer/removeServer read-modify-write and only touch `mcpServers`.
 *
 * Entry shape note: Gemini CLI reads `command`/`args`/`env`/`cwd`/`timeout`/`trust`
 * for stdio and `url` (SSE) / `httpUrl` (HTTP) for remote. mcpm writes `url` for
 * URL servers, which Gemini interprets as SSE — the same URL-transport caveat that
 * already applies to non-Cursor clients. Unknown fields survive the round-trip.
 *
 * Scope: user-global only. Per-project `.gemini/settings.json` is deliberately
 * not managed here (same reasoning as ClaudeCodeAdapter's per-project deferral).
 */
export class GeminiCliAdapter extends BaseAdapter {
  readonly clientId: ClientId = "gemini-cli";
  protected readonly rootKey = "mcpServers";
}
