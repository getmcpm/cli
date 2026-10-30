import { ParkedServersAdapter } from "./parked-servers.js";
import type { ClientId } from "../paths.js";

/**
 * Gemini CLI (Google's terminal agent) — user-global MCP config at
 * `~/.gemini/settings.json`.
 *
 * Disabled entries are parked outside `mcpServers` because Gemini ignores the
 * entry-level disabled flag. Enable restores the definition without changing
 * native exclusions or enablement state. Unrelated settings (theme, auth, tool
 * config, …) survive target-only mutations.
 *
 * Entry shape note: Gemini CLI reads `command`/`args`/`env`/`cwd`/`timeout`/`trust`
 * for stdio and `url` (SSE) / `httpUrl` (HTTP) for remote. mcpm writes `url` for
 * URL servers, which Gemini interprets as SSE — the same URL-transport caveat that
 * already applies to non-Cursor clients. Unknown fields survive the round-trip.
 *
 * Scope: user-global only. Per-project `.gemini/settings.json` is deliberately
 * not managed here (same reasoning as ClaudeCodeAdapter's per-project deferral).
 */
export class GeminiCliAdapter extends ParkedServersAdapter {
  readonly clientId: ClientId = "gemini-cli";
  protected readonly clientName = "Gemini CLI";
}
