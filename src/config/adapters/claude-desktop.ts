import { BaseAdapter } from "./base.js";
import type { ClientId } from "../paths.js";

export class ClaudeDesktopAdapter extends BaseAdapter {
  readonly clientId: ClientId = "claude-desktop";
  protected readonly rootKey = "mcpServers";
}
