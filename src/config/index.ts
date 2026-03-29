/**
 * Barrel export for src/config/.
 */

export { getConfigPath, CLIENT_IDS } from "./paths.js";
export type { ClientId } from "./paths.js";
export { detectInstalledClients } from "./detector.js";
export type { ConfigAdapter, McpServerEntry } from "./adapters/index.js";
export { ClaudeDesktopAdapter } from "./adapters/claude-desktop.js";
export { CursorAdapter } from "./adapters/cursor.js";
export { VSCodeAdapter } from "./adapters/vscode.js";
export { WindsurfAdapter } from "./adapters/windsurf.js";
export { getAdapter } from "./adapters/factory.js";
