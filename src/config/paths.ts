/**
 * OS-aware config file paths for each supported AI client.
 *
 * All paths are derived from os.homedir() and process.platform at call time.
 * An explicit platform override is accepted for testing.
 */

import os from "os";
import path from "path";

export type ClientId = "claude-desktop" | "cursor" | "vscode" | "windsurf";

export const CLIENT_IDS: ClientId[] = [
  "claude-desktop",
  "cursor",
  "vscode",
  "windsurf",
];

/**
 * Returns the base "app data" directory for the current (or overridden) platform.
 *
 * - darwin  → ~/Library/Application Support
 * - win32   → %APPDATA% (falls back to homedir if unset)
 * - linux   → ~/.config
 */
function appDataDir(platform: string, home: string): string {
  if (platform === "darwin") {
    return path.join(home, "Library", "Application Support");
  }
  if (platform === "win32") {
    return process.env["APPDATA"] ?? home;
  }
  // linux and everything else
  return path.join(home, ".config");
}

/**
 * Returns the absolute path to the MCP config file for the given client.
 *
 * @param clientId  - One of the supported client identifiers.
 * @param platform  - Defaults to process.platform. Pass explicitly in tests.
 */
export function getConfigPath(
  clientId: ClientId,
  platform: string = process.platform
): string {
  const home = os.homedir();
  const appData = appDataDir(platform, home);

  switch (clientId) {
    case "claude-desktop":
      return path.join(appData, "Claude", "claude_desktop_config.json");

    case "cursor": {
      if (platform === "win32") {
        return path.join(appData, ".cursor", "mcp.json");
      }
      return path.join(home, ".cursor", "mcp.json");
    }

    case "vscode":
      return path.join(appData, "Code", "User", "mcp.json");

    case "windsurf": {
      if (platform === "win32") {
        return path.join(appData, ".codeium", "windsurf", "mcp_config.json");
      }
      return path.join(home, ".codeium", "windsurf", "mcp_config.json");
    }

    default: {
      // TypeScript exhaustiveness — this branch is reached only with a bad cast.
      const _never: never = clientId;
      throw new Error(`Unknown clientId: ${String(_never)}`);
    }
  }
}
