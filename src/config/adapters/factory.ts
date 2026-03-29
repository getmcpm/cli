/**
 * Shared factory for creating a ConfigAdapter from a ClientId.
 * Extracted from 6 command files to eliminate duplication.
 */

import type { ClientId } from "../paths.js";
import type { ConfigAdapter } from "./index.js";
import { ClaudeDesktopAdapter } from "./claude-desktop.js";
import { CursorAdapter } from "./cursor.js";
import { VSCodeAdapter } from "./vscode.js";
import { WindsurfAdapter } from "./windsurf.js";

export function getAdapter(clientId: ClientId): ConfigAdapter {
  switch (clientId) {
    case "claude-desktop":
      return new ClaudeDesktopAdapter();
    case "cursor":
      return new CursorAdapter();
    case "vscode":
      return new VSCodeAdapter();
    case "windsurf":
      return new WindsurfAdapter();
    default: {
      const _never: never = clientId;
      throw new Error(`Unknown clientId: ${String(_never)}`);
    }
  }
}
