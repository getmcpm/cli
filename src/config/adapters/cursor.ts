import { BaseAdapter } from "./base.js";
import type { ClientId } from "../paths.js";

export class CursorAdapter extends BaseAdapter {
  readonly clientId: ClientId = "cursor";
  protected readonly rootKey = "mcpServers";
}
