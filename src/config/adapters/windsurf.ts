import { BaseAdapter } from "./base.js";
import type { ClientId } from "../paths.js";

export class WindsurfAdapter extends BaseAdapter {
  readonly clientId: ClientId = "windsurf";
  protected readonly rootKey = "mcpServers";
}
