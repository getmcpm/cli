import { BaseAdapter } from "./base.js";
import type { ClientId } from "../paths.js";

export class VSCodeAdapter extends BaseAdapter {
  readonly clientId: ClientId = "vscode";
  protected readonly rootKey = "servers";
}
