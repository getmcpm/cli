import { ParkedServersAdapter } from "./parked-servers.js";
import type { ClientId } from "../paths.js";

export class CursorAdapter extends ParkedServersAdapter {
  readonly clientId: ClientId = "cursor";
  protected readonly clientName = "Cursor";
}
