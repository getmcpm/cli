import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

export const SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo";

/** Legacy initialize and modern discovery share the existing capability/identity pin. */
export function extractServerDeclaration(msg: JSONRPCMessage): {
  capabilities?: unknown;
  serverInfo?: { name?: unknown };
  instructions?: unknown;
} | null {
  if (!("result" in msg) || msg.result === null || typeof msg.result !== "object") return null;
  const result = msg.result;
  const legacy = typeof result.protocolVersion === "string";
  if (!legacy && (
    result.resultType !== "complete" ||
    !Array.isArray(result.supportedVersions) || result.supportedVersions.length === 0 ||
    !result.supportedVersions.every((v) => typeof v === "string") ||
    result.capabilities === null || typeof result.capabilities !== "object" || Array.isArray(result.capabilities)
  )) return null;
  return {
    capabilities: result.capabilities,
    serverInfo: (legacy ? result.serverInfo : result._meta?.[SERVER_INFO_META_KEY]) as { name?: unknown } | undefined,
    instructions: result.instructions,
  };
}
