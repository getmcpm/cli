/**
 * MCP server for mcpm — exposes search, install, audit, and setup as tools.
 *
 * Uses @modelcontextprotocol/sdk with stdio transport.
 * All logic delegates to handlers.ts which wraps existing mcpm functions.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  SearchInput,
  InstallInput,
  InfoInput,
  ListInput,
  RemoveInput,
  SetupInput,
} from "./tools.js";
import {
  handleSearch,
  handleInstall,
  handleInfo,
  handleList,
  handleRemove,
  handleAudit,
  handleDoctor,
  handleSetup,
} from "./handlers.js";
import type { ServerDeps } from "./handlers.js";

// ---------------------------------------------------------------------------
// Wire up real dependencies
// ---------------------------------------------------------------------------

async function createDeps(): Promise<ServerDeps> {
  const { RegistryClient } = await import("../registry/client.js");
  const { detectInstalledClients } = await import("../config/detector.js");
  const { getConfigPath } = await import("../config/paths.js");
  const { getAdapter } = await import("../config/index.js");
  const { scanTier1 } = await import("../scanner/tier1.js");
  const { computeTrustScore } = await import("../scanner/trust-score.js");
  const { addInstalledServer, removeInstalledServer } = await import("../store/servers.js");

  const client = new RegistryClient();

  return {
    registrySearch: async (query, limit) => {
      const result = await client.searchServers(query, { limit });
      return result.servers;
    },
    registryGetServer: (name) => client.getServer(name),
    detectClients: detectInstalledClients,
    getAdapter,
    getConfigPath,
    scanTier1,
    computeTrustScore,
    addToStore: addInstalledServer,
    removeFromStore: removeInstalledServer,
  };
}

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

export async function startServer(): Promise<void> {
  const deps = await createDeps();

  const server = new McpServer({
    name: "mcpm",
    version: "0.1.0",
  });

  // Register tools
  server.tool("mcpm_search", "Search the MCP registry for servers with trust scores", SearchInput.shape, async (args) => {
    const result = await handleSearch(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_install", "Install an MCP server with trust assessment", InstallInput.shape, async (args) => {
    const result = await handleInstall(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_info", "Show full details and trust score for an MCP server", InfoInput.shape, async (args) => {
    const result = await handleInfo(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_list", "List installed MCP servers across AI clients", ListInput.shape, async (args) => {
    const result = await handleList(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_remove", "Remove an MCP server from client configs", RemoveInput.shape, async (args) => {
    const result = await handleRemove(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_audit", "Scan all installed servers and produce trust report", {}, async () => {
    const result = await handleAudit(deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_doctor", "Check MCP setup health", {}, async () => {
    const result = await handleDoctor(deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.tool("mcpm_setup", "Install MCP servers from a natural language description", SetupInput.shape, async (args) => {
    const result = await handleSetup(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  // Start stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
