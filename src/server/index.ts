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
  UpInput,
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
  handleMcpUp,
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

/**
 * Register every mcpm tool on the server. Extracted from startServer so the
 * registration can be unit-tested (fix F.1): a test spies registerTool and
 * asserts every TOOL_DEFINITIONS name is registered exactly once, guarding
 * against future tool/registration divergence.
 *
 * `server` is typed loosely as `Pick<McpServer, "registerTool">` so tests can
 * pass a lightweight spy without constructing a full McpServer.
 */
export function registerTools(
  server: Pick<McpServer, "registerTool">,
  deps: ServerDeps
): void {
  // Register tools using registerTool API
  server.registerTool("mcpm_search", {
    description: "Search the MCP registry for servers with trust scores",
    inputSchema: SearchInput.shape,
  }, async (args) => {
    const result = await handleSearch(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_install", {
    description: "Install an MCP server with trust assessment",
    inputSchema: InstallInput.shape,
    annotations: { destructiveHint: true },
  }, async (args) => {
    const result = await handleInstall(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_info", {
    description: "Show full details and trust score for an MCP server",
    inputSchema: InfoInput.shape,
    annotations: { readOnlyHint: true },
  }, async (args) => {
    const result = await handleInfo(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_list", {
    description: "List installed MCP servers across AI clients",
    inputSchema: ListInput.shape,
    annotations: { readOnlyHint: true },
  }, async (args) => {
    const result = await handleList(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_remove", {
    description: "Remove an MCP server from client configs",
    inputSchema: RemoveInput.shape,
    annotations: { destructiveHint: true },
  }, async (args) => {
    const result = await handleRemove(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_audit", {
    description: "Scan all installed servers and produce trust report",
    annotations: { readOnlyHint: true },
  }, async () => {
    const result = await handleAudit(deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_doctor", {
    description: "Check MCP setup health",
    annotations: { readOnlyHint: true },
  }, async () => {
    const result = await handleDoctor(deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_setup", {
    description: "Install MCP servers from a natural language description",
    inputSchema: SetupInput.shape,
    annotations: { destructiveHint: true },
  }, async (args) => {
    const result = await handleSetup(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });

  server.registerTool("mcpm_up", {
    description: "Install all servers from an mcpm.yaml stack file with trust verification. Equivalent to docker-compose up for MCP servers. Runs trust re-assessment and blocks servers that violate the trust policy. Pass profile to install only servers matching that profile, or dryRun to preview what would be installed without making changes.",
    inputSchema: UpInput.shape,
    annotations: { destructiveHint: true },
  }, async (args) => {
    const result = await handleMcpUp(args, deps);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  });
}

export async function startServer(): Promise<void> {
  const deps = await createDeps();

  const server = new McpServer({
    name: "mcpm",
    // Issue #22: advertise the real package version (injected by tsup at build),
    // not a hardcoded stale "0.1.0".
    version: __PKG_VERSION__,
  });

  registerTools(server, deps);

  // Start stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
