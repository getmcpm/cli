/**
 * MCP tool definitions for mcpm serve.
 *
 * Each tool has a name, description, and Zod input schema.
 * Handlers are in handlers.ts.
 */

import { z } from "zod";
import { CLIENT_IDS } from "../config/paths.js";

export const TOOL_DEFINITIONS = [
  {
    name: "mcpm_search",
    description: "Search the MCP registry for servers. Returns results with trust scores.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (substring match on server name)" },
        limit: { type: "number", description: "Max results to return (default 20)" },
      },
      required: ["query"],
    },
  },
  {
    name: "mcpm_install",
    description: "Install an MCP server from the registry into detected AI client configs. Runs trust assessment automatically. Rejects servers below the minimum trust score (default 50).",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Server name (e.g. io.github.domdomegg/filesystem-mcp)" },
        client: { type: "string", description: "Install to specific client only (claude-desktop, cursor, vscode, windsurf)" },
        minTrustScore: { type: "number", description: "Minimum trust score to allow install (default 50, range 0-100)" },
      },
      required: ["name"],
    },
  },
  {
    name: "mcpm_info",
    description: "Show full details for an MCP server including trust score breakdown.",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Server name" },
      },
      required: ["name"],
    },
  },
  {
    name: "mcpm_list",
    description: "List all installed MCP servers across detected AI clients.",
    inputSchema: {
      type: "object" as const,
      properties: {
        client: { type: "string", description: "Filter to specific client" },
      },
      required: [],
    },
  },
  {
    name: "mcpm_remove",
    description: "Remove an MCP server from AI client configs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Server name to remove" },
        client: { type: "string", description: "Remove from specific client only" },
      },
      required: ["name"],
    },
  },
  {
    name: "mcpm_audit",
    description: "Scan all installed MCP servers and produce a trust report with scores.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "mcpm_doctor",
    description: "Check MCP setup health: detected clients, available runtimes, configuration issues.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "mcpm_setup",
    description: "Install MCP servers from a natural language description. Searches, evaluates trust, installs the best match for each keyword. Example: 'filesystem and GitHub' installs filesystem + GitHub servers.",
    inputSchema: {
      type: "object" as const,
      properties: {
        description: { type: "string", description: "What you need (e.g. 'filesystem access and GitHub integration')" },
        client: { type: "string", description: "Install to specific client only" },
        minTrustScore: { type: "number", description: "Minimum trust score to auto-install (default 50, range 0-100)" },
      },
      required: ["description"],
    },
  },
  {
    name: "mcpm_up",
    description: "Install all servers from an mcpm.yaml stack file with trust verification. Equivalent to docker-compose up for MCP servers. Runs trust re-assessment and blocks servers that violate the trust policy.",
    inputSchema: {
      type: "object" as const,
      properties: {
        stackFile: { type: "string", description: "Path to mcpm.yaml (default: mcpm.yaml in CWD)" },
        profile: { type: "string", description: "Install only servers matching this profile" },
        dryRun: { type: "boolean", description: "Show what would be installed without making changes" },
      },
      required: [],
    },
  },
] as const;

// Shared field schemas (security #31): a bounded server-name string and a closed
// client enum, so the Zod layer — not just the runtime `validateMcpServerName` /
// `CLIENT_IDS.includes` checks in handlers.ts — is the declarative enforcement
// point. The objects below are `strictObject` so unknown keys are rejected
// instead of silently dropped.
//
// NOTE on `.shape`: these schemas reach the MCP SDK via `.shape` (see
// server/index.ts), which rebuilds a plain `z.object(shape)`. The bounded fields
// and client enum DO propagate through that path (they live on the per-field
// schemas); the object-level `strict` setting does NOT. The runtime guards in
// handlers.ts stay the enforced backstop; `strictObject` additionally hardens any
// direct `.parse()` of these exported schemas.
const serverName = z.string().min(1).max(256);
const clientId = z.enum(CLIENT_IDS);

export const SearchInput = z.strictObject({
  query: z.string().min(1).max(200),
  limit: z.number().int().min(1).max(100).optional().default(20),
});

export const InstallInput = z.strictObject({
  name: serverName,
  client: clientId.optional(),
  minTrustScore: z.number().min(0).max(100).optional().default(50),
});

export const InfoInput = z.strictObject({
  name: serverName,
});

export const ListInput = z.strictObject({
  client: clientId.optional(),
});

export const RemoveInput = z.strictObject({
  name: serverName,
  client: clientId.optional(),
});

export const SetupInput = z.strictObject({
  description: z.string().min(1).max(1000),
  client: clientId.optional(),
  minTrustScore: z.number().min(0).max(100).optional().default(50),
});

export const UpInput = z.strictObject({
  stackFile: z.string().optional().default("mcpm.yaml"),
  profile: z.string().optional(),
  dryRun: z.boolean().optional().default(false),
});
