/**
 * .mcpm-publish.yaml manifest schema and reader.
 */

import { z } from "zod";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { isEnoent } from "../../utils/fs.js";

// The official MCP Registry's server.schema.json sets maxLength: 100 on
// `description` (confirmed against static.modelcontextprotocol.io); mcpm's
// own manifest schema previously only checked min(1), so an over-cap
// description scaffolded fine, passed `mcpm publish check`, and was only
// rejected by the registry at submit time (backlog #85).
const DESCRIPTION_MAX = 100;

export const PublishManifestSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1).max(DESCRIPTION_MAX, {
    error: (issue) =>
      `the MCP registry caps description at ${DESCRIPTION_MAX} characters (server.schema.json maxLength); yours is ${String(issue.input).length}`,
  }),
  homepage: z.string().url().optional(),
  tags: z.array(z.string()).default([]),
  package: z.object({
    registryType: z.enum(["npm", "pypi", "oci"]),
    identifier: z.string().min(1),
  }),
});

export type PublishManifest = z.infer<typeof PublishManifestSchema>;

const MANIFEST_FILENAME = ".mcpm-publish.yaml";

/**
 * Reads and validates .mcpm-publish.yaml from cwd.
 * Returns null if the file does not exist.
 */
export async function readManifest(cwd = process.cwd()): Promise<PublishManifest | null> {
  const manifestPath = resolve(cwd, MANIFEST_FILENAME);
  let raw: string;
  try {
    raw = await readFile(manifestPath, "utf-8");
  } catch (err) {
    if (isEnoent(err)) return null;
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(`Invalid .mcpm-publish.yaml: ${err instanceof Error ? err.message : String(err)}`);
  }

  // safeParse + formatted issues (not .parse()'s raw ZodError dump) so the
  // user sees a readable "path: message" list, matching parseStackFile's
  // and parseLockFile's pattern in src/stack/schema.ts.
  const result = PublishManifestSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid .mcpm-publish.yaml:\n${issues}`);
  }
  return result.data;
}
