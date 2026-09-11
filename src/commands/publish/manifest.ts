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

// `maxLength` counts CODE POINTS, not UTF-16 units: server.schema.json is JSON
// Schema draft-07, whose maxLength is "the number of characters as defined by
// RFC 8259" (code points), and the registry enforces it with
// santhosh-tekuri/jsonschema v5, which measures with `utf8.RuneCount`. Zod's
// own `.max()` already counts code points, so `.length` here only made the
// message contradict the check it explains — one emoji is two UTF-16 units, so
// a description exactly ONE character over the cap reported "yours is 202".
const descriptionLength = (value: string): number => [...value].length;

const descriptionCapMessage = (value: string): string =>
  `the MCP registry caps description at ${DESCRIPTION_MAX} characters (server.schema.json maxLength); yours is ${descriptionLength(value)}`;

/**
 * The scaffold wizard's description check, shared with the schema below so the
 * prompt cannot refuse what the manifest — and the registry — would accept.
 * `@inquirer/prompts` accepts on `true` and re-prompts with the returned string.
 * publish-scaffold.test.ts pins that the wizard passes THIS function, because a
 * re-inlined `value.length` check would silently refuse a registry-legal
 * description again (one emoji is two UTF-16 units but one character).
 */
export const validateDescription = (value: string): true | string =>
  descriptionLength(value) <= DESCRIPTION_MAX ? true : descriptionCapMessage(value);

export const PublishManifestSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1).max(DESCRIPTION_MAX, {
    error: (issue) => descriptionCapMessage(String(issue.input)),
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
