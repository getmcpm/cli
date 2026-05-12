/**
 * .mcpm-publish.yaml manifest schema and reader.
 */

import { z } from "zod";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { isEnoent } from "../../utils/fs.js";

export const PublishManifestSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
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
  try {
    return PublishManifestSchema.parse(parseYaml(raw));
  } catch (err) {
    throw new Error(`Invalid .mcpm-publish.yaml: ${err instanceof Error ? err.message : String(err)}`);
  }
}
