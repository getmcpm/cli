/**
 * Stack/lock path derivation — one definition, four consumers.
 *
 * `lock`, `up`, `verify` and `diff` each derived the lock path inline with
 * `stackPath.replace(/\.yaml$/, "-lock.yaml")`. That regex is anchored AND
 * case-sensitive, so any stack path not ending in exactly `.yaml` was returned
 * UNCHANGED — making `lockPath === stackPath`. For `mcpm lock` that meant a plain
 * `writeFile` of the lock over the user's own stack file: their server
 * declarations replaced by generated lock content, reported as success, exit 0.
 * `mcpm.yml` is the obvious case (docker-compose / GitHub Actions habit), but
 * `mcpm.YAML`, `mcpm.yaml.bak` and an extensionless `stack` all self-destructed.
 *
 * The first fix STRIPPED any yaml extension and appended a fixed `-lock.yaml`. That
 * cured the self-overwrite but was not INJECTIVE: `mcpm.yaml`, `mcpm.yml` and
 * `mcpm.YAML` all normalised onto the single path `mcpm-lock.yaml`. With two such
 * files in one directory — a production stack and a scratch copy — `mcpm lock -f
 * mcpm.yml` overwrote the OTHER stack's lock, discarding its trust snapshots and
 * sticky Sigstore provenance baselines, reported as success, exit 0. Proving that the
 * output differs from its own input says nothing about two inputs sharing an output.
 *
 * So the extension is PRESERVED and `-lock` inserted before it. `mcpm.yaml` still maps
 * to `mcpm-lock.yaml`, byte-identical, so no existing lock file moves.
 *
 * Injective, by invertibility: the output is the input with `-lock` inserted at a
 * position recoverable from the output itself (immediately before a trailing yaml
 * extension, or at the end when there is none — `-lock` never ends in a yaml
 * extension, so the two cases cannot be confused). A map you can invert cannot merge
 * two inputs. Parameterising the `-lock` infix would void that argument.
 *
 * A path with no yaml extension gets `-lock` appended and nothing invented:
 * defaulting to `.yaml` would put `stack` and `stack.yaml` back on one output.
 */

/** Derive the lock-file path that belongs to a stack file. */
export function lockPathFor(stackPath: string): string {
  return stackPath.replace(/(\.ya?ml)?$/i, "-lock$1");
}
