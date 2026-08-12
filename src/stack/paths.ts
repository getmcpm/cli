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
 * The fix is to STRIP any yaml extension rather than require one, then always
 * append. Because the suffix is appended unconditionally, the result can never
 * equal the input — so no collision guard is needed here. (A guard was written and
 * then removed: no input could reach it, and an unreachable branch is unverifiable,
 * which is the shape this project keeps turning into bugs.)
 */

/** Derive the lock-file path that belongs to a stack file. */
export function lockPathFor(stackPath: string): string {
  return `${stackPath.replace(/\.ya?ml$/i, "")}-lock.yaml`;
}
