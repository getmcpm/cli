/**
 * Platform-neutral entry point that turns a ConfineProfile into a rewritten
 * spawn target for the guard relay. v1 dispatches to the macOS backend only;
 * other platforms report "no backend" so the caller applies the hybrid posture
 * (warn + run unconfined, unless the profile is require_confine).
 */

import type { ConfineProfile } from "./profile.js";
import { isMacosBackendAvailable, buildMacosWrap } from "./backend-macos.js";

export interface WrappedSpawn {
  readonly command: string;
  readonly args: string[];
}

/** Does THIS platform have a working confine backend right now? v1 = macOS. */
export function isConfineBackendAvailable(): boolean {
  return isMacosBackendAvailable();
}

/**
 * Rewrite {command,args} to launch under the OS sandbox for `profile`, or null
 * when no backend is available on this platform. MUST only be called after
 * isConfineBackendAvailable() returned true — pre-checking availability keeps a
 * missing sandbox binary from surfacing as the child-spawn ENOENT of the WRAPPER
 * (which would misattribute H9's spawn-failure forensics to the wrong binary).
 */
export function wrapForConfinement(
  profile: ConfineProfile,
  command: string,
  args: readonly string[],
): WrappedSpawn | null {
  if (!isConfineBackendAvailable()) return null;
  return buildMacosWrap(profile, command, args);
}
