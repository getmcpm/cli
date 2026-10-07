/** Package launch coordinates, shared by install, lock, up and verification. */
import { valid as semverValid } from "semver";
import type { Package, ServerEntry } from "./types.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";

const NPM_IDENTIFIER_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI_IDENTIFIER_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const OCI_REPOSITORY = "(?:[a-z0-9]+(?:[.-][a-z0-9]+)*:[0-9]+/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*";
const OCI_IDENTIFIER_RE = new RegExp(`^${OCI_REPOSITORY}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})$|^${OCI_REPOSITORY}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`);
// PEP 440 exact release spellings; no requirement operators, markers, URLs or extras.
const PYPI_VERSION_RE = /^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$/i;

export interface PackageCoordinate {
  registryType: string;
  identifier: string;
  version: string;
}

export function validateIdentifier(identifier: string, registryType: string): void {
  const pattern = registryType === "npm" ? NPM_IDENTIFIER_RE : registryType === "pypi" ? PYPI_IDENTIFIER_RE : registryType === "oci" ? OCI_IDENTIFIER_RE : undefined;
  if (!pattern) throw new Error(`Unsupported registry type: ${JSON.stringify(sanitizeForTerminal(registryType))}`);
  if (/[\x00-\x20\x7f]/.test(identifier) || !pattern.test(identifier)) throw new Error(`Rejected potentially malicious ${registryType} identifier: ${JSON.stringify(sanitizeForTerminal(identifier))}`);
}

export function preferredPackage(entry: ServerEntry): Package {
  for (const registryType of ["npm", "pypi", "oci"]) {
    const pkg = entry.server.packages.find((p) => p.registryType === registryType);
    if (pkg) return pkg;
  }
  throw new Error(`No install path found for ${JSON.stringify(sanitizeForTerminal(entry.server.name))}: no supported packages or compatible remotes`);
}

export function packageCoordinate(pkg: Pick<Package, "registryType" | "identifier" | "version">): PackageCoordinate {
  validateIdentifier(pkg.identifier, pkg.registryType);
  let version = pkg.version;
  if (version !== undefined && /[\x00-\x20\x7f]/.test(version)) throw new Error("Invalid registry package version: whitespace and control characters are not allowed");
  if (pkg.registryType === "oci") {
    const digest = pkg.identifier.match(/@sha256:[a-f0-9]{64}$/)?.[0].slice(1);
    if (digest) {
      // A registry's descriptive release version need not equal an image digest.
      return { registryType: pkg.registryType, identifier: pkg.identifier, version: digest };
    }
    const tag = pkg.identifier.slice(pkg.identifier.lastIndexOf(":") + 1);
    if (tag === "latest" || (version !== undefined && version !== tag)) {
      throw new Error(`Invalid registry package version for ${pkg.identifier}: OCI needs an explicit tag agreeing with package.version, or a sha256 digest`);
    }
    version = tag;
  }
  const exact = version !== undefined && (
    pkg.registryType === "npm" ? semverValid(version) === version :
    pkg.registryType === "pypi" ? PYPI_VERSION_RE.test(version) :
    pkg.registryType === "oci"
  );
  if (!exact) throw new Error(`Invalid registry package version for ${JSON.stringify(sanitizeForTerminal(pkg.identifier))}: an exact ${sanitizeForTerminal(pkg.registryType)} package.version is required (not a publication version, alias or range)`);
  return { registryType: pkg.registryType, identifier: pkg.identifier, version: version! };
}

/** Structural subset so this module does not depend on the lock schema. */
interface LockedCoordinate {
  version: string;
  registryType: string;
  identifier: string;
  packageVersion?: string;
  npmIntegrity?: { npmVersion: string };
  provenance?: { npmVersion: string };
}

export function lockedPackageCoordinate(locked: LockedCoordinate, required = true): PackageCoordinate | undefined {
  if (locked.registryType !== "npm" && (locked.npmIntegrity || locked.provenance)) {
    throw new Error("Conflicting locked package coordinate: npm evidence belongs to a non-npm package; re-lock after reviewing the entry");
  }
  const anchors = [locked.packageVersion, locked.npmIntegrity?.npmVersion, locked.provenance?.npmVersion].filter((v): v is string => v !== undefined);
  if (new Set(anchors).size > 1) throw new Error("Conflicting locked package versions; review the integrity/provenance evidence and re-lock");
  if (anchors.length === 0 && locked.registryType !== "oci") {
    if (!required) return undefined;
    throw new Error("Old lock has no package-version evidence; run mcpm lock to record the actual package coordinate");
  }
  const coordinate = packageCoordinate({ ...locked, version: anchors[0] });
  if (anchors[0] !== undefined && coordinate.version !== anchors[0]) throw new Error("Conflicting locked OCI digest/version; review and re-lock");
  return coordinate;
}

export function assertLockedPackageConsistency(lock: { servers: Record<string, unknown> }): void {
  for (const entry of Object.values(lock.servers)) {
    if (entry && typeof entry === "object" && "version" in entry) lockedPackageCoordinate(entry as LockedCoordinate, false);
  }
}

export function bindLockedPackage(entry: ServerEntry, locked: LockedCoordinate, name: string): PackageCoordinate {
  assertPublication(entry, name, locked.version);
  const coordinate = lockedPackageCoordinate(locked)!;
  packageForCoordinate(entry, coordinate);
  return coordinate;
}

export function packageForCoordinate(entry: ServerEntry, coordinate: PackageCoordinate): Package {
  const candidates = entry.server.packages.filter((p) => p.registryType === coordinate.registryType && p.identifier === coordinate.identifier &&
    (coordinate.registryType === "oci" || p.version === coordinate.version));
  if (candidates.length !== 1 || packageCoordinate(candidates[0]).version !== coordinate.version) {
    throw new Error(`Registry package coordinate differs from lock for ${sanitizeForTerminal(entry.server.name)}; review the listing before re-locking`);
  }
  return candidates[0];
}

export function assertPublication(entry: ServerEntry, name: string, version?: string): void {
  if (entry.server.name !== name || (version !== undefined && entry.server.version !== version)) {
    throw new Error(`Registry publication identity/version differs from requested coordinate for ${sanitizeForTerminal(name)}`);
  }
}
