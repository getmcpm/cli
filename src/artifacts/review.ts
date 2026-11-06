/** Byte-bound local artifact review. No archive member is opened or executed. */
import { createHash } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { parseDocument } from "yaml";
import { z } from "zod";
import { fileIdentity, readBoundedBytes, parseJsonObject } from "../config/read-bounded-json.js";
import { MAX_ARCHIVE_BYTES, memberPath, parseUstar } from "./ustar.js";

export const PROFILES = ["agent-skills-2026-11-06", "claude-plugin-2026-11-06"] as const;
export interface ReviewOptions { profile: string; withhold?: string[]; }
interface Gap { code: string; source: string; sourceSha256?: string; pointer?: string; }
interface FileReceipt { path: string; state: "present" | "withheld"; size: number; mode: number; sha256?: string; }
interface Component { kind: string; name: string; source: string; sourceSha256: string; pointer?: string; form: "file" | "inline"; handlerType?: string; timeout?: number; }
interface Reference { source: string; sourceSha256: string; target: string; state: "present" | "withheld" | "missing" | "outside-root"; kind: "literal-local"; }
interface Snapshot {
  source: { path: string; state: string; sha256?: string; size?: number };
  byteInventoryComplete: boolean;
  declarationCoverageComplete: boolean;
  host: { configured: "unknown"; cached: "unknown"; loaded: "unknown"; enforced: "unknown"; version: "unknown" };
  files: FileReceipt[]; components: Component[]; references: Reference[]; gaps: Gap[];
}
export interface ArtifactReview {
  schemaVersion: 1; profile: string; byteInventoryComplete: boolean; declarationCoverageComplete: boolean;
  before: Snapshot; after: Snapshot;
  changedFiles: { path: string; change: "added" | "removed" | "modified" | "unknown"; beforeSha256?: string; afterSha256?: string; beforeMode?: number; afterMode?: number; roles: string[] }[];
  interpretationLimits: string[];
}
const hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const pointerKey = (key: string) => key.replaceAll("~", "~0").replaceAll("/", "~1");
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const records = z.record(z.string(), z.unknown());
const skillSchema = z.object({ name: z.string().min(1).max(64).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/), description: z.string().min(1).max(1024), license: z.string().optional(), compatibility: z.string().min(1).max(500).optional(), metadata: z.record(z.string(), z.string()).optional(), "allowed-tools": z.string().optional() }).passthrough();
const sensitive = (name: string) => name.split("/").some(part => /^(?:\.env(?:\..*)?|\.npmrc|\.netrc|\.git|node_modules|\.ssh|\.aws|\.gnupg|keychains?|credentials?(?:\.json)?|auth\.json)$/i.test(part) || /\.(?:key|pem|p12|pfx|keychain(?:-db)?)$/i.test(part));
const LIMITS = [
  "Only two explicitly supplied uncompressed USTAR00 files are read. No member is extracted, opened, installed or executed; no network, host, credential store or native validator is invoked.",
  "Source identity is the archive bytes and SHA-256, not a verified publisher, repository commit, cache location or host version. Member hashes bind content; mode changes are compared separately. Hashing is not redaction.",
  "Byte inventory and declaration coverage are separate. Neither is a safety verdict. Script/JavaScript, shell, node -e, dynamic imports, prose commands, dependencies, hooks module behavior and native loading semantics are not analyzed.",
  "Only explicit Markdown links, conventional scripts/references/assets tokens and literal CLAUDE_PLUGIN_ROOT paths are referenced. Prose/dynamic references are not fully discoverable. External links are never followed.",
  "Withheld members are omitted from interpretation and member hashes, but their bytes were read inside the archive and affect its digest. Omit sensitive bytes before packaging when they must not be read. Withheld inputs remain gaps.",
  "Configured, cached, loaded and enforced state remain unknown. The Claude profile describes a dated declaration subset, not a native loader/validator, marketplace merge, precedence or activation check.",
  "Reads are bounded to 16 MiB per archive, 2 MiB per member, 256 files, 512 entries and 16 path levels. Both opened input identities are rechecked at the end; this is not an atomic filesystem snapshot or protection from a privileged writer.",
];

async function snapshot(file: string, options: ReviewOptions) {
  const model: Snapshot = { source: { path: file ? path.resolve(file) : "", state: "unreadable" }, byteInventoryComplete: false, declarationCoverageComplete: false,
    host: { configured: "unknown", cached: "unknown", loaded: "unknown", enforced: "unknown", version: "unknown" }, files: [], components: [], references: [], gaps: [] };
  const gap = (code: string, source = "", pointer?: string) => {
    if (model.gaps.length >= 512) return;
    model.gaps.push({ code, source, ...(model.files.find(f => f.path === source)?.sha256 ? { sourceSha256: model.files.find(f => f.path === source)!.sha256 } : {}), ...(pointer ? { pointer } : {}) });
  };
  if (!file || sensitive(model.source.path.replaceAll(path.sep, "/"))) { gap("withheld-source"); model.source.state = "withheld"; return { model, gap }; }
  const read = await readBoundedBytes(model.source.path, MAX_ARCHIVE_BYTES, true);
  model.source.state = read.state;
  if (!read.bytes) { gap("input-" + read.state); return { model, gap }; }
  model.source.sha256 = hash(read.bytes); model.source.size = read.bytes.length;
  const archive = parseUstar(read.bytes);
  if (archive.error) { model.source.state = "invalid-archive"; gap(archive.error); return { model, gap, read }; }
  const withheld = options.withhold ?? [];
  for (const omitted of withheld) if (!archive.members.some(member => member.path === omitted || member.path.startsWith(omitted + "/"))) gap("withheld-omitted", omitted);
  const bytes = new Map<string, Buffer>();
  for (const member of archive.members) {
    const omit = sensitive(member.path) || withheld.some(p => member.path === p || member.path.startsWith(p + "/"));
    model.files.push({ path: member.path, state: omit ? "withheld" : "present", size: member.bytes.length, mode: member.mode, ...(!omit ? { sha256: hash(member.bytes) } : {}) });
    if (omit) gap("withheld", member.path);
    else bytes.set(member.path, member.bytes);
  }
  model.files.sort((a, b) => a.path.localeCompare(b.path, "en"));
  model.byteInventoryComplete = model.gaps.length === 0;
  const directoryExists = (target: string) => target === "" || archive.directories?.includes(target) || model.files.some(file => file.path.startsWith(target + "/"));
  const digest = (source: string) => model.files.find(f => f.path === source)!.sha256!;
  const add = (component: Omit<Component, "sourceSha256">) => {
    if (model.components.length >= 1024) { gap("too-many-components", component.source); return; }
    if (component.kind !== "hook" && model.components.some(c => c.kind === component.kind && c.name === component.name)) gap("duplicate-component", component.source, component.pointer);
    model.components.push({ ...component, sourceSha256: digest(component.source) });
  };
  const reference = (source: string, value: string) => {
    if (model.references.length >= 2048) { gap("too-many-references", source); return; }
    const target = memberPath(value);
    const state = !target ? "outside-root" : sensitive(target) || withheld.some(p => target === p || target.startsWith(p + "/")) ? "withheld" : model.files.find(f => f.path === target)?.state ?? (directoryExists(target) ? "present" : "missing");
    // Never echo a rejected reference or arbitrary command/credential value.
    model.references.push({ source, sourceSha256: digest(source), target: target ?? "[outside-root]", state, kind: "literal-local" });
    if (state !== "present") gap(state === "missing" ? "missing-resource" : state, source);
  };
  const references = (source: string, raw: string, skillRoot?: string) => {
    const values = new Set<string>();
    for (const match of raw.matchAll(/\$\{CLAUDE_PLUGIN_ROOT\}\/([a-zA-Z0-9_./-]+)/g)) values.add(match[1]);
    for (const match of raw.matchAll(/(?:^|[\s`'"(])((?:\.\/)?(?:scripts|references|assets|hooks)\/[a-zA-Z0-9_./-]+)/g)) values.add((skillRoot ? skillRoot + "/" : "") + match[1].replace(/^\.\//, ""));
    if (skillRoot !== undefined) {
      // Consume each target once so unterminated labels/targets cannot cause quadratic backtracking.
      let label = false;
      for (let i = 0; i < raw.length; i++) {
        if (raw[i] === "[") label = true;
        else if (raw[i] === "\n") label = false;
        else if (raw[i] === "]") {
          const linked = label && raw[i + 1] === "(";
          label = false;
          if (!linked) continue;
          const start = i + 2;
          i = start;
          while (i < raw.length && raw[i] !== ")" && !/\s/.test(raw[i])) i++;
          if (raw[i] !== ")" || i === start) continue;
          const target = raw.slice(start, i);
          const value = target.split(/[?#]/)[0];
          if (!value || /^[a-z][a-z0-9+.-]*:/i.test(value)) continue;
          if (target.split("#")[0].includes("?")) gap("reference-query-not-evaluated", source);
          values.add((skillRoot ? skillRoot + "/" : "") + value.replace(/^\.\//, ""));
        }
      }
    }
    for (const value of values) reference(source, value);
  };
  const json = (source: string) => {
    const input = bytes.get(source);
    const parsed = input && parseJsonObject(input);
    if (!parsed || !records.safeParse(parsed).success) { gap("malformed-manifest", source); return undefined; }
    return parsed;
  };
  const skill = (source: string) => {
    const input = bytes.get(source);
    if (!input || !isUtf8(input)) { gap("invalid-skill", source); return; }
    const raw = input.toString("utf8");
    const front = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(raw);
    try {
      if (!front) throw new Error();
      const document = parseDocument(front[1], { uniqueKeys: true });
      if (document.errors.length) throw new Error();
      const parsed = skillSchema.safeParse(document.toJS({ maxAliasCount: 0 }));
      if (!parsed.success) throw new Error();
      const root = path.posix.dirname(source) === "." ? "" : path.posix.dirname(source);
      if (root && path.posix.basename(root) !== parsed.data.name) gap("skill-name-directory-mismatch", source);
      add({ kind: "skill", name: parsed.data.name, source, form: "file" });
      for (const key of Object.keys(parsed.data)) if (!["name", "description", "license", "compatibility", "metadata", "allowed-tools"].includes(key)) gap("unknown-skill-field", source);
      references(source, raw.slice(front[0].length), root);
      if (parsed.data["allowed-tools"] !== undefined) gap("declared-tool-permissions-not-evaluated", source);
    } catch { gap("invalid-skill", source); }
  };
  const required = (source: string, value: string, kind: "file" | "directory" | "either" = "file"): string | undefined => {
    if (!value.startsWith("./") && !(value === "." && kind === "directory")) { gap("unsupported-component-path", source); return undefined; }
    const result = value === "." || value === "./" ? "" : memberPath(value);
    if (result === undefined) { gap("outside-root", source); return undefined; }
    const isFile = model.files.some(f => f.path === result);
    const isDirectory = directoryExists(result);
    if (!isFile && !isDirectory) { gap("missing-resource", source); return undefined; }
    if (kind === "file" && !isFile || kind === "directory" && !isDirectory) { gap("wrong-component-path-kind", source); return undefined; }
    if (isFile && !bytes.has(result) || withheld.some(p => result === p || result.startsWith(p + "/"))) gap("withheld-resource", source);
    return result;
  };
  const hookMap = (value: unknown, source: string, pointer: string) => {
    if (!object(value)) { gap("unsupported-hook-shape", source, pointer); return; }
    for (const [event, groups] of Object.entries(value)) {
      if (event.length > 128) { gap("unsupported-hook-event", source, pointer); continue; }
      if (!Array.isArray(groups)) { gap("unsupported-hook-shape", source, pointer); continue; }
      for (const [i, group] of groups.entries()) {
        if (!object(group) || !Array.isArray(group.hooks)) { gap("unsupported-hook-shape", source, pointer); continue; }
        if (Object.keys(group).some(key => !["matcher", "hooks"].includes(key))) gap("unsupported-hook-field", source, pointer);
        for (const [j, handler] of group.hooks.entries()) {
          const location = `${pointer}/${pointerKey(event)}/${i}/hooks/${j}`;
          if (!object(handler) || typeof handler.type !== "string" || !["command", "http", "prompt", "agent"].includes(handler.type)) { gap("unsupported-hook-handler", source, location); continue; }
          const bodyKey = handler.type === "http" ? "url" : handler.type === "command" ? "command" : "prompt";
          if (Object.keys(handler).some(key => !["type", bodyKey, "timeout", "statusMessage"].includes(key))) gap("unsupported-hook-field", source, location);
          if (typeof handler[bodyKey] !== "string" || handler.timeout !== undefined && (typeof handler.timeout !== "number" || !Number.isFinite(handler.timeout) || handler.timeout <= 0)) gap("unsupported-hook-handler", source, location);
          add({ kind: "hook", name: location, source, pointer: location, form: source === ".claude-plugin/plugin.json" ? "inline" : "file", handlerType: handler.type,
            ...(typeof handler.timeout === "number" && Number.isFinite(handler.timeout) ? { timeout: handler.timeout } : {}) });
          if (typeof handler.command === "string") {
            references(source, handler.command);
            if (/(?:^|\s)-(?:e|c)\b|process\.env|\$\(|`/.test(handler.command)) gap("dynamic-command-not-resolved", source, location);
          }
        }
      }
    }
  };
  if (options.profile === PROFILES[0]) {
    if (!bytes.has("SKILL.md")) gap("missing-skill", "SKILL.md"); else skill("SKILL.md");
  } else {
    const source = ".claude-plugin/plugin.json";
    const manifest = bytes.has(source) ? json(source) : undefined;
    if (!manifest) gap("missing-or-incomplete-manifest", source);
    else {
      if (typeof manifest.name !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(manifest.name)) gap("invalid-plugin-name", source);
      if (manifest.version !== undefined && typeof manifest.version !== "string") gap("unknown-plugin-version", source);
      if (manifest.version === undefined) gap("unknown-plugin-version", source);
      if (manifest.manifestVersion !== undefined) gap("unknown-manifest-version", source);
      if (typeof manifest.name === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(manifest.name)) add({ kind: "plugin", name: manifest.name, source, form: "file" });
      const known = ["name", "displayName", "version", "description", "author", "homepage", "repository", "license", "keywords", "metadata", "icon", "documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl", "skills", "commands", "agents", "hooks", "mcpServers", "lspServers", "outputStyles", "workflows", "experimental", "defaultEnabled", "dependencies", "settings", "userConfig", "channels", "types"];
      for (const key of Object.keys(manifest)) if (!known.includes(key)) gap("unknown-manifest-field", source);
      for (const key of ["experimental", "dependencies", "settings", "userConfig", "channels", "types"]) if (manifest[key] !== undefined) gap("unsupported-manifest-field", source, "/" + key);
      const paths = (value: unknown, key: string, defaults: string[], additive = false): string[] => {
        if (value === undefined) return defaults;
        const list = Array.isArray(value) ? value : [value];
        const result = additive ? [...defaults] : [];
        for (const item of list) {
          if (typeof item !== "string") { gap("unsupported-component-shape", source, "/" + key); continue; }
          const p = required(source, item, key === "skills" ? "directory" : key === "agents" ? "file" : "either"); if (p !== undefined) result.push(p);
        }
        return [...new Set(result)];
      };
      for (const root of paths(manifest.skills, "skills", ["skills"], true)) {
        const direct = root ? root + "/SKILL.md" : "SKILL.md";
        if (bytes.has(direct)) skill(direct);
        else for (const file of bytes.keys()) if (file.startsWith(root ? root + "/" : "") && file.endsWith("/SKILL.md") && file.slice(root ? root.length + 1 : 0).split("/").length === 2) skill(file);
      }
      if (manifest.skills === undefined && !model.files.some(file => file.path.startsWith("skills/")) && bytes.has("SKILL.md")) skill("SKILL.md");
      const fileComponent = (kind: string, name: string, target: string) => {
        add({ kind, name, source: target, form: "file" });
        const input = bytes.get(target)!;
        if (!isUtf8(input)) gap("invalid-component-text", target);
        if (isUtf8(input) && target.endsWith(".md")) references(target, input.toString("utf8"), "");
        if (!target.endsWith(kind === "workflow" ? ".js" : ".md")) gap("unsupported-component-format", target);
      };
      for (const key of ["commands", "agents", "outputStyles", "workflows"] as const) {
        const kind = key === "outputStyles" ? "output-style" : key.slice(0, -1);
        if (key === "commands" && object(manifest[key])) {
          for (const [name, declaration] of Object.entries(manifest[key])) {
            if (!object(declaration) || (typeof declaration.source === "string") === (typeof declaration.content === "string")) { gap("unsupported-command-shape", source, "/commands"); continue; }
            if (typeof declaration.source === "string") { const target = required(source, declaration.source); if (target && bytes.has(target)) fileComponent(kind, name, target); }
            else { add({ kind, name, source, pointer: "/commands/" + pointerKey(name), form: "inline" }); references(source, String(declaration.content)); }
          }
          continue;
        }
        for (const target of paths(manifest[key], key, [key === "outputStyles" ? "output-styles" : key])) {
          if (bytes.has(target)) fileComponent(kind, path.posix.basename(target).replace(/\.(?:md|js)$/, ""), target);
          else {
            if (key === "agents" && manifest[key] !== undefined) { gap("unsupported-agent-directory", source); continue; }
            const prefix = target ? target + "/" : "";
            for (const file of bytes.keys()) if (file.startsWith(prefix) && (key === "agents" || !file.slice(prefix.length).includes("/")) && file.endsWith(key === "workflows" ? ".js" : ".md")) fileComponent(kind, file.slice(prefix.length).replace(/\.(?:md|js)$/, ""), file);
          }
        }
      }
      for (const key of ["hooks", "mcpServers", "lspServers"] as const) {
        const defaultFile = key === "hooks" ? "hooks/hooks.json" : key === "mcpServers" ? ".mcp.json" : ".lsp.json";
        const configurations: { value: unknown; source: string; pointer: string }[] = [];
        const fromFile = (target: string) => {
          if (!bytes.has(target)) return;
          if (!target.endsWith(".json")) { gap("unsupported-component-format", target); return; }
          const config = json(target); if (!config) return;
          add({ kind: key === "hooks" ? "hooks-file" : "server-file", name: target, source: target, form: "file" });
          if (key === "hooks") for (const field of Object.keys(config)) if (field !== "hooks") gap(field === "modules" ? "unsupported-hook-module" : "unsupported-hook-field", target, "/" + pointerKey(field));
          configurations.push({ value: key === "hooks" ? config.hooks : config, source: target, pointer: key === "hooks" ? "/hooks" : "" });
        };
        fromFile(defaultFile);
        for (const [index, value] of (Array.isArray(manifest[key]) ? manifest[key] : manifest[key] === undefined ? [] : [manifest[key]]).entries()) {
          if (typeof value === "string") { const target = required(source, value); if (target !== undefined) fromFile(target); }
          else configurations.push({ value, source, pointer: `/${key}` + (Array.isArray(manifest[key]) ? `/${index}` : "") });
        }
        for (const config of configurations) {
          if (key === "hooks") hookMap(config.value, config.source, config.pointer);
          else {
            let servers = config.value;
            let location = config.pointer;
            if (object(servers) && object(servers[key])) { servers = servers[key]; location += "/" + key; }
            if (!object(servers)) { gap("unsupported-server-shape", config.source); continue; }
            for (const [name, entry] of Object.entries(servers)) {
              if (!object(entry)) { gap("unsupported-server-shape", config.source); continue; }
              const entryPointer = location + "/" + pointerKey(name);
              const command = typeof entry.command === "string" && entry.command.trim() !== "";
              const url = typeof entry.url === "string" && /^(?:https?|wss?):\/\//.test(entry.url) && URL.canParse(entry.url);
              const serverShape = key === "mcpServers"
                ? command && entry.url === undefined && (entry.type === undefined || entry.type === "stdio") || url && entry.command === undefined && (entry.type === undefined || ["http", "sse", "ws"].includes(String(entry.type)))
                : command && object(entry.extensionToLanguage) && Object.keys(entry.extensionToLanguage).length > 0 && Object.values(entry.extensionToLanguage).every(value => typeof value === "string");
              if (!serverShape) gap("unsupported-server-shape", config.source, entryPointer);
              if (entry.args !== undefined && (!Array.isArray(entry.args) || entry.args.some(arg => typeof arg !== "string"))) gap("unsupported-server-shape", config.source, entryPointer);
              if (Object.keys(entry).some(field => !["command", "args", "url", "type", "extensionToLanguage"].includes(field))) gap("unsupported-server-field", config.source, entryPointer);
              add({ kind: key === "mcpServers" ? "mcp-server" : "lsp-server", name, source: config.source, pointer: entryPointer, form: config.source === source ? "inline" : "file" });
              if (typeof entry.command === "string") references(config.source, entry.command);
              if (Array.isArray(entry.args)) for (const arg of entry.args) if (typeof arg === "string") references(config.source, arg);
            }
          }
        }
      }
    }
    for (const file of bytes.keys()) if (file !== source && /(?:^|\/)(?:plugin\.(?:json|ya?ml)|gemini-extension\.json)$/.test(file)) gap("other-host-manifest", file);
    for (const file of bytes.keys()) if (/^(?:settings\.json$|monitors\/|themes\/|bin\/)/.test(file)) gap("unsupported-default-component", file);
  }
  model.declarationCoverageComplete = model.byteInventoryComplete && model.gaps.length === 0;
  return { model, gap, read };
}

export async function buildArtifactReview(before: string, after: string, options: ReviewOptions): Promise<ArtifactReview> {
  const invalid = !PROFILES.includes(options.profile as typeof PROFILES[number]) || (options.withhold ?? []).some(p => memberPath(p) !== p);
  // Invalid profiles/options never cause artifact reads.
  const first = await snapshot(invalid ? "" : before, options);
  let second: Awaited<ReturnType<typeof snapshot>> | undefined;
  try {
    second = await snapshot(invalid ? "" : after, options);
    for (const entry of [first, second]) {
      if (invalid) entry.gap("unsupported-profile-or-withhold");
      if (!entry.read?.handle) continue;
      let stable = false;
      try { stable = fileIdentity(await entry.read.handle.stat()) === entry.read.identity && fileIdentity(await lstat(entry.model.source.path)) === entry.read.identity; } catch { /* unavailable is incomplete */ }
      if (!stable) { entry.gap("snapshot-changed"); entry.model.source.state = "changed"; entry.model.byteInventoryComplete = false; entry.model.declarationCoverageComplete = false; }
    }
    const complete = first.model.byteInventoryComplete && second.model.byteInventoryComplete;
    const changedFiles: ArtifactReview["changedFiles"] = [];
    for (const name of [...new Set([...first.model.files, ...second.model.files].map(f => f.path))].sort()) {
      const a = first.model.files.find(f => f.path === name), b = second.model.files.find(f => f.path === name);
      const comparable = first.model.source.state === "present" && second.model.source.state === "present" && a?.sha256 !== undefined && b?.sha256 !== undefined;
      if (comparable && a.sha256 === b.sha256 && a.mode === b.mode) continue;
      const roles = [...new Set([...first.model.components, ...second.model.components].filter(c => c.source === name).map(c => c.kind))];
      if ([...first.model.references, ...second.model.references].some(reference => reference.target === name)) roles.push("literal-reference");
      if (/\.(?:[cm]?js|tsx?|py|sh|bash|ps1)$/.test(name) || ((a?.mode ?? 0) | (b?.mode ?? 0)) & 0o111) roles.push("executable-or-source");
      changedFiles.push({ path: name, change: comparable ? "modified" : !complete ? "unknown" : !a ? "added" : !b ? "removed" : "modified", ...(a?.sha256 ? { beforeSha256: a.sha256 } : {}), ...(b?.sha256 ? { afterSha256: b.sha256 } : {}), ...(a ? { beforeMode: a.mode } : {}), ...(b ? { afterMode: b.mode } : {}), roles });
    }
    return { schemaVersion: 1, profile: options.profile, byteInventoryComplete: complete, declarationCoverageComplete: first.model.declarationCoverageComplete && second.model.declarationCoverageComplete, before: first.model, after: second.model, changedFiles, interpretationLimits: [...LIMITS] };
  } finally { await first.read?.handle?.close(); await second?.read?.handle?.close(); }
}
