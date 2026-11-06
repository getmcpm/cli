# Local artifact change review

`mcpm review-artifacts <before.tar> <after.tar> --profile <profile> [--json]`
compares two explicitly supplied local snapshots. This is a bounded experiment
for a maintainer reviewing a concrete update, alongside manual source review.
It identifies changed bytes/modes, declared components and literal local
references without extracting files, executing code, installing anything,
invoking native validators or reading host configuration/credential stores.

## Input and source identity

Prepare **uncompressed USTAR00** archives outside mcpm, with bundle-relative
member paths (no enclosing checkout directory). One skill snapshot has
`SKILL.md` at its root; one plugin snapshot has `.claude-plugin/plugin.json`.
Directory inputs fail before any child read. No archive member path ever reaches
the filesystem. This avoids the ancestor-symlink race in recursive path readers.
The explicitly opened archive must be a regular file without symlink components.

Fixed limits are 16 MiB per archive, 2 MiB per member, 256 regular files,
512 entries and 16 path levels. Only regular files and zero-size directories
are accepted. Magic/version, unsigned header checksum, octal numbers, paths,
payload bounds, zero padding, two zero end blocks and zero-only aligned trailers
are checked. Links, special files, PAX/GNU/sparse extensions, duplicate normalized
names, file/ancestor collisions, invalid UTF-8 names and truncated/concatenated
archives make inventory incomplete. Unsupported archives yield no partial
definitive member inventory. This strict subset intentionally refuses some
archives accepted by native tar. [Primary format reference](https://www.gnu.org/software/tar/manual/html_node/Standard.html).

Source identity means the retained archive bytes and SHA-256. It does not
authenticate a publisher, commit, tag, cache location or supplied label. Member
hashes bind content from that same buffer; permission modes are separate facts.
Archive order/owner/time differences can change the container hash without
changing member content. Both open handles and named file identities are checked
again after both analyses; observed changes make the result incomplete. This is
not an atomic filesystem snapshot or protection from a privileged writer.

## Pinned interpretation profiles

- `agent-skills-2026-11-06`: required YAML frontmatter, naming/description and
  optional standard metadata constraints, root `SKILL.md`, explicit Markdown
  links and conventional resource tokens. The root directory name cannot be
  verified from a flat archive; nested plugin skill names are checked against
  their member directory. Unknown fields remain gaps. [Agent Skills specification](https://agentskills.io/specification).
- `claude-plugin-2026-11-06`: manifest-required static subset of the rolling
  Claude reference retrieved on that date. Default/additional skills,
  replacement command/agent/style/workflow paths, inline commands, hook paths
  and arrays/inline event maps, and path/inline MCP/LSP declarations are
  inventoried. Duplicate component names are gaps. Alternate forms outside
  this subset, modules/Mods, userConfig, dependencies, settings, experimental
  fields, unknown fields and other host manifests remain explicit gaps.
  Declared paths are checked as files or directories as appropriate; empty
  declared directories are retained. Unsupported hook fields, event names over
  128 characters and unsupported or incomplete MCP/LSP entry shapes remain gaps.
  A missing manifest is incomplete even though native Claude supports
  manifest-free plugins. Plugin version strings are opaque release metadata,
  not schema/host versions or byte identity. [Manifest reference](https://code.claude.com/docs/en/plugins-reference),
  [loading reference](https://code.claude.com/docs/en/plugins/loading).

Literal local reference candidates come only from Markdown links, conventional
`scripts/`, `references/`, `assets/`, `hooks/` tokens and literal
`${CLAUDE_PLUGIN_ROOT}/...` paths. They are not inferred executions. Dynamic
commands such as `node -e` remain unresolved; JS imports, shell behavior,
dependencies, module semantics and commands in prose are not analyzed. External
URLs are never followed. A named module file is not proof that a host loads it.
Local Markdown URL queries and fragments are omitted from reference targets;
queries retain an interpretation gap. JSON pointers escape member names and
identify the actual singleton, array or wrapped declaration location.

## Receipt, gaps and sensitive input

JSON is `schemaVersion: 1`. Each side contains the explicit source path/state,
archive digest, member paths/states/sizes/modes/digests, components, references
and gaps. Components/references/gaps identify their source member digest where
available. No raw instruction, command, environment, header or credential values
are emitted. Configured/cached/loaded/enforced state and host version are unknown;
archive preparation provenance belongs in a separate maintainer record.

`byteInventoryComplete` and `declarationCoverageComplete` are separate. Neither
means safe, approved or active. A known hash/mode difference on both retained
sides is a `modified` fact even when unrelated members are withheld. Missing
counterparts under incomplete inventory have `unknown` deltas, never definitive
removal/addition. Exit 0 requires both coverage flags; exit 1 retains the receipt
and its gaps. Consumers must inspect gaps and source states, and stop on unknown
receipt versions. There is no universal score, installer or enforcement claim.

Sensitive-looking members (`.env*`, credential/key files and store directories,
`.git`, `node_modules`) are withheld from interpretation and member hashes by
default. `--withhold <paths...>` adds member paths/subtrees, including inputs
omitted during preparation, as coverage gaps. **Archive buffering still reads
packaged member bytes and the container digest includes them. Hashing is not
redaction.** Omit sensitive bytes before packaging when they must not be read;
record omitted paths with `--withhold` and preserve preparation provenance.

## Actual consumer checkpoint — 2026-11-06

An mcpm maintainer used two candidate receipts plus manual source
review to decide whether to retain the reviewed local Ponytail 5.3.3 source
update or request a rollback to 5.3.2. Inputs were inert USTAR snapshots of the
two pinned upstream tags and the explicitly captured 5.3.3 source directory;
source capture provenance was recorded separately from the product reports.
Only `.git` was omitted before packaging; no `node_modules`/vendor directory was
present or omitted. `.git` was declared with `--withhold`, and the packaged
`.env.example` member was withheld from interpretation/member hashing by default.

The old-to-capture receipt exposed 31 changed/unknown member records. The
tag-to-capture comparison had 208 matching known file bytes/modes, five known
README/translation modifications, two unknown SVG additions and one withheld
`.env.example` record. Declared shared hooks and timeout fields focused the code
review; unresolved `node -e`, opaque Claude-band modules, unsupported manifest
fields and nine other-host manifest gaps prevented a complete interpretation.
Both commands exited **1**, with both coverage flags false.

The maintainer retained the reviewed source update without requesting a rollback.
No global configuration, installation or native activation was changed or
approved. Manual review, rather than the report, interpreted subprocess timeout,
buffer-size and transcript-discovery changes; SVG content was checked separately
without treating the file-role heuristic as a safety verdict. The receipt's
observed value was combining actual captured byte/mode identity with component,
reference and missing-coverage mapping. Time savings, general demand and
superiority over native/Git/APM tooling were not measured.

The first reports belonged to an earlier candidate before the Markdown CPU fix.
A fresh archive of the latest reviewed source reran both comparisons with all
66 installed JavaScript files, all three input hashes and every reported member
hash/size/mode checked against the actual isolated image. Both new reports
matched the reviewed earlier reports, and the maintainer reaffirmed retention.
This is new candidate evidence, not an inherited earlier pass or a publication
claim. Exact archive identities, additional smoke/protocol/confinement results,
receipt locations and remaining gates are in the
[candidate validation record](ARTIFACT-REVIEW-VALIDATION.md). Configured, cached,
loaded and enforced host states remain unknown throughout.
