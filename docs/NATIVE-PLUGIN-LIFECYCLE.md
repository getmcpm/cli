# Native inline-plugin lifecycle experiment

Backlog #158 addresses a concrete limit of [archive-only review](ARTIFACT-REVIEW.md):
comparing installed bytes cannot establish which component an already-running
host executes. The maintainer consumes a bounded native fixture receipt before
accepting activation/drift evidence. This is verification tooling; it adds no
public CLI, model requirement or production guard policy.

## Scope and inputs

One actual Claude Code **2.1.296, Linux arm64** native executable loads a synthetic
local inline plugin. Its manifest declares 1.0.0 or 2.0.0; its command hooks embed
independent `v1`/`v2` build literals in the loaded command. An immutable emitter
records native hook input, session and a unique prompt nonce. The receipt maps
that executed command to its SHA-256 and separately reports the author-declared
bundle version. It does not infer a loaded command from the mutable manifest.

The plugin includes an inert text skill. Native command/skill discovery is
retained separately; **text-skill activation remains unknown**. One hook command
cannot establish all bundled components, publisher authenticity, permission
behavior, arbitrary plugins or another host/platform/version.

[`plugin-lifecycle-pins.json`](../scripts/native-client/plugin-lifecycle-pins.json)
fixes the public native tarball/SRI/executable SHA-256. Its SRI matches the existing
native-client lock. The public Agent SDK 0.3.296 source was inspected as a control
protocol reference (tarball SHA-256
`e966be99b6f047d56165e2ec03822f17a49beebd48ac8efb91dab1e48bcf69a7`);
it is not an added dependency. A small raw-stdio driver sends actual initialize,
settings-inspection, reload and flag-settings controls to the pinned native
binary. Newer `addPlugins` behavior is outside this pin.

## Lifecycle and evidence

| Phase | Required observation |
| --- | --- |
| A baseline | Actual default permission mode, fixed native bytes/version, v1 startup and prompt hook markers. |
| A disk update | Replace v1 files with v2 while A is alive; retain each file's complete bytes/hash and replacement order. Probe before reload and record the observed known command identity. |
| A reload | Correlated native reload success without held state/load errors; same PID/session, executed v2 command. |
| A file disable | Write false, inspect actual native user/effective settings, probe before reload, then reload. The post-reload plugin hook must be absent while an independent blocker completes. |
| A flag lane | Separately apply false at the native flag layer, inspect, reload and probe; do not relabel this as file delivery. |
| B restart disabled | Terminate A, launch fresh B against the false file with identical arguments; no plugin startup/prompt marker, positive independent blocker. |
| C restart enabled | Re-enable the file, launch fresh C; v2 startup/prompt markers return. |

These are eight prompt observations across three processes. Pre-reload state is
measured, not a universal stale-cache promise. Replacements are atomic per file,
not an atomic bundle transaction; write order and intervening native traffic are
retained. There is no sleep-as-applied rule.

The independent harness-owned `UserPromptSubmit` hook blocks every probe before
model processing, including disabled phases. Positive enabled observations must
show the blocker and plugin hook both complete. A rejecting loopback API
tripwire must observe zero requests. Native results require zero turns, API
duration and cost. A settings or hook listing is supplementary metadata:
discovery showed a newly listed user hook could coexist with an older executed
user-hook command. The measured file-inspection/reload sequence is not described
as an instant file-watch guarantee or a host bug.

Native hook progress notifications can arrive after a blocked result. Completion
records join their owned start IDs with PID/session/event agreement, within the
process span and before the next probe; frame arrival before the result is not
required. The driver waits for those bounded completions before its next action.

The gate recomputes phases from the full outgoing requests, native replies,
command lifecycle, hook start/completion events and global marker stream. It
ignores copied per-probe summaries. Missing/duplicate/foreign-session observations,
lost controls/phases, wrong process ownership, bypass mode, stale required
markers, held/error reloads, incomplete snapshots and provider attempts reject
the receipt. Each process has a raw initialize PID/version/default-mode binding;
restarts require new PIDs and sessions. Fixed source files independently bind
the configured bytes. A deliberately corrupted actual retained result must fail
the same gate. Unkeyed hashes detect mismatches; they are not report authentication.

## Run and retain

Obtain the exact public archive named in the pin file without running its installer.
With the pinned Node container base available locally, run:

```sh
bash scripts/dogfood-plugin-lifecycle.sh /tmp/fresh-plugin-evidence /tmp/claude-native-2.1.296.tgz
```

Preparation checks the bounded archive's SHA-256/SRI against the fixed pin and
existing lock, reads only the exact native member to stdout, checks its bytes,
and writes a mode-0600 Docker input. It never executes that binary on the host.
Docker makes it executable inside the fixture image. Only allowlisted scripts,
public inputs and synthetic fixtures enter the build context.

Execution uses no host mounts/network, a read-only root, UID1000, dropped
capabilities, no-new-privileges and bounded writable disposable state/evidence.
No real HOME, client profile, credentials, keychain, model/provider, marketplace
or shared folder is accessed. Update/nonessential traffic is disabled; OS network
denial is the actual external boundary. Default permissions remain enabled.
The runner has finite output/process/time limits, preserves failed observations
and stops the container before export/cleanup if the outer deadline expires.

Retain `report.json`, `inputs.json`, execution/container/image receipts and
independent image/input readback. The report contains complete synthetic
snapshots, raw parsed native messages, global markers, source/input hashes,
native process/session identities, derived command hashes and expected/observed
outcomes. Review those bindings and the actual isolation configuration before
accepting the receipt. Native fixture self-checks run through the existing CI
entry point `node --test scripts/native-client/self-check.mjs`; its small projected
unit capture is explicitly not a full native execution receipt.

## Validation checkpoint

The final attempt-2 run passed all eight observations on the pinned native host:
`v1 / v1 / v2 / v2 / absent / absent / absent / v2`. All three processes closed
cleanly, with distinct native PIDs/sessions and zero API requests, model turns,
API duration and reported cost. The actual retained-result negative control was
rejected by the same gate. The normal CI native entry points passed 75 Node
self-checks with zero failures/skips, including 41 lifecycle checks, on Node
26.11.1 with loopback available. Restricted local runs of the older native tests
aborted inside Node; the successful loopback-enabled run is the evidence used.

The final code/input freeze is SHA-256
`1c6b88f4bf782defebb356a298b60b2d82e810a1b5d33ab1d53b48930565ed85`.
The first full native receipt remains a failed checker result: its legitimate
owned completion notification crossed a blocked-result/control boundary. A
regression and ID-based completion fix preceded the fresh attempt-2 run; replay
of the old capture is separately labeled and does not replace that new run.
Discovery/follow-up receipts remain historical.

The parent independently replayed all 126 raw frames and 15 markers, including
control/process/session/lifetime and complete configured-byte bindings, and
matched the installed image, harness, fixtures, native SRI/SHA, fixed lock and
actual offline isolation. The final report SHA-256 is
`71ca0eef7e97e769b321fb54a19eebca5bb43e22428d3ea80d1a17bd81b772ee`;
the measured image is
`74297895f50f7017298e65afc1a4452f4c30009cb00e510fb6b745927f21dfd9`.
Execution/readback containers were removed. The maintainer **accepted the scoped
hook lifecycle evidence**. Astra independently replayed the final receipt and
negative control, checked source/readback bindings and reviewed the documentation;
the final review passed.
This does not measure a real installed plugin, Ponytail activation or text-skill
execution. No npm release or companion repin is needed for this harness-only change.

Primary references: [plugin loading](https://code.claude.com/docs/en/plugins/loading),
[SDK plugin controls](https://code.claude.com/docs/en/agent-sdk/plugins),
[pinned control interface context](https://code.claude.com/docs/en/agent-sdk/typescript#sdkcontrolreloadpluginsresponse)
and [hook behavior](https://code.claude.com/docs/en/hooks#userpromptsubmit-decision-control).
