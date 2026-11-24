# Command-hook confinement decision experiment

This is the original #95 isolation/breakage experiment for mcpm's development
and release workflow. It uses direct executable command-hook candidate tasks;
inspect receives synthetic MCP-shaped stdin and the other useful commands
receive empty stdin. No deployed hooks or hook-host dispatch are measured.
HTTP, MCP-tool, prompt,
agent and in-process JavaScript handlers are outside this measurement.

**Decision: NO-GO for integrating this fixed candidate.** The complete measured
experiment found useful-work breakage and detached work surviving cancellation.
The production backend/API remains unchanged; a strict hook backend is unbuilt.

The useful cohort runs Node syntax validation, the actual 41-check native
inline-hook fixture suite, built `guard inspect --json` allow/block cases, and
`pnpm pack --out` with prepared public inputs. Exit 2 for the known blocked frame
is the expected useful result. Baseline and strict runs keep each command/input
contract and compare packed member byte lengths and SHA-256 digests.
The inspect inputs are static MCP-shaped data required by that CLI's input
format; no MCP peer, stdio relay or hook-host dispatch is part of this run.

The separate experimental SBPL starts deny-default. It grants public system
runtime and explicit public workspace/tool reads, task scratch writes, the one
Node executable and process creation, with no network grant. It does not use or
change the production standard profile, which remains allow-default with secret
read denials and selected write/network restrictions. No backend integration,
global settings, real profiles, private paths or provider requests are involved.
See the existing [standard backend](../src/guard/confine/backend-macos.ts) and
the separate [native hook-loading experiment](NATIVE-PLUGIN-LIFECYCLE.md).

## Measurements and retained evidence

The measured host is macOS 27.3 build 26C5035r, with public Node 26.11.1 and
pnpm 10.30.0. Initial strict startup and its three-command diagnostic aborted
before probe output; those attempts prove no sensitive-effect denial. A reviewed
revision takes only unconditional startup rules from the OS-provided
`/System/Library/Sandbox/Profiles/dyld-support.sb`, pinned to SHA-256
`bdfc2354c683c8fb95a39e63fbc8610e9739b0256c89ab880564edefbe73a5ce`.
Apple marks that source a private interface. Unknown bytes stop the experiment;
they are not imported or adapted automatically. Apple profile text is retained
only in local evidence, not distributed in this repository.

With that revision, Node and the OS executable control started successfully.
The same-path effect bootstrap then observed successful unconfined synthetic
read/write/TCP/UDP controls and strict EPERM for all four. Independent sink/write
replay passed. The report SHA-256 is
`96d7a0078d531b7155ffe6a659c26e0e8740eee6590f52bd6ff0d44bed40000f`;
the bootstrap policy SHA-256 is
`604a060d80acfb4f4a591e0bf1af1cd7156683de87095d87dbf41018151bb992`.
This is single-process evidence, separate from the complete run below.

The final complete run observed:

| Useful case | Unconfined | Strict |
| --- | --- | --- |
| Node syntax check | exit 0 | exit 0 |
| Actual 41-check native fixture module | 41 pass | 41 pass |
| Public inspect, benign frame | exit 0, `pass` | exit 1 during startup |
| Public inspect, critical frame | exit 2, `block` | exit 1 during startup |
| pnpm pack | exit 0 | exit 0; identical archive bytes and all 136 member hashes/sizes |

Both confined inspect cases failed at `os.userInfo` / `uv_os_get_passwd` with
ENOENT before producing any verdict. That is real benign-work breakage, not
evidence of a sensitive-read denial. We did not broaden the policy or change
the production CLI to make them work.

The parent, ordinary child and detached grandchild each attempted direct and
symlink reads, out-of-root writes, TCP and UDP. All fifteen role/effect
combinations had successful same-target unconfined controls and strict EPERM.
Each tree retained 34 effect rows: one parent, one child and 32 grandchild rows.
All five effects remained denied throughout the strict tree, including continued
attempts after cancellation. The unconfined sinks received 34 TCP and 34 UDP
messages; the strict sinks received none, and forbidden writes stayed absent.

SIGTERM ended the parent and ordinary child. The detached grandchild retained
its PID/birth/group/command identity, reparented to PID 1, and continued
heartbeats and effects after cancellation. It subsequently self-exited within
the fixed bound. Independent final observations found all sixteen known command
and tree PIDs absent. Safe cleanup does not repair the measured cancellation
failure.

The first full run exited 1 because its checker incorrectly expected benign
action `allow`; the actual public contract is `pass`. A failing regression
reproduced that oracle error before the one-line fix. Prospective replay of the
unchanged failed receipt checked the fix; the fresh second run owns the final
decision. Its exit 0 means the measurement completed and reported NO-GO.

The final local receipt is
`/private/tmp/mcpm-hook-full-attempt2-20261108/evidence/report.json`, SHA-256
`937c02ecbdf36cc9674c6265b987724ec23f49273d2074ff26dea66f7c9ecffd`.
Source freeze `faa6827a3d67f7988ae327fa2cee41bb7454db730c12eacfdf31452af00ab64b`
binds the seven selected source/package/lock inputs; final policy SHA-256 is
`785326acca5d2cc4d24f182965fe3b022fc9ec8cf38282ccd8a6ba60f3551f1b`.
The packed prepared-build archive SHA-256 is
`9a39064a617c76b843e9241b8324a3fc7e09842bc986dce0760b696e7a4805e4`.
This is a local build identity, not a new published release/authentication claim.

The maintainer's independent Python replay imported no checker code. It verified
7,937 retained public input files, source/runtime/OS bindings, raw command and
process observations, every effect and both packed archives. Its
`evidence/parent-verified.json` SHA-256 is
`e3672d9a66502b06e8e13708b358a4d5a4d583a83b0c2f4078aa78ddaca146e1`.
The maintainer accepted the bounded NO-GO evidence. All 29 focused receipt checks
and 104 checks through the three existing native CI entry points passed; this
does not turn the experiment's negative integration decision into a pass.

The complete runner retains command/env/cwd/three-pipe stdin/out/err, public
runtime/dependency/fixture inputs, final policy bytes, synthetic canary and sink
observations, and a parent → ordinary child → detached grandchild tree. Every
process in the effect fixture has its own eight-second self-exit bound; useful
commands instead have a thirty-second watchdog. Specific-PID observations bind
birth, group, initial ancestry, nonce and executed command; observer failures
remain incomplete. Group cancellation and subsequent safety cleanup are separate.
Continued detached heartbeats and sensitive attempts after cancellation are a
NO-GO even if the sandbox keeps denying those effects. Cleanup never turns that
limitation into cancellation success.

## Reproduction and limits

After preparing the public build with the frozen lockfile, run the dependency-free
receipt checks with `node --test scripts/hook-confine/self-check.mjs`. They also
run through the existing native CI self-check entry point. A manual native run
requires review of the exact generated profile, selected public inputs and
disposable layout before invoking:

```sh
node scripts/hook-confine/run.mjs /private/tmp/mcpm-hook-evidence /path/to/public/pnpm
```

The output root must be fresh. The outer process must use an empty environment
with only explicitly selected PATH, synthetic HOME/TMPDIR and locale values.
The runner gives commands separate synthetic homes/configs, disables package
manager downloads/update checks, and uses owned loopback sinks only. It never
signals a PID obtained solely from fixture output: group signals require the
live direct child plus matching independent PID/birth/parent/group observations.
Finite self-expiry is the separate cleanup mechanism for detached work.

These fixtures measure selected file, symlink, TCP/UDP and descendant behavior.
They do not establish all IPC/descriptor/broker channels, arbitrary hostile code,
universal macOS containment or generic hook-host supervision. The existing MCP
stdio confinement dogfood remains separate. No production policy is broadened
to make the useful cohort pass.
Reopen integration for a reviewed alternative that preserves the restrictive
boundary and remeasures the complete useful cohort and descendant lifetime.
This decision does not require a new VM platform, loosen the policy, or authorize
building a production backend.
