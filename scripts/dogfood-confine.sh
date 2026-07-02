#!/usr/bin/env bash
# Hermetic end-to-end dogfood for `mcpm guard --confine` (macOS Seatbelt enforcement).
#
# WHY a throwaway HOME: every mcpm path derives from os.homedir(), which respects
# $HOME on POSIX. Pointing HOME at a mktemp dir gives REAL kernel `sandbox-exec`
# enforcement with zero blast radius — it never touches your real ~/.mcpm, IDE
# configs, or secrets. sandbox-exec is a kernel facility, so your Mac IS the
# accurate env; filesystem isolation (not a different machine) is what makes the
# result trustworthy and reproducible.
#
# WHY it's trustworthy: a POSITIVE CONTROL reads the same decoy secret unconfined
# (must succeed) before the confined child tries (must be denied with EPERM/EACCES,
# not ENOENT). Same path, same code — unconfined success + confined denial proves
# the sandbox is the cause, not a missing file.
#
# This exercises the whole shipped chain CI cannot: enable --confine → marker +
# store → guard run spawn → decide table → sandbox-exec → relay stdio. ubuntu CI
# only runs the mocked arg-vector unit tests. Run this before every release.
#
# macOS only (sandbox-exec). Exits 0 (SKIP) on other platforms.

set -euo pipefail

step() { printf "\n\033[1;36m▶ %s\033[0m\n" "$1"; }

if [[ "$(uname)" != "Darwin" ]]; then
  echo "SKIP: dogfood-confine requires macOS (sandbox-exec)." >&2
  exit 0
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
export DIST="$REPO/dist/index.js"
if [[ ! -f "$DIST" ]]; then
  echo "FAIL: $DIST not found — run 'pnpm build' first (or use 'pnpm dogfood:confine')." >&2
  exit 1
fi

# --- hermetic sandbox home --------------------------------------------------
# Canonicalize (pwd -P): macOS `mktemp -d` lands under /var/folders, and /var is
# a symlink to /private/var. Seatbelt (subpath ...) matches the CANONICAL path,
# so a deny rule derived from a /var/folders home would silently not match a
# /private/var read — a false pass. A real user's $HOME (/Users/<name>) is
# already canonical; resolving symlinks here makes the hermetic home faithful.
DFHOME="$(cd "$(mktemp -d)" && pwd -P)"
cleanup() { rm -rf "$DFHOME"; }
trap cleanup EXIT
export HOME="$DFHOME"
unset MCPM_DISABLE_CONFINE   # the backend MUST be on

step "Hermetic HOME: $HOME"

# --- seed a decoy secret in a denylisted dir (~/.ssh) -----------------------
mkdir -p "$HOME/.ssh"
printf 'TOPSECRET-do-not-read\n' > "$HOME/.ssh/decoy"

# --- tiny stdio MCP server; reads argv[2] and reports if it was denied ------
mkdir -p "$HOME/srv"
cat > "$HOME/srv/server.js" <<'EOF'
// Minimal newline-delimited JSON-RPC MCP server for the confine dogfood.
// argv[2] = absolute path to attempt to read via the "probe" tool. Returns a
// STATUS TOKEN (not the bytes/path) so the guard response scanner doesn't BLOCK
// and muddy the enforcement result.
const fs = require("fs");
const SECRET = process.argv[2];
let buf = "";
process.stdin.on("data", (d) => {
  buf += d.toString("utf8");
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (line.trim()) handle(JSON.parse(line));
  }
});
const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
function handle(msg) {
  switch (msg.method) {
    case "initialize":
      return send({ jsonrpc: "2.0", id: msg.id, result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "decoy", version: "0" },
      }});
    case "notifications/initialized":
      return;
    case "tools/list":
      return send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{
        name: "probe",
        description: "diagnostic self-check",
        inputSchema: { type: "object", properties: {} },
      }]}});
    case "tools/call": {
      let status;
      try { fs.readFileSync(SECRET); status = "read_allowed"; }
      catch (e) { status = "read_denied " + (e.code || "ERR"); }
      return send({ jsonrpc: "2.0", id: msg.id, result: {
        content: [{ type: "text", text: status }],
      }});
    }
    default:
      if (msg.id != null) send({ jsonrpc: "2.0", id: msg.id, result: {} });
  }
}
EOF

# --- driver: control read, happy-path enforcement, then tamper fail-closed --
cat > "$HOME/srv/driver.js" <<'EOF'
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const die = (m) => { console.error("FAIL: " + m); process.exit(1); };

const entry = JSON.parse(
  fs.readFileSync(path.join(process.env.HOME, ".cursor", "mcp.json"), "utf8")
).mcpServers.decoy;
if (!entry || !entry.command) die("decoy entry missing/URL-only after enable");
if (!entry.args.includes("--confine-profile-hash")) die("config not confine-wrapped");

// Positive control: the SAME read succeeds when NOT sandboxed. Proves the file
// exists and is readable, so a denial inside the sandbox is caused by the
// sandbox — not by a missing file or a path typo.
const secretPath = entry.args[entry.args.length - 1]; // last orig arg = secret path
try { fs.readFileSync(secretPath); }
catch (e) { die("control read of " + secretPath + " failed unconfined (" + e.code + ") — test broken, not a real denial"); }

function driveHappy(args) {
  return new Promise((resolve) => {
    const child = spawn(entry.command, args, { stdio: ["pipe", "pipe", "inherit"] });
    const seen = {};
    let buf = "", step = 1, done = false;
    const to = setTimeout(() => { if (!done) { child.kill(); die("timeout — no JSON-RPC responses (stdio broken through relay/sandbox?)"); } }, 15000);
    const send = (m) => child.stdin.write(JSON.stringify(m) + "\n");
    function advance() {
      if (step === 1 && seen[1]) { step = 2; send({ jsonrpc: "2.0", method: "notifications/initialized" }); send({ jsonrpc: "2.0", id: 2, method: "tools/list" }); }
      else if (step === 2 && seen[2]) { step = 3; send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "probe", arguments: {} } }); }
      else if (step === 3 && seen[3]) { done = true; clearTimeout(to); child.kill(); resolve(seen); }
    }
    child.stdout.on("data", (d) => {
      buf += d.toString("utf8");
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let m; try { m = JSON.parse(line); } catch { continue; }
        if (m.id != null) seen[m.id] = m;
        advance();
      }
    });
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "dogfood", version: "0" } } });
  });
}

function runToExit(args) {
  return new Promise((resolve) => {
    const child = spawn(entry.command, args, { stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    child.stderr.on("data", (d) => { err += d.toString("utf8"); });
    const to = setTimeout(() => { child.kill(); resolve({ code: null, timedOut: true, err }); }, 15000);
    child.on("exit", (code) => { clearTimeout(to); resolve({ code, err }); });
  });
}

(async () => {
  // 1. happy path — real kernel sandbox
  const seen = await driveHappy(entry.args);
  if (!seen[1] || !seen[1].result) die("initialize returned no result — stdio broken through relay/sandbox");
  const tools = seen[2] && seen[2].result && seen[2].result.tools;
  if (!Array.isArray(tools) || !tools.some((t) => t.name === "probe")) die("tools/list broken through relay");
  const text = (((seen[3] || {}).result || {}).content || [{}])[0].text || "";
  if (/^read_denied (EPERM|EACCES)/.test(text)) {
    console.log("OK: stdio intact through relay + kernel sandbox; secret read denied (" + text + ")");
  } else if (/^read_denied ENOENT/.test(text)) {
    die("secret not found inside sandbox (ENOENT) — path mismatch, not a real denial: '" + text + "'");
  } else {
    die("secret read was NOT denied inside sandbox — enforcement FAILED: '" + text + "'");
  }

  // 2. tamper — corrupt the embedded profile hash → must fail closed via the
  // CONFINE gate (decide table row 3). Clear the WHOLE pins sidecar set first:
  // the happy-path step above ran a real tools/list that TOFU-writes BOTH
  // pins.json AND its pins.json.integrity sidecar (off-thread). Deleting only
  // pins.json leaves the sidecar, so readPins sees a sidecar with no matching
  // file -> PINS-READ-ERROR, which fails closed for an UNRELATED reason and masks
  // the CONFINE gate under test. (Timing-dependent: locally the sidecar write may
  // not have landed yet; on a slower CI runner it has — which is how the macOS CI
  // leg first caught this.) Remove pins.json, its .integrity sidecar, and any
  // stale .lock so readPins sees a clean first-run state.
  const mcpmDir = path.join(process.env.HOME, ".mcpm");
  fs.rmSync(path.join(mcpmDir, "pins.json"), { force: true });
  fs.rmSync(path.join(mcpmDir, "pins.json.integrity"), { force: true });
  fs.rmSync(path.join(mcpmDir, "pins.json.lock"), { recursive: true, force: true });
  const hi = entry.args.indexOf("--confine-profile-hash");
  const tampered = entry.args.slice();
  tampered[hi + 1] = "0".repeat(64);
  const r = await runToExit(tampered);
  if (r.timedOut) die("tamper: wrapped process hung instead of failing closed");
  if (r.code === 0) die("tamper: mismatched profile hash did NOT fail closed (exit 0) — enforcement bypass");
  if (/PINS-READ-ERROR/.test(r.err)) die("tamper: failed closed on pins, not confine — gate not isolated");
  if (!/CONFINE-BLOCK.*hash mismatch/i.test(r.err)) die("tamper: fail-closed but NOT via the confine hash-mismatch gate — got: " + (r.err.trim().split("\n")[0] || "(no stderr)"));
  console.log("OK: tampered profile hash fails closed via CONFINE gate (exit " + r.code + ")");

  console.log("PASS: confine dogfood");
})();
EOF

# --- fake cursor client with one stdio server enrolling the decoy -----------
step "Writing fake cursor config"
node -e '
  const fs = require("fs"), path = require("path");
  const p = path.join(process.env.HOME, ".cursor", "mcp.json");
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const cfg = { mcpServers: { decoy: { command: "node", args: [
    path.join(process.env.HOME, "srv", "server.js"),
    path.join(process.env.HOME, ".ssh", "decoy"),
  ] } } };
  fs.writeFileSync(p, JSON.stringify(cfg, null, 2), { mode: 0o600 });
'

# --- enable OS confinement --------------------------------------------------
step "mcpm guard enable --confine --client cursor"
node "$DIST" guard enable --confine --client cursor

# --- post-enable assertions: marker + store --------------------------------
step "Verifying enrollment (marker + store)"
node -e '
  const fs = require("fs"), path = require("path");
  const a = JSON.parse(fs.readFileSync(path.join(process.env.HOME, ".cursor", "mcp.json"), "utf8")).mcpServers.decoy.args;
  if (!a.includes("--confine-profile-hash")) { console.error("FAIL: config not confine-wrapped"); process.exit(1); }
  const store = path.join(process.env.HOME, ".mcpm", "guard-confine.yaml");
  if (!fs.existsSync(store)) { console.error("FAIL: confine store not written"); process.exit(1); }
  if (!/tier:\s*standard/.test(fs.readFileSync(store, "utf8"))) { console.error("FAIL: store tier not standard"); process.exit(1); }
  console.log("OK: decoy enrolled — marker embedded + store written (tier standard)");
'

# --- doctor-confine sanity --------------------------------------------------
step "mcpm guard doctor-confine --json"
node -e '
  const { execFileSync } = require("child_process");
  const d = JSON.parse(execFileSync(process.execPath, [process.env.DIST, "guard", "doctor-confine", "--json"], { encoding: "utf8" }));
  if (!d.backendAvailable) { console.error("FAIL: doctor-confine backendAvailable=false (sandbox-exec missing?)"); process.exit(1); }
  const s = (d.servers || []).find((x) => x.name === "decoy");
  if (!s) { console.error("FAIL: doctor-confine does not list decoy"); process.exit(1); }
  console.log("OK: doctor-confine — backend available, decoy enrolled (tier " + s.tier + ", net " + s.net + ")");
'

# --- live enforcement + tamper fail-closed ----------------------------------
step "Live enforcement: control read + sandbox denial + tamper fail-closed"
node "$HOME/srv/driver.js"

# --- confine decision recorded in the event log -----------------------------
step "Verifying CONFINE event logged"
node -e '
  const fs = require("fs"), path = require("path");
  const p = path.join(process.env.HOME, ".mcpm", "guard-events.jsonl");
  if (!fs.existsSync(p)) { console.error("FAIL: no guard-events.jsonl"); process.exit(1); }
  const events = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse);
  if (!events.some((e) => e.category === "CONFINE" || /confine/i.test(JSON.stringify(e)))) { console.error("FAIL: no CONFINE event recorded"); process.exit(1); }
  console.log("OK: CONFINE decision recorded in guard-events.jsonl");
'

printf "\n\033[1;32m✓ confine dogfood PASSED\033[0m — real sandbox-exec enforcement verified end-to-end.\n"
