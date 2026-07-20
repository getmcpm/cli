#!/usr/bin/env bash
#
# Release dogfood — pack the tarball, install it into a CLEAN throwaway project,
# and smoke-run the REAL `mcpm` binary. This gates `pnpm publish`: a broken
# artifact (missing dist, broken bin, an unresolved runtime dep, an un-bundled
# vendored trusted root, an engines mismatch, a dynamic import that only fails on
# a clean install) can NEVER reach npm. Source tests pass on a broken pack — this
# exercises the exact bytes users receive.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Building + packing @getmcpm/cli"
pnpm build >/dev/null
pnpm pack >/dev/null
TARBALL="$ROOT/$(ls -t getmcpm-cli-*.tgz | head -1)"
[ -f "$TARBALL" ] || { echo "FAIL: pnpm pack produced no tarball"; exit 1; }
echo "    tarball: $(basename "$TARBALL")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK" "$TARBALL"' EXIT
cd "$WORK"

echo "==> Clean-installing the packed artifact (pulls prod deps + checks engines)"
npm init -y >/dev/null 2>&1
npm install "$TARBALL" >/dev/null 2>&1
BIN="$WORK/node_modules/.bin/mcpm"
[ -x "$BIN" ] || { echo "FAIL: mcpm bin not installed or not executable"; exit 1; }

fail() { echo "FAIL: $1"; exit 1; }

echo "==> Smoke-testing the installed binary"
"$BIN" --version >/dev/null            || fail "mcpm --version crashed"; echo "    ✓ --version"
"$BIN" --help >/dev/null               || fail "mcpm --help crashed";    echo "    ✓ --help"
"$BIN" guard list-signatures >/dev/null|| fail "guard list-signatures crashed"; echo "    ✓ guard list-signatures (catalog loads)"
"$BIN" completions bash >/dev/null     || fail "completions bash crashed"; echo "    ✓ completions bash"
# `doctor` may exit 1 on a bare runner (missing uvx/docker) — gate on it RUNNING,
# not on a healthy verdict.
"$BIN" doctor >"$WORK/doctor.out" 2>&1 || true
grep -q "mcpm doctor" "$WORK/doctor.out" || fail "mcpm doctor did not run"
echo "    ✓ doctor runs"
# F8 crypto: confirm the vendored Sigstore trust material shipped inside the bundle
# (files:["dist"] — the trusted root is inlined into a dist chunk, not a loose file).
grep -rq "sigstore.dev" "$WORK/node_modules/@getmcpm/cli/dist" \
  || fail "Sigstore trust material not bundled — crypto verify would be broken"
echo "    ✓ Sigstore trust material bundled (F8 verify path shippable)"

echo "==> Release dogfood PASSED — the packed artifact installs and runs"
