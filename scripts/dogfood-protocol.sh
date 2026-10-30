#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:?Usage: bash scripts/dogfood-protocol.sh OUTPUT_DIRECTORY [CANDIDATE_TGZ]}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
node -e 'if(require("node:fs").readdirSync(process.argv[1]).length)throw Error("Evidence directory must be empty")' "$OUTPUT"
CONTEXT="$(mktemp -d)"
CONTAINER=""
CANDIDATE="${2:-}"
cleanup() {
  local status=$?
  if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null || status=1; fi
  rm -rf "$CONTEXT" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Send only the harness and public fixtures to Docker, never the entire checkout.
for file in Dockerfile package.json package-lock.json harness.mjs self-check.mjs peer.mjs run.mjs; do
  cp "$ROOT/scripts/protocol-sandbox/$file" "$CONTEXT/$file"
done
if [ -n "$CANDIDATE" ]; then
  cp "$CANDIDATE" "$CONTEXT/candidate.tgz"
  node - "$CONTEXT" "$ROOT" <<'NODE'
const fs = require('node:fs'), crypto = require('node:crypto');
const [context, root] = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(`${context}/package.json`));
pkg.dependencies['@getmcpm/cli'] = 'file:./candidate.tgz';
fs.writeFileSync(`${context}/package.json`, JSON.stringify(pkg));
const version = JSON.parse(fs.readFileSync(`${root}/package.json`)).version;
const filesSha256 = Object.fromEntries(fs.readdirSync(`${root}/dist`).filter(f => f.endsWith('.js')).sort().map(f => [f, crypto.createHash('sha256').update(fs.readFileSync(`${root}/dist/${f}`)).digest('hex')]));
fs.writeFileSync(`${context}/candidate.json`, JSON.stringify({ version, filesSha256 }));
const dockerfile = `${context}/Dockerfile`;
fs.writeFileSync(dockerfile, fs.readFileSync(dockerfile, 'utf8').replace('COPY package.json package-lock.json ./', 'COPY package.json package-lock.json candidate.tgz candidate.json ./').replace('RUN npm ci', 'RUN npm install --package-lock-only --ignore-scripts --no-audit --no-fund && npm ci'));
NODE
fi
cp "$ROOT/skills/mcpm/SKILL.md" "$CONTEXT/mcpm-SKILL.md"
mkdir "$CONTEXT/fixtures"
for group in benign warn attacks; do
  cp "$ROOT/src/guard/__tests__/fixtures/mcptox/$group"/modern-*.json "$CONTEXT/fixtures/"
done
docker build --iidfile "$CONTEXT/image.id" "$CONTEXT" >&2
IMAGE="$(cat "$CONTEXT/image.id")"
CONTAINER="$(docker create --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 768m --cpus 2 --init \
  --mount type=volume,destination=/evidence \
  --tmpfs /work:rw,noexec,nosuid,size=128m,uid=1000,gid=1000 "$IMAGE")"
set +e
node - "$CONTAINER" "$OUTPUT" <<'NODE'
const r = require('node:child_process').spawnSync('docker', ['start', '-a', process.argv[2]], {
  stdio: 'inherit', timeout: 120000, killSignal: 'SIGKILL',
});
const status = r.error?.code === 'ETIMEDOUT' ? 124 : (r.status ?? 1);
require('node:fs').writeFileSync(`${process.argv[3]}/execution.json`, JSON.stringify({
  status: status === 0 ? 'pass' : 'fail', exitCode: status, error: r.error?.code, signal: r.signal,
}));
process.exitCode = status;
NODE
RESULT=$?
set -e
# Killing the attach client does not stop its container. Freeze evidence first.
if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then
  docker kill "$CONTAINER" >/dev/null || [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" = false ]
fi
docker cp "$CONTAINER:/evidence/." "$OUTPUT"
docker inspect --format '{{json .HostConfig}}' "$CONTAINER" > "$OUTPUT/container.json"
docker image inspect --format '{{json .}}' "$IMAGE" > "$OUTPUT/image.json"
echo "Protocol evidence: $OUTPUT/report.json"
exit "$RESULT"
