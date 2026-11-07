#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:?Usage: bash scripts/dogfood-plugin-lifecycle.sh EMPTY_OUTPUT_DIRECTORY PINNED_NATIVE_TGZ}"
ARCHIVE="${2:?Provide the pinned public Linux arm64 Claude native archive}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
node -e 'if(require("node:fs").readdirSync(process.argv[1]).length)throw Error("Evidence directory must be empty")' "$OUTPUT"
CONTEXT="$(mktemp -d)"
CONTAINER=""
cleanup() {
  local status=$?
  if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null || status=1; fi
  rm -rf "$CONTEXT" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
node "$ROOT/scripts/native-client/plugin-lifecycle-prepare.mjs" "$CONTEXT" "$ARCHIVE"
cp "$CONTEXT/inputs.json" "$OUTPUT/inputs.json"
docker build --network=none --pull=false --iidfile "$CONTEXT/image.id" "$CONTEXT" >&2
IMAGE="$(cat "$CONTEXT/image.id")"
CONTAINER="$(docker create --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 2g --cpus 2 --init \
  --mount type=volume,destination=/evidence \
  --tmpfs /work:rw,noexec,nosuid,size=128m,uid=1000,gid=1000 "$IMAGE")"
set +e
node - "$CONTAINER" "$OUTPUT" <<'NODE'
const fs = require('node:fs'), { spawnSync } = require('node:child_process');
const result = spawnSync('docker', ['start', '-a', process.argv[2]], { stdio: 'inherit', timeout: 110000, killSignal: 'SIGKILL' });
const status = result.error?.code === 'ETIMEDOUT' ? 124 : (result.status ?? 1);
fs.writeFileSync(`${process.argv[3]}/execution.json`, JSON.stringify({ exitCode: status, error: result.error?.code, signal: result.signal }));
process.exitCode = status;
NODE
RESULT=$?
set -e
if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" = true ]; then
  docker kill "$CONTAINER" >/dev/null || [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" = false ]
fi
docker cp "$CONTAINER:/evidence/." "$OUTPUT"
docker inspect --format '{{json .HostConfig}}' "$CONTAINER" > "$OUTPUT/container.json"
docker image inspect --format '{{json .}}' "$IMAGE" > "$OUTPUT/image.json"
echo "Native inline-plugin evidence: $OUTPUT/report.json"
exit "$RESULT"
