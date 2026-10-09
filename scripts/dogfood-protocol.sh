#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:?Usage: bash scripts/dogfood-protocol.sh OUTPUT_DIRECTORY}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
CONTEXT="$(mktemp -d)"
CONTAINER=""
cleanup() {
  if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null; fi
  rm -rf "$CONTEXT"
}
trap cleanup EXIT
# Send only the harness and public fixtures to Docker, never the entire checkout.
for file in Dockerfile package.json package-lock.json harness.mjs self-check.mjs peer.mjs run.mjs; do
  cp "$ROOT/scripts/protocol-sandbox/$file" "$CONTEXT/$file"
done
mkdir "$CONTEXT/fixtures"
for group in benign warn attacks; do
  cp "$ROOT/src/guard/__tests__/fixtures/mcptox/$group"/modern-*.json "$CONTEXT/fixtures/"
done
IMAGE="$(docker build -q "$CONTEXT")"
CONTAINER="$(docker create --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 768m --cpus 2 --init \
  --mount type=volume,destination=/evidence \
  --tmpfs /work:rw,noexec,nosuid,size=128m,uid=1000,gid=1000 "$IMAGE")"
set +e
node -e 'const r=require("node:child_process").spawnSync("docker",["start","-a",process.argv[1]],{stdio:"inherit",timeout:120000});process.exit(r.status??1)' "$CONTAINER"
RESULT=$?
set -e
docker cp "$CONTAINER:/evidence/." "$OUTPUT"
docker inspect --format '{{json .HostConfig}}' "$CONTAINER" > "$OUTPUT/container.json"
docker image inspect --format '{{json .}}' "$IMAGE" > "$OUTPUT/image.json"
echo "Protocol evidence: $OUTPUT/report.json"
exit "$RESULT"
