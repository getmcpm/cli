#!/usr/bin/env bash
# Backlog #88: proves the vitest coverage threshold actually gates, since a
# renamed test.coverage.thresholds key is accepted silently and never
# type-checked (see tsconfig.tooling.json). Same script for CI and local use.
set -uo pipefail

REPORTS_DIR="$(mktemp -d)"
TEST_FILE="src/guard/__tests__/owasp.test.ts"

OUTPUT="$(pnpm exec vitest run --coverage --coverage.thresholds.lines=101 \
  --coverage.reportsDirectory="$REPORTS_DIR" "$TEST_FILE" 2>&1)"
EXIT_CODE=$?

rm -rf "$REPORTS_DIR"

if [ "$EXIT_CODE" -ne 0 ] \
  && printf '%s\n' "$OUTPUT" | grep -qF 'does not meet global threshold (101%)'; then
  exit 0
fi

printf '%s\n' "$OUTPUT"
exit 1
