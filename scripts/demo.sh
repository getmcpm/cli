#!/usr/bin/env bash
# Demo script for mcpm CLI
#
# Build first:  npm run build
# Record:       asciinema rec assets/demo.cast --command="./scripts/demo.sh" --overwrite
# Convert GIF:  agg assets/demo.cast assets/demo.gif --theme monokai

set -e
export NODE_NO_WARNINGS=1

MCPM="$(cd "$(dirname "$0")/.." && pwd)/dist/index.js"

slow_type() {
  local cmd="$1"
  shift
  printf "\n\033[1;32m❯\033[0m "
  for ((i=0; i<${#cmd}; i++)); do
    printf "%s" "${cmd:$i:1}"
    sleep 0.04
  done
  echo ""
  sleep 0.3
  "$@"
  sleep 2
}

clear
echo ""
echo -e "  \033[1;36mmcpm\033[0m — the MCP package manager  \033[2mv0.3.2\033[0m"
echo -e "  \033[2msecurity-first · open source · works with every AI client\033[0m"
echo ""
sleep 2

# Search and inspect
slow_type "mcpm search filesystem" node "$MCPM" search filesystem
slow_type "mcpm info io.github.domdomegg/filesystem-mcp" node "$MCPM" info io.github.domdomegg/filesystem-mcp

# Current state
slow_type "mcpm doctor" node "$MCPM" doctor || true
slow_type "mcpm list" node "$MCPM" list

# Stack files — v0.3 feature
echo ""
echo -e "  \033[1;33m── Stack files\033[0m  \033[2mdocker-compose for MCP servers\033[0m"
echo ""
sleep 2

# Export writes mcpm.yaml to a temp dir; lock + diff default to mcpm.yaml in cwd
DEMO_DIR="$(mktemp -d)"
trap 'rm -rf "$DEMO_DIR"' EXIT
cd "$DEMO_DIR"

slow_type "mcpm export --output mcpm.yaml" node "$MCPM" export --output mcpm.yaml
slow_type "mcpm lock" node "$MCPM" lock || true
slow_type "mcpm diff" node "$MCPM" diff

echo ""
echo -e "  \033[1;36mmcpm serve\033[0m — run mcpm as an MCP server"
echo -e "  \033[2m9 tools · AI agents can search, install, and audit servers\033[0m"
echo ""
sleep 2

echo -e "  \033[1mInstall:\033[0m npm install -g @getmcpm/cli"
echo -e "  \033[1mGitHub:\033[0m github.com/getmcpm/cli"
echo ""
sleep 2
