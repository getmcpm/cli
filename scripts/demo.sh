#!/usr/bin/env bash
# Demo script for mcpm CLI
#
# Recording options:
#   brew install asciinema && asciinema rec --command="./scripts/demo.sh" demo.cast
#   brew install vhs && vhs scripts/demo.tape
#   Or just run: ./scripts/demo.sh

set -e

type_cmd() {
  echo ""
  echo -e "\033[1;32m$\033[0m $1"
  sleep 0.8
  eval "$1"
  sleep 1.5
}

echo ""
echo -e "\033[1mmcpm\033[0m — the MCP package manager"
echo "npm install -g @getmcpm/cli"
echo ""
sleep 1.5

# 1. Search the registry
type_cmd "mcpm search filesystem"

# 2. Get server details
type_cmd "mcpm info io.github.domdomegg/filesystem-mcp"

# 3. Check your setup
type_cmd "mcpm doctor"

# 4. List what's installed
type_cmd "mcpm list"

# 5. Show the serve command
echo ""
echo -e "\033[1;32m$\033[0m mcpm serve"
echo "  Starts mcpm as an MCP server — 8 tools over stdio."
echo "  AI agents can search, install, and audit MCP servers programmatically."
sleep 2

echo ""
echo -e "\033[1mInstall:\033[0m npm install -g @getmcpm/cli"
echo -e "\033[1mGitHub:\033[0m github.com/getmcpm/cli"
echo ""
