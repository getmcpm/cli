#!/usr/bin/env bash
# Demo script for mcpm CLI
# Usage: ./scripts/demo.sh
# For recording: asciinema rec --command="./scripts/demo.sh" demo.cast

set -e

# Simulate typing effect for demo recordings
type_cmd() {
  echo ""
  echo "$ $1"
  sleep 0.5
  eval "$1"
  sleep 1
}

echo "mcpm -- MCP Package Manager"
echo ""
sleep 1

type_cmd "mcpm search filesystem"
type_cmd "mcpm info io.github.modelcontextprotocol/servers-filesystem"
type_cmd "mcpm doctor"
type_cmd "mcpm init --help"

echo ""
echo "Install: npm install -g @getmcpm/cli"
