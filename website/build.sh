#!/bin/sh
set -eu

# Netlify runs this in website/; publish only the public asset allowlist.
cd "$(dirname "$0")"
rm -rf dist
mkdir -p dist/assets
cp index.html styles.css tokens.css base.css site.js dist/
cp assets/logo.svg dist/assets/
