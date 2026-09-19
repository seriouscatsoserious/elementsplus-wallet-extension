#!/usr/bin/env sh
set -eu

required_major=24
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 24 or newer is required." >&2
  exit 1
fi

node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
if [ "$node_major" -lt "$required_major" ]; then
  echo "Node.js 24 or newer is required; found $(node --version)." >&2
  exit 1
fi

npm ci --ignore-scripts
npm run check

echo
echo "Build complete. Load this directory as an unpacked Chromium extension:"
echo "$(pwd)/dist/chromium"
