#!/usr/bin/env bash
# Sync sources to the host and (re)build/start the testnet stack.
# Usage: deploy/testnet/deploy.sh [ssh-host]   (default: helsinki)
set -euo pipefail
HOST="${1:-helsinki}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WALLET="$(cd "$HERE/../.." && pwd)"
DEX="${DEX_REPO:-$WALLET/../elementsplus-dex}"
REMOTE=/srv/instantnet
ssh "$HOST" "mkdir -p $REMOTE/src/scripts $REMOTE/src/dex-server"
rsync -a --delete "$HERE"/{Dockerfile.node,Dockerfile.services,compose.yaml,dex.env,nginx-instantnet.conf} "$HOST:$REMOTE/"
rsync -a "$WALLET"/scripts/{regtest-explorer.mjs,regtest-demo.mjs} "$HOST:$REMOTE/src/scripts/"
# Ship a committed ref, never a working tree another branch may be editing.
DEX_REF="${DEX_REF:-main}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git -C "$DEX" archive "$DEX_REF" server | tar -x -C "$TMP"
rsync -a --delete "$TMP/server/" "$HOST:$REMOTE/src/dex-server/"
ssh "$HOST" "cd $REMOTE && docker compose build && docker compose up -d && docker compose ps"
