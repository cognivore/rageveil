#!/usr/bin/env bash
# Run from your Mac, in the rageveil repo. Ships the gitolite-lite
# scripts (+ your admin pubkey) to the server, runs the bootstrap with
# sudo, then repoints the local store at the dedicated git user.
#
#   ops/gitolite-lite/deploy.sh [host] [admin_pubkey_file]
#
# Defaults: host=doma.dev, key=~/.ssh/id_ed25519.pub
set -euo pipefail

HOST="${1:-doma.dev}"
PUBKEY_FILE="${2:-$HOME/.ssh/id_ed25519.pub}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STORE="${RAGEVEIL_STORE:-$HOME/.rageveil}/store"

[ -f "$PUBKEY_FILE" ] || { echo "no pubkey at $PUBKEY_FILE"; exit 1; }

echo ">> shipping scripts + admin key to $HOST"
ssh "$HOST" 'mkdir -p /tmp/glite'
scp "$HERE/bootstrap.sh" "$HERE/post-receive" "$HERE/rageveil-sync-keys" "$HOST:/tmp/glite/"
# Ship the key as a file — sudo strips env vars, so bootstrap reads admin.pub.
scp "$PUBKEY_FILE" "$HOST:/tmp/glite/admin.pub"

echo ">> bootstrapping git user (sudo password prompt incoming)"
ssh -t "$HOST" "sudo bash /tmp/glite/bootstrap.sh"

echo ">> repointing local store at git@$HOST"
git -C "$STORE" remote set-url origin "git@$HOST:.rageveil"

echo ">> verifying transport"
git -C "$STORE" ls-remote origin >/dev/null && echo "   OK: git@$HOST:.rageveil reachable"
echo ">> done. interactive shell is refused by design:  ssh -T git@$HOST"
