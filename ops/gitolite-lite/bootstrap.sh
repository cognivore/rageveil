#!/usr/bin/env bash
# One-time, idempotent bootstrap of the dedicated `git` user that
# fronts a rageveil secret store on this host ("gitolite-lite",
# Option C). Safe to re-run.
#
#   sudo  bash bootstrap.sh            # reads admin key from ./admin.pub
#   sudo  ADMIN_PUBKEY="ssh-ed25519 …"  bash bootstrap.sh
#
# Env knobs:
#   GIT_USER          dedicated account name          (default: git)
#   REPO              bare repo path                   (default: ~git/.rageveil → git@host:.rageveil)
#   SRC_REPO          existing bare repo to seed from  (default: /home/$SUDO_USER/.rageveil if present)
#   ADMIN_PUBKEY      admin bootstrap key string       (else read from ADMIN_PUBKEY_FILE)
#   ADMIN_PUBKEY_FILE file holding the admin key        (default: <script dir>/admin.pub)
#
# NB: `sudo` strips most env vars, so prefer the admin.pub file (the
# deploy.sh driver ships it next to this script).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
GIT_USER="${GIT_USER:-git}"
GIT_HOME="$(getent passwd "$GIT_USER" 2>/dev/null | cut -d: -f6 || true)"
GIT_HOME="${GIT_HOME:-/home/$GIT_USER}"
REPO="${REPO:-$GIT_HOME/.rageveil}"
SRC_REPO="${SRC_REPO:-/home/${SUDO_USER:-root}/.rageveil}"

# Admin key: env var wins, else the shipped file.
ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-$HERE/admin.pub}"
if [ -z "$ADMIN_PUBKEY" ] && [ -f "$ADMIN_PUBKEY_FILE" ]; then
  ADMIN_PUBKEY="$(cat "$ADMIN_PUBKEY_FILE")"
fi

# 0. deps — install system git/python if missing (root PATH won't see
#    a per-user nix git, so don't rely on it).
export DEBIAN_FRONTEND=noninteractive
if ! command -v git-shell >/dev/null 2>&1; then
  apt-get update
  apt-get install -y git
fi
command -v python3 >/dev/null 2>&1 || apt-get install -y python3

GIT_SHELL="$(command -v git-shell 2>/dev/null || true)"
if [ -z "$GIT_SHELL" ]; then
  for c in /usr/bin/git-shell /usr/local/bin/git-shell /bin/git-shell; do
    [ -x "$c" ] && { GIT_SHELL="$c"; break; }
  done
fi
[ -n "$GIT_SHELL" ] || { echo "ERROR: git-shell not found after install"; exit 1; }

# 1. account with git-shell as its login shell (no interactive shell, ever)
grep -qxF "$GIT_SHELL" /etc/shells || echo "$GIT_SHELL" >> /etc/shells
id "$GIT_USER" >/dev/null 2>&1 || useradd -m -d "$GIT_HOME" -s "$GIT_SHELL" "$GIT_USER"
usermod -s "$GIT_SHELL" "$GIT_USER"
install -d -m 700 -o "$GIT_USER" -g "$GIT_USER" "$GIT_HOME/.ssh"
install -d -m 755 -o "$GIT_USER" -g "$GIT_USER" "$GIT_HOME/bin"

# 2. bare repo: copy an existing store if one was named, else init fresh
if [ ! -d "$REPO" ]; then
  if [ -d "$SRC_REPO" ]; then
    echo "seeding $REPO from $SRC_REPO"
    cp -a "$SRC_REPO" "$REPO"
  else
    echo "initialising empty bare repo at $REPO"
    git init --bare "$REPO"
    git --git-dir="$REPO" symbolic-ref HEAD refs/heads/main
  fi
fi

# 3. key-sync helper + post-receive hook
install -m 755 -o "$GIT_USER" -g "$GIT_USER" "$HERE/rageveil-sync-keys" "$GIT_HOME/bin/rageveil-sync-keys"
install -d   -m 755 -o "$GIT_USER" -g "$GIT_USER" "$REPO/hooks"
install -m 755 -o "$GIT_USER" -g "$GIT_USER" "$HERE/post-receive"      "$REPO/hooks/post-receive"

# 4. immutable base authorized_keys (admin key — never removed by sync)
BASE="$GIT_HOME/.ssh/authorized_keys.base"
if [ -n "$ADMIN_PUBKEY" ]; then
  printf 'restrict %s\n' "$ADMIN_PUBKEY" > "$BASE"
fi
[ -s "$BASE" ] || { echo "ERROR: $BASE missing and no ADMIN_PUBKEY/admin.pub — refusing to leave a lockout"; exit 1; }
chown "$GIT_USER:$GIT_USER" "$BASE"; chmod 600 "$BASE"

# 5. own everything, then prime authorized_keys from the current book
chown -R "$GIT_USER:$GIT_USER" "$GIT_HOME"
sudo -u "$GIT_USER" env HOME="$GIT_HOME" RAGEVEIL_REPO="$REPO" \
  "$GIT_HOME/bin/rageveil-sync-keys" refs/heads/main \
  || install -m 600 -o "$GIT_USER" -g "$GIT_USER" "$BASE" "$GIT_HOME/.ssh/authorized_keys"

HOST="$(hostname -f 2>/dev/null || hostname)"
echo
echo "done."
echo "  interactive ssh is refused:   ssh git@$HOST"
echo "  repo is reachable:            git clone git@$HOST:.rageveil"
