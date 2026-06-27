#!/usr/bin/env bash
# One-time, idempotent bootstrap of the dedicated `git` user that
# fronts a rageveil secret store on this host ("gitolite-lite",
# Option C, with admin/user tiers). Safe to re-run.
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
# Identity model: the account's login shell is bash, and EVERY key in
# authorized_keys carries a forced `rageveil-shell <fp>` command (no
# bare keys — rageveil-sync-keys guarantees this), so the pre-receive
# hook can tell admins from users. Admins are fingerprints in ~/admins
# (outside the repo); the bootstrap key is seeded there.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
GIT_USER="${GIT_USER:-git}"
GIT_HOME="$(getent passwd "$GIT_USER" 2>/dev/null | cut -d: -f6 || true)"
GIT_HOME="${GIT_HOME:-/home/$GIT_USER}"
REPO="${REPO:-$GIT_HOME/.rageveil}"
SRC_REPO="${SRC_REPO:-/home/${SUDO_USER:-root}/.rageveil}"

ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"
ADMIN_PUBKEY_FILE="${ADMIN_PUBKEY_FILE:-$HERE/admin.pub}"
if [ -z "$ADMIN_PUBKEY" ] && [ -f "$ADMIN_PUBKEY_FILE" ]; then
  ADMIN_PUBKEY="$(cat "$ADMIN_PUBKEY_FILE")"
fi
[ -n "$ADMIN_PUBKEY" ] || { echo "ERROR: no ADMIN_PUBKEY / admin.pub — refusing to bootstrap without an admin"; exit 1; }

# 0. deps — git (for git-shell) and python3. Root PATH won't see a
#    per-user nix git, so install the system one if absent.
export DEBIAN_FRONTEND=noninteractive
if ! command -v git-shell >/dev/null 2>&1; then
  apt-get update
  apt-get install -y git
fi
command -v python3 >/dev/null 2>&1 || apt-get install -y python3

# 1. account — login shell is bash (a forced command needs a real
#    shell to exec it); safety comes from every key being forced.
id "$GIT_USER" >/dev/null 2>&1 || useradd -m -d "$GIT_HOME" -s /bin/bash "$GIT_USER"
usermod -s /bin/bash "$GIT_USER"
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

# 3. identity shell + key-sync helper + hooks (pre-receive = doorman,
#    post-receive = regenerate keys)
install -m 755 -o "$GIT_USER" -g "$GIT_USER" "$HERE/rageveil-shell"     "$GIT_HOME/bin/rageveil-shell"
install -m 755 -o "$GIT_USER" -g "$GIT_USER" "$HERE/rageveil-sync-keys" "$GIT_HOME/bin/rageveil-sync-keys"
install -d   -m 755 -o "$GIT_USER" -g "$GIT_USER" "$REPO/hooks"
install -m 755 -o "$GIT_USER" -g "$GIT_USER" "$HERE/pre-receive"        "$REPO/hooks/pre-receive"
install -m 755 -o "$GIT_USER" -g "$GIT_USER" "$HERE/post-receive"       "$REPO/hooks/post-receive"

# 4. base authorized_keys (RAW pubkey, one per line) — admin key, never
#    derived from a push, so a hostile book can't drop the admin.
BASE="$GIT_HOME/.ssh/authorized_keys.base"
printf '%s\n' "$ADMIN_PUBKEY" > "$BASE"
chown "$GIT_USER:$GIT_USER" "$BASE"; chmod 600 "$BASE"

# 5. admin set — fingerprint(s) of the admin key(s), outside the repo.
ADMIN_FP="$(printf '%s' "$ADMIN_PUBKEY" | python3 -c \
  'import sys,hashlib;t=sys.stdin.read().split();\
print(hashlib.sha256(f"{t[0]} {t[1]}".encode()).hexdigest()[:16]) if len(t)>=2 else sys.exit(1)')"
ADMINS="$GIT_HOME/admins"
# Keep any existing admins; ensure the bootstrap fp is present.
touch "$ADMINS"
grep -qxF "$ADMIN_FP" "$ADMINS" || echo "$ADMIN_FP" >> "$ADMINS"
chown "$GIT_USER:$GIT_USER" "$ADMINS"; chmod 600 "$ADMINS"
echo "admin fingerprint: $ADMIN_FP"

# 6. own everything, then build authorized_keys from base + book
chown -R "$GIT_USER:$GIT_USER" "$GIT_HOME"
sudo -u "$GIT_USER" env HOME="$GIT_HOME" RAGEVEIL_REPO="$REPO" \
  "$GIT_HOME/bin/rageveil-sync-keys" refs/heads/main

HOST="$(hostname -f 2>/dev/null || hostname)"
echo
echo "done."
echo "  interactive ssh is refused:   ssh git@$HOST"
echo "  repo is reachable:            git clone git@$HOST:.rageveil"
echo "  add another admin later:      append a fingerprint to $ADMINS (as $GIT_USER)"
