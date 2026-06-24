# gitolite-lite — address book *is* the access list

A dedicated, shell-less `git` user fronts the rageveil secret store.
Its `authorized_keys` is **regenerated from the committed address book
on every push** by a `post-receive` hook. So onboarding is just:

```
rageveil address add bob "ssh-ed25519 AAAA… bob@laptop"   # commit
rageveil sync                                              # push → hook grants bob SSH access
```

No second admin channel, no per-user server fiddling, no gitolite. The
config that controls access (`addressbook.json`) is the same file
rageveil already syncs.

## Pieces

| file | role |
|------|------|
| `bootstrap.sh` | one-time, idempotent server setup (run as root) |
| `post-receive` | hook installed into the bare repo; fires `rageveil-sync-keys` |
| `rageveil-sync-keys` | rebuilds `~git/.ssh/authorized_keys` from `addressbook.json` |

## Server setup (root, once)

```bash
sudo ADMIN_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" bash bootstrap.sh
```

This creates the `git` user with `git-shell` as its **login shell**
(so `ssh git@host` can never get a prompt), seeds the bare repo at
`~git/.rageveil` (copying an existing store if one is found), installs
the hook + helper, and writes an immutable `authorized_keys.base`
holding your key.

## Why it's safe

- **Login shell is `git-shell`** — connections can only run
  `git-{receive,upload}-pack`; no shell, ever.
- **`restrict` on every generated key** — no port/agent/X11 forwarding,
  no PTY.
- **Keys are read from the pushed git object and validated** as a
  single well-formed pubkey line (known key type + base64, no embedded
  newlines), so a pushed value can't inject `authorized_keys` options
  or extra lines.
- **`authorized_keys.base` is never regenerated** — a malformed or
  empty book can't lock the admin out; they can always push a fix.
- **Only SSH keys are emitted.** `age1…` recipients get *crypto* access
  to secrets but not *transport* access (they can't SSH); give them the
  repo another way if needed.

## Client-side guard

`rageveil address add` refuses to register a name unless the store's
`origin` is a `git@…` remote (override with `-f/--force`). On any other
remote the address book isn't wired to this hook, so a registration
would grant no access — and you don't want the access list pointed at a
personal shell account.
