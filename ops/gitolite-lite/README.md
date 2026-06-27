# gitolite-lite — address book *is* the access list, admins control it

A dedicated, shell-less `git` user fronts the rageveil secret store. Its
`authorized_keys` is **regenerated from the committed address book on
every push**, and **only admins may change that address book** —
enforced on the server, not the client.

```
# admin:
rageveil address add bob "ssh-ed25519 AAAA… bob@laptop"   # commits + pushes; bob gets access
# regular user:
rageveil sync                                             # pull/push secrets — fine
rageveil address add eve …                                # REJECTED by the server, rolled back locally
```

No second admin channel, no per-user server fiddling, no gitolite.

## Two tiers

| | pull secrets | push secrets (`insert`/`allow`/`deny`) | change `addressbook.json` |
|---|:--:|:--:|:--:|
| **admin** | ✅ | ✅ | ✅ |
| **user**  | ✅ | ✅ | ❌ (server rejects) |

Admins are listed **by fingerprint** in `~git/admins`, a file that lives
*outside* the repo — so no push can grant itself admin. The bootstrap
key is seeded there; add another admin by appending its fingerprint
(as the `git` user) on the server.

## How identity works (the one gitolite trick)

Every line in `authorized_keys` carries a forced command:

```
command="~/bin/rageveil-shell <fp>",restrict <type> <b64> <label>
```

`<fp>` is the key's rageveil fingerprint. `rageveil-shell` records it as
`RAGEVEIL_FP` and hands off to `git-shell`, so the **pre-receive** hook
knows who is pushing. Because a forced command needs a real shell to
exec it, the account's login shell is **bash** — which means safety
rests on *every* key being forced. `rageveil-sync-keys` guarantees that
(it never emits a bare key, and refuses to write an empty file).

## Pieces

| file | role |
|------|------|
| `bootstrap.sh` | one-time, idempotent server setup (run as root) |
| `deploy.sh` | drives bootstrap from the operator's machine |
| `rageveil-shell` | forced command: stamps `RAGEVEIL_FP`, execs git-shell |
| `pre-receive` | **doorman** — rejects non-admin changes to `addressbook.json` |
| `post-receive` | runs `rageveil-sync-keys` after an accepted push |
| `rageveil-sync-keys` | rebuilds `authorized_keys` (base + book) as forced lines |

## Server setup (root, once / to upgrade)

```bash
sudo ADMIN_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" bash bootstrap.sh
# or just: ./deploy.sh   (from the rageveil repo, on your machine)
```

## Why it's safe

- **Server-enforced tiers.** A patched client can't bypass `pre-receive`;
  the admin set lives outside the repo.
- **Every key is forced + `restrict`** — no shell, no port/agent/X11
  forwarding, no PTY.
- **Keys validated** from the pushed object as single well-formed pubkey
  lines (known type + base64, no embedded newlines) — no option
  injection.
- **No lockout.** `authorized_keys.base` (admin key) is never derived
  from a push, and the bootstrap fingerprint is always an admin, so a
  malformed/hostile book can't lock the admin out.
- **Only SSH keys** are emitted; `age1…` recipients get crypto access to
  secrets but not transport access.

## Client side

`rageveil address add/remove` on a `git@…` store commits + pushes
immediately. If the server rejects the push (you're not an admin), the
local commit is **rolled back** so your tree isn't poisoned and the next
`sync` isn't wedged. On a non-`git@` store, `add` refuses unless
`--force`.
