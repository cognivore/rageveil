//! `rageveil invite …` — admin-issued device enrollment.
//!
//! The flow this implements (protocol vocabulary and rationale in
//! [`crate::invite`]):
//!
//!   * **issue** — mint an ephemeral ssh-ed25519 transport key,
//!     register its public half in the address book as
//!     `invite:<name>` (one commit, pushed — the git@ hook grants
//!     the bearer access), and print the `visageveil://invite/…`
//!     URL to hand to the invitee.
//!   * **accept** — after the invitee's app pushed its real public
//!     key to `invites/<name>.pub`: swap ephemeral → real in the
//!     book and delete the drop file, in ONE commit — the same
//!     push that enrolls the device revokes the invite key.
//!   * **revoke** — kill a pending invite (book entry + any
//!     response), one commit, pushed.
//!   * **status** — pending invites and whether a response has
//!     arrived (run `rageveil sync` first to fetch responses).
//!
//! Every mutation snapshots HEAD first and rolls back if the
//! server rejects the push — same discipline as `address add`,
//! whose plumbing this reuses.

use crate::addressbook::AddressBook;
use crate::commands::address::{
    commit_book, guard_remote, kind_of, propagate, validate_key, validate_name,
};
use crate::dsl::Vault;
use crate::invite::{pins_of_keyscan_output, ssh_host_of_remote, InvitePayload};
use crate::store::StoreLayout;
use crate::sugar::write_json;
use crate::{git, vault_do};

use chrono::{DateTime, Utc};
use std::path::PathBuf;

/// Prefix of the address-book entries that carry ephemeral invite
/// transport keys.
pub const INVITE_ENTRY_PREFIX: &str = "invite:";

#[derive(Clone, Debug)]
pub struct InviteIssueArgs {
    pub root: PathBuf,
    pub name: String,
    /// How long the invite URL stays acceptable (payload expiry;
    /// the phone refuses an expired invite, and `accept` warns).
    pub ttl_hours: i64,
    /// Waive the `git@`-host requirement (useful against local
    /// test remotes; grants no server-side access there).
    pub force: bool,
}

#[derive(Clone, Debug)]
pub struct InviteAcceptArgs {
    pub root: PathBuf,
    pub name: String,
    /// The fingerprint digest the invitee read out over a trusted
    /// channel (`7c09 2cf1 44df 0890`; whitespace/case ignored).
    /// When set, accept refuses a response whose key does not
    /// match — the verbal ceremony, made mechanical.
    pub expected_fingerprint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct InviteRevokeArgs {
    pub root: PathBuf,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct InviteStatusArgs {
    pub root: PathBuf,
}

/// One pending invite, as `status` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInvite {
    pub name: String,
    pub responded: bool,
    /// The responded key's speakable digest (`7c09 2cf1 44df
    /// 0890`) — compare it against what the invitee reads to you
    /// BEFORE accepting. `None` until they respond.
    pub fingerprint_digest: Option<String>,
}

// ─── issue ───────────────────────────────────────────────────────────────

/// Returns the minted payload — the caller renders the URL
/// (`payload.to_url()`); logs narrate everything else.
pub fn invite_issue<S>(s: S, args: InviteIssueArgs) -> S::R<crate::invite::InvitePayload>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let name = args.name.trim().to_owned();
    if let Err(msg) = validate_name(&name) {
        return s.fail(msg);
    }
    let layout = StoreLayout::new(args.root.clone());
    let store_dir = layout.store_dir();
    let ttl = args.ttl_hours.max(1);
    let force = args.force;

    let s2 = s.clone();
    let name2 = name.clone();
    vault_do! { s ;
        // The remote is both the guard's subject and the URL the
        // phone will clone — read it once.
        let remote = git::remote_get_url(&s, store_dir.clone(), "origin".into()) ;
        let _ = guard_remote(s.clone(), kind_of(remote.clone()), force) ;
        let remote_url = match remote {
            Some(url) => s.pure(url),
            None => s.fail(
                "this store has no `origin` remote — nothing an invitee could clone".into(),
            ),
        } ;
        let book = crate::commands::address::load_or_empty(s.clone(), layout.addressbook_path()) ;
        let _ = guard_book_for_issue(s.clone(), &book, &name) ;
        // Ephemeral keypair from DSL entropy, so even keygen is a
        // recorded effect.
        let seed = s.random_bytes(32) ;
        let now = s.now() ;
        issue_with_material(s2.clone(), layout.clone(), name2.clone(), remote_url, seed, now, ttl, force)
    }
}

fn guard_book_for_issue<S: Vault>(s: S, book: &AddressBook, name: &str) -> S::R<()> {
    if book.people.contains_key(name) {
        return s.fail(format!(
            "{name:?} is already enrolled — `rageveil deny`/`address remove` first"
        ));
    }
    let invite_entry = format!("{INVITE_ENTRY_PREFIX}{name}");
    if book.people.contains_key(&invite_entry) {
        return s.fail(format!(
            "an invite for {name:?} is already pending — `rageveil invite revoke {name}` first"
        ));
    }
    s.pure(())
}

#[allow(clippy::too_many_arguments)]
fn issue_with_material<S>(
    s: S,
    layout: StoreLayout,
    name: String,
    remote_url: String,
    seed: Vec<u8>,
    now: DateTime<Utc>,
    ttl_hours: i64,
    force: bool,
) -> S::R<crate::invite::InvitePayload>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let (ephemeral_private, ephemeral_public) = match keypair_from_seed(&seed, &name) {
        Ok(pair) => pair,
        Err(e) => return s.fail(format!("invite keygen: {e:#}")),
    };

    let store_dir = layout.store_dir();
    let invite_entry = format!("{INVITE_ENTRY_PREFIX}{name}");
    let s2 = s.clone();
    let name2 = name.clone();
    let remote2 = remote_url.clone();
    vault_do! { s ;
        // Host-key scan so the phone connects pre-pinned. Fatal on
        // an ssh remote if it cannot be done — never downgraded.
        let host_pin = scan_host_pin(s.clone(), remote_url.clone()) ;
        // Whom the invitee should trust to sign the address book.
        let admin_keys = local_admins(s.clone(), layout.root.clone()) ;
        let head = git::head(&s, store_dir.clone()) ;
        let _ = write_invite_entry(
            s.clone(), layout.clone(), invite_entry.clone(), ephemeral_public.clone(),
        ) ;
        let _ = propagate(
            s.clone(), store_dir.clone(),
            kind_of_for_push(remote2.clone(), force),
            format!("invite for {name2}"), head,
        ) ;
        emit_invite_url(
            s2.clone(), name2.clone(), remote2.clone(), host_pin, admin_keys,
            ephemeral_private.clone(), now, ttl_hours,
        )
    }
}

/// Under `--force` against a non-git@ remote there is nothing to
/// push access to, but the invite still needs the commit pushed so
/// the response round-trip works against plain remotes (tests,
/// self-hosted setups). Treat any remote as pushable.
fn kind_of_for_push(url: String, force: bool) -> crate::commands::address::RemoteKind {
    if force {
        crate::commands::address::RemoteKind::GitAt
    } else {
        kind_of(Some(url))
    }
}

fn keypair_from_seed(seed: &[u8], name: &str) -> anyhow::Result<(String, String)> {
    use anyhow::anyhow;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow!("seed must be 32 bytes"))?;
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(keypair),
        format!("rageveil-invite:{name}"),
    )
    .map_err(|e| anyhow!("assemble invite key: {e}"))?;
    let private_pem = private
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| anyhow!("serialise invite key: {e}"))?
        .to_string();
    let public = private
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow!("serialise invite public key: {e}"))?;
    Ok((private_pem, public))
}

/// `ssh-keyscan` the remote's host so the payload carries a pin.
///
/// Every offered key type is scanned, not just ed25519: the phone
/// cannot pick which host key it is served, so pinning one
/// algorithm locks it out of the server we just scanned.
///
/// A failed scan is fatal, not a downgrade. An unpinned invite is
/// a bearer credential that will trust whatever answers on the
/// other end, so minting one silently would hand an interceptor
/// the first-contact window. The admin already talks to this
/// server; if the scan cannot, that is worth stopping for.
/// Non-ssh remotes (`file://`, tests) have no host to pin and
/// return the empty set legitimately.
fn scan_host_pin<S>(s: S, remote: String) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    if !crate::invite::is_ssh_remote(&remote) {
        // No ssh host behind this remote, so nothing to pin and no
        // transport to impersonate.
        return s.pure(Vec::new());
    }
    let (host, port) = match ssh_host_of_remote(&remote) {
        Ok(hp) => hp,
        Err(e) => return s.fail(format!("cannot read the ssh host out of {remote:?}: {e:#}")),
    };
    let mut argv: Vec<String> = vec!["-T".into(), "5".into()];
    if let Some(p) = port {
        argv.push("-p".into());
        argv.push(p.to_string());
    }
    argv.push(host.clone());
    let s2 = s.clone();
    vault_do! { s ;
        let out = s.handle(s.shell("ssh-keyscan".into(), argv, None, Vec::new())) ;
        match out {
            Ok(out) if out.success() => {
                let pins = pins_of_keyscan_output(out.stdout_str());
                match pins.is_empty() {
                    false => s2.pure(pins),
                    true => fail_no_pin(s2.clone(), &host),
                }
            }
            _ => fail_no_pin(s2.clone(), &host),
        }
    }
}

/// The issuer's own trust list, or empty on an unsigned store.
///
/// Read from `<root>/admins.json` — local, never committed — so an
/// invite hands over the same anchor the issuer actually uses, and
/// a repository writer has no way to inject one.
fn local_admins<S>(s: S, root: PathBuf) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let path = crate::signing::admins_path(&root);
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(path.clone()) ;
        match exists {
            true => crate::sugar::read_json::<S, Vec<String>>(s2.clone(), path),
            false => s2.pure(Vec::new()),
        }
    }
}

fn fail_no_pin<S: Vault + Clone + Send + Sync + 'static>(s: S, host: &str) -> S::R<Vec<String>> {
    s.fail(format!(
        "cannot scan {host}'s ssh host key, so this invite would have nothing to pin. \
         Refusing to issue one that trusts whatever answers: the URL carries a \
         transport key, and an unpinned first contact is exactly what an interceptor \
         needs. Check the host is reachable (`ssh-keyscan {host}`) and re-run."
    ))
}

fn write_invite_entry<S>(
    s: S,
    layout: StoreLayout,
    invite_entry: String,
    ephemeral_public: String,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let ab_path = layout.addressbook_path();
    let store_dir = layout.store_dir();
    let s2 = s.clone();
    vault_do! { s ;
        let key = validate_key(s.clone(), ephemeral_public) ;
        let mut book = crate::commands::address::load_or_empty(s.clone(), ab_path.clone()) ;
        {
            book.people.insert(invite_entry.clone(), key);
            let s3 = s2.clone();
            let msg = format!("invite issue {}", invite_entry.trim_start_matches(INVITE_ENTRY_PREFIX));
            vault_do! { s2 ;
                let _ = write_json(s2.clone(), ab_path.clone(), book) ;
                commit_book(s3.clone(), store_dir, ab_path, msg)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_invite_url<S>(
    s: S,
    name: String,
    remote: String,
    host_pin: Vec<String>,
    admin_keys: Vec<String>,
    ephemeral_private: String,
    now: DateTime<Utc>,
    ttl_hours: i64,
) -> S::R<crate::invite::InvitePayload>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let payload = InvitePayload {
        v: crate::invite::PAYLOAD_VERSION,
        name: name.clone(),
        remote: remote.clone(),
        host_sha256: host_pin.clone(),
        admin_keys: admin_keys.clone(),
        invite_private_openssh: ephemeral_private,
        issued_at: now,
        expires_at: now + chrono::Duration::hours(ttl_hours),
    };
    let pin_line = match host_pin.is_empty() {
        false => format!(
            "host pin: {} key(s) — sha256 {} (invitee connects pre-pinned)",
            host_pin.len(),
            host_pin.join(", ")
        ),
        true => "host pin: none — remote is not ssh, so there is no host to pin".into(),
    };
    let s2 = s.clone();
    vault_do! { s ;
        let _ = s.log(format!(
            "invite issued for {name:?} on {remote} (expires {})",
            payload.expires_at.format("%Y-%m-%d %H:%M UTC"),
        )) ;
        let _ = s.log(pin_line) ;
        let _ = s.log(
            "send this link over a channel you trust; whoever opens it can answer the invite. \
             After they do: `rageveil sync` then `rageveil invite accept`."
                .into(),
        ) ;
        s2.pure(payload)
    }
}

// ─── accept ──────────────────────────────────────────────────────────────

pub fn invite_accept<S>(s: S, args: InviteAcceptArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let name = args.name.trim().to_owned();
    let layout = StoreLayout::new(args.root.clone());
    let store_dir = layout.store_dir();
    let response = layout.invite_response_path(&name);
    let invite_entry = format!("{INVITE_ENTRY_PREFIX}{name}");

    let s2 = s.clone();
    let name2 = name.clone();
    vault_do! { s ;
        let exists = s.exists(response.clone()) ;
        let _ = match exists {
            true => s.pure(()),
            false => s.fail(format!(
                "no response for {name:?} at {} — has the invitee opened the link? \
                 (run `rageveil sync` to fetch responses)",
                response.display()
            )),
        } ;
        let bytes = s.read_file(response.clone()) ;
        let key_line = crate::commands::address::first_key_line(s.clone(), bytes) ;
        let real_key = validate_key(s.clone(), key_line) ;
        let _ = verify_fingerprint(s.clone(), &real_key, args.expected_fingerprint.clone(), &name) ;
        let book = crate::commands::address::load_or_empty(s.clone(), layout.addressbook_path()) ;
        let _ = guard_book_for_accept(s.clone(), &book, &name, &invite_entry) ;
        let remote = git::remote_get_url(&s, store_dir.clone(), "origin".into()) ;
        let head = git::head(&s, store_dir.clone()) ;
        let _ = swap_and_commit(
            s.clone(), layout.clone(), name2.clone(), invite_entry.clone(),
            real_key.clone(), response.clone(), book,
        ) ;
        let _ = propagate(
            s.clone(), store_dir.clone(), kind_of(remote), name2.clone(), head,
        ) ;
        finish_accept(s2.clone(), name2.clone(), real_key)
    }
}

/// The ceremony check: when the admin supplies the digest the
/// invitee read out, a mismatched response is refused before it
/// touches the book. No flag = no check (the fingerprint is still
/// printed after enrollment).
fn verify_fingerprint<S: Vault>(
    s: S,
    real_key: &crate::types::RecipientSpec,
    expected: Option<String>,
    name: &str,
) -> S::R<()> {
    let Some(expected) = expected else {
        return s.pure(());
    };
    let actual = real_key.fingerprint();
    if actual.matches_spoken(&expected) {
        s.pure(())
    } else {
        s.fail(format!(
            "fingerprint mismatch for {name:?}: the response's key digests to\n  {}\nbut you              expected\n  {}\nRefusing to enroll. If the invitee re-reads the same digest from              their device, someone else answered this invite — `rageveil invite revoke {name}`              and start over.",
            actual.digest(),
            crate::types::RecipientFingerprint(expected).digest(),
        ))
    }
}

fn guard_book_for_accept<S: Vault>(
    s: S,
    book: &AddressBook,
    name: &str,
    invite_entry: &str,
) -> S::R<()> {
    if !book.people.contains_key(invite_entry) {
        return s.fail(format!(
            "no pending invite for {name:?} in the address book — issue one first"
        ));
    }
    if book.people.contains_key(name) {
        return s.fail(format!(
            "{name:?} already exists in the address book; refusing to overwrite from an invite"
        ));
    }
    s.pure(())
}

fn swap_and_commit<S>(
    s: S,
    layout: StoreLayout,
    name: String,
    invite_entry: String,
    real_key: crate::types::RecipientSpec,
    response: PathBuf,
    mut book: AddressBook,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    book.people.remove(&invite_entry);
    book.people.insert(name.clone(), real_key);
    let ab_path = layout.addressbook_path();
    let store_dir = layout.store_dir();
    let s2 = s.clone();
    vault_do! { s ;
        let _ = write_json(s.clone(), ab_path.clone(), book) ;
        let _ = s.remove_file(response.clone()) ;
        // Stage the deletion alongside the book so the swap is one
        // commit: enroll the real key, revoke the ephemeral one,
        // drop the response — atomically, from the server's view.
        let _ = git::add_path(&s, store_dir.clone(), response) ;
        let _ = git::add_path(&s, store_dir.clone(), ab_path) ;
        let out = git::commit(&s, store_dir, format!("invite accept {name}")) ;
        match out {
            crate::types::CommitOutcome::Committed
            | crate::types::CommitOutcome::NothingToCommit => s2.pure(()),
        }
    }
}

fn finish_accept<S>(s: S, name: String, key: crate::types::RecipientSpec) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let fp = key.fingerprint().0;
    let s2 = s.clone();
    vault_do! { s ;
        let _ = s.log(format!(
            "enrolled {name:?} (key fingerprint {fp}); the invite key is revoked"
        )) ;
        s2.log(format!(
            "share entries with them now: `rageveil allow <entry> {name}`"
        ))
    }
}

// ─── revoke ──────────────────────────────────────────────────────────────

pub fn invite_revoke<S>(s: S, args: InviteRevokeArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let name = args.name.trim().to_owned();
    let layout = StoreLayout::new(args.root.clone());
    let store_dir = layout.store_dir();
    let invite_entry = format!("{INVITE_ENTRY_PREFIX}{name}");
    let response = layout.invite_response_path(&name);

    let s2 = s.clone();
    let name2 = name.clone();
    vault_do! { s ;
        let book = crate::commands::address::load_or_empty(s.clone(), layout.addressbook_path()) ;
        let _ = match book.people.contains_key(&invite_entry) {
            true => s.pure(()),
            false => s.fail(format!("no pending invite for {name:?}")),
        } ;
        let remote = git::remote_get_url(&s, store_dir.clone(), "origin".into()) ;
        let head = git::head(&s, store_dir.clone()) ;
        let _ = remove_invite_and_commit(
            s.clone(), layout.clone(), name2.clone(), invite_entry.clone(),
            response.clone(), book,
        ) ;
        let _ = propagate(
            s.clone(), store_dir.clone(), kind_of(remote),
            format!("invite revocation for {name2}"), head,
        ) ;
        s2.log(format!("invite for {name2:?} revoked; its transport key is out of the book"))
    }
}

fn remove_invite_and_commit<S>(
    s: S,
    layout: StoreLayout,
    name: String,
    invite_entry: String,
    response: PathBuf,
    mut book: AddressBook,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    book.people.remove(&invite_entry);
    let ab_path = layout.addressbook_path();
    let store_dir = layout.store_dir();
    let s2 = s.clone();
    vault_do! { s ;
        let _ = write_json(s.clone(), ab_path.clone(), book) ;
        let had_response = s.exists(response.clone()) ;
        let _ = match had_response {
            true => stage_response_removal(s.clone(), store_dir.clone(), response.clone()),
            false => s.pure(()),
        } ;
        let _ = git::add_path(&s, store_dir.clone(), ab_path) ;
        let out = git::commit(&s, store_dir, format!("invite revoke {name}")) ;
        match out {
            crate::types::CommitOutcome::Committed
            | crate::types::CommitOutcome::NothingToCommit => s2.pure(()),
        }
    }
}

fn stage_response_removal<S>(s: S, store_dir: PathBuf, response: PathBuf) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    vault_do! { s ;
        let _ = s.remove_file(response.clone()) ;
        let _ = git::add_path(&s, store_dir, response) ;
        s.pure(())
    }
}

// ─── status ──────────────────────────────────────────────────────────────

pub fn invite_status<S>(s: S, args: InviteStatusArgs) -> S::R<Vec<PendingInvite>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let invites_dir = layout.invites_dir();
    let s2 = s.clone();
    vault_do! { s ;
        let book = crate::commands::address::load_or_empty(s.clone(), layout.addressbook_path()) ;
        let responses = s.list_dir(invites_dir) ;
        collect_statuses(s2.clone(), pending_names(&book), responses)
    }
}

fn pending_names(book: &AddressBook) -> Vec<String> {
    book.people
        .keys()
        .filter_map(|k| k.strip_prefix(INVITE_ENTRY_PREFIX))
        .map(str::to_owned)
        .collect()
}

/// For each pending name, read the response file (when present)
/// and digest its key — so `status` shows what the invitee should
/// be reading out, before any accept.
fn collect_statuses<S>(
    s: S,
    names: Vec<String>,
    responses: Vec<PathBuf>,
) -> S::R<Vec<PendingInvite>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let responded: std::collections::BTreeMap<String, PathBuf> = responses
        .into_iter()
        .filter_map(|p| {
            p.file_stem()
                .and_then(|n| n.to_str())
                .map(|n| (n.to_owned(), p.clone()))
        })
        .collect();
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        mut rest: std::vec::IntoIter<String>,
        responded: std::collections::BTreeMap<String, PathBuf>,
        mut acc: Vec<PendingInvite>,
    ) -> S::R<Vec<PendingInvite>> {
        match rest.next() {
            None => s.pure(acc),
            Some(name) => match responded.get(&name).cloned() {
                None => {
                    acc.push(PendingInvite {
                        name,
                        responded: false,
                        fingerprint_digest: None,
                    });
                    go(s, rest, responded, acc)
                }
                Some(path) => {
                    let s2 = s.clone();
                    vault_do! { s ;
                        let bytes = s.read_file(path) ;
                        let line = crate::commands::address::first_key_line(s.clone(), bytes) ;
                        {
                            acc.push(PendingInvite {
                                name,
                                responded: true,
                                fingerprint_digest: Some(
                                    crate::types::RecipientSpec::new(line).fingerprint().digest(),
                                ),
                            });
                            go(s2, rest, responded, acc)
                        }
                    }
                }
            },
        }
    }
    go(s, names.into_iter(), responded, Vec::new())
}
