//! Commands. Each is a free function generic over `S: Vault +
//! Clone + Send + Sync + 'static`, returning `S::R<Out>` for some
//! `Out` (mostly `()` or a small printable struct).
//!
//! Every command is composed via [`crate::vault_do!`] over the
//! [`Vault`] trait — there is no `tokio::fs`, no
//! `std::process::Command`, no direct age call inside this module.
//! That's the whole architectural property: a future interpreter
//! can replay all of these against an emulated filesystem, an
//! offline git, a "what would this do?" renderer, with no source
//! changes here.
//!
//! [`Vault`]: crate::Vault

pub mod allow;
pub mod delete;
pub mod deny;
pub mod init;
pub mod insert;
pub mod list;
pub mod show;
pub mod sync;

pub use allow::allow;
pub use delete::delete;
pub use deny::deny;
pub use init::init;
pub use insert::insert;
pub use list::list;
pub use show::{show, ShowOutput};
pub use sync::sync;
