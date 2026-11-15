//! Encrypt standard input to one recipient, armored, the way rageveil
//! writes an entry file. Used to check interoperability by hand:
//!
//!     printf hi | cargo run --example encrypt_to -- age1se1… | age -d -i key.txt

use std::io::{Read, Write};

use rageveil_core::{Live, RecipientSpec, Vault};

fn main() -> anyhow::Result<()> {
    let recipient = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: encrypt_to RECIPIENT < plaintext"))?;
    let mut plaintext = Vec::new();
    std::io::stdin().read_to_end(&mut plaintext)?;
    let runtime = tokio::runtime::Runtime::new()?;
    let cipher = runtime.block_on(Live::new().encrypt(plaintext, vec![RecipientSpec::new(recipient)]))?;
    std::io::stdout().write_all(&cipher)?;
    Ok(())
}
