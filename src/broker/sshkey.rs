//! Which secret values are SSH keys, and the only form a key leaves the store in. Both builds
//! compile it, so a client reading its own store refuses a key as the broker does

use anyhow::{Result, bail};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

pub(crate) const HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// A secret is an SSH key when its value is an unencrypted Ed25519 or P-256 OpenSSH key
pub(crate) fn parse(value: &str) -> Option<PrivateKey> {
    if !value.trim_start().starts_with(HEADER) {
        return None;
    }
    let key = PrivateKey::from_openssh(value).ok()?;
    (usable(&key) && !key.is_encrypted()).then_some(key)
}

fn usable(key: &PrivateKey) -> bool {
    matches!(
        key.algorithm(),
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
    )
}

/// A passphrase-protected key the agent can use, decrypted with the passphrase `ask` returns
pub(crate) fn decrypt(value: &str, ask: impl FnOnce() -> Result<String>) -> Result<Option<String>> {
    if !value.trim_start().starts_with(HEADER) {
        return Ok(None);
    }

    let Ok(key) = PrivateKey::from_openssh(value) else {
        return Ok(None);
    };
    if !key.is_encrypted() || !usable(&key) {
        return Ok(None);
    }

    let passphrase = zeroize::Zeroizing::new(ask()?);
    let plain = key
        .decrypt(passphrase.as_bytes())
        .map_err(|_| anyhow::anyhow!("wrong passphrase for the SSH key"))?;
    let text = plain.to_openssh(ssh_key::LineEnding::LF)?;
    Ok(Some(text.trim_end_matches('\n').to_string()))
}

/// What a read hands out. A key the agent signs with leaves only encrypted with `passphrase`
pub(crate) fn release(name: &str, value: &str, passphrase: &str) -> Result<String> {
    let Some(key) = parse(value) else {
        if !passphrase.is_empty() {
            bail!("{name} is not an SSH key, drop --encrypt to read it");
        }

        return Ok(value.to_string());
    };
    if passphrase.is_empty() {
        bail!(
            "{name} is an SSH key, which only the SSH agent signs with\n\
             run `passbox get --encrypt {name}` at a terminal to export it with a passphrase"
        );
    }

    let locked = key.encrypt(&mut OsRng, passphrase)?;
    let text = locked.to_openssh(ssh_key::LineEnding::LF)?;
    Ok(text.trim_end_matches('\n').to_string())
}
