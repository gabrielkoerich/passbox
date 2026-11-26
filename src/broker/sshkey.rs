//! Which secret values are SSH keys, and the only form a key leaves the store in. Both builds
//! compile it, so a client reading its own store refuses a key as the broker does

use anyhow::{Result, bail};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

pub(crate) const HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// A key anywhere in the value, such as a 1Password field folded into a login, which a read
/// would hand out bare
pub(crate) fn holds_key(value: &str) -> bool {
    value.contains(HEADER)
}

/// Any OpenSSH private key, of a type the agent signs with or not, encrypted or not
pub(crate) fn is_key(value: &str) -> bool {
    value.trim_start().starts_with(HEADER) && PrivateKey::from_openssh(value).is_ok()
}

/// A key the agent signs with: unencrypted, and Ed25519 or ECDSA
#[cfg(feature = "host")]
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
                curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384 | EcdsaCurve::NistP521
            }
    )
}

/// Why the agent does not offer this key, or None when it does or the value is no key
#[cfg(feature = "host")]
pub(crate) fn unoffered(name: &str, value: &str) -> Option<String> {
    if parse(value).is_some() {
        return None;
    }
    if holds_key(value) && !is_key(value) {
        return Some(
            "it holds an SSH private key among other text, so no read releases it until the key moves into a secret of its own with `passbox add`".into(),
        );
    }

    let key = value
        .trim_start()
        .starts_with(HEADER)
        .then(|| PrivateKey::from_openssh(value).ok())??;
    Some(if key.is_encrypted() && usable(&key) {
        format!(
            "the SSH key has its own passphrase, run `passbox add --replace {name}` at a terminal to enter it once so the agent offers it"
        )
    } else {
        format!(
            "the SSH agent does not sign with {} keys, so it stores the key but does not offer it",
            key.algorithm()
        )
    })
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

/// What a read hands out. Any SSH key, of every type, leaves only encrypted with `passphrase`
pub(crate) fn release(name: &str, value: &str, passphrase: &str) -> Result<String> {
    if !holds_key(value) {
        if !passphrase.is_empty() {
            bail!("{name} is not an SSH key, drop --encrypt to read it");
        }

        return Ok(value.to_string());
    }
    if !is_key(value) {
        bail!(
            "{name} holds an SSH private key among other text, which never leaves the store bare\n\
             move the key into a secret of its own with `passbox add`"
        );
    }
    if passphrase.is_empty() {
        bail!(
            "{name} is an SSH key, which only the SSH agent signs with\n\
             run `passbox get --encrypt {name}` at a terminal to export it with a passphrase"
        );
    }

    let key = PrivateKey::from_openssh(value)?;
    // Encrypting it again would need the passphrase it was stored with
    if key.is_encrypted() {
        bail!(
            "{name} is stored with its own passphrase\n\
             run `passbox add --replace {name}` at a terminal to enter it once, then export it"
        );
    }

    let locked = key.encrypt(&mut OsRng, passphrase)?;
    let text = locked.to_openssh(ssh_key::LineEnding::LF)?;
    Ok(text.trim_end_matches('\n').to_string())
}
