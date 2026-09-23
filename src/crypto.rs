//! age encryption, including plugin identities such as Secure Enclave and YubiKey.

use age::{Decryptor, Encryptor, Identity, Recipient};
use anyhow::{anyhow, Result};
use std::io::{Read, Write};

/// Encrypt to every recipient. One recipient failing to wrap is fatal, a store
/// that silently drops its recovery key is worse than no store.
pub fn encrypt(plaintext: &[u8], recipients: &[Box<dyn Recipient + Send>]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(anyhow!("no recipients, refusing to write an unreadable file"));
    }
    let refs: Vec<&dyn Recipient> = recipients.iter().map(|r| r.as_ref() as &dyn Recipient).collect();
    let encryptor = Encryptor::with_recipients(refs.into_iter())
        .map_err(|e| anyhow!("could not build encryptor: {e}"))?;

    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(out)
}

pub fn decrypt(ciphertext: &[u8], identities: &[Box<dyn Identity>]) -> Result<Vec<u8>> {
    let decryptor = Decryptor::new_buffered(ciphertext)?;
    let refs: Vec<&dyn Identity> = identities.iter().map(|i| i.as_ref() as &dyn Identity).collect();
    let mut reader = decryptor.decrypt(refs.into_iter())?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_x25519() {
        let id = age::x25519::Identity::generate();
        let recipients: Vec<Box<dyn Recipient + Send>> = vec![Box::new(id.to_public())];
        let identities: Vec<Box<dyn Identity>> = vec![Box::new(id)];

        let ct = encrypt(b"correct horse battery staple", &recipients).unwrap();
        assert_ne!(ct, b"correct horse battery staple");
        let pt = decrypt(&ct, &identities).unwrap();
        assert_eq!(pt, b"correct horse battery staple");
    }

    #[test]
    fn refuses_empty_recipients() {
        assert!(encrypt(b"x", &[]).is_err());
    }

    #[test]
    fn wrong_identity_fails() {
        let a = age::x25519::Identity::generate();
        let b = age::x25519::Identity::generate();
        let ct = encrypt(b"secret", &[Box::new(a.to_public())]).unwrap();
        assert!(decrypt(&ct, &[Box::new(b)]).is_err());
    }
}
