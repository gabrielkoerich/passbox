//! Secure Enclave wrapping, through the Swift helper that owns the Touch ID prompt.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// The helper rides inside this binary so `cargo install` stays a single step
const HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/passbox-se"));

/// Everything needed to open the store key on this machine, minus the fingerprint
#[derive(Serialize, Deserialize)]
pub struct SeWrap {
    pub public_key: String,
    pub key_blob: String,
    pub ephemeral: String,
    pub ciphertext: String,
}

#[derive(Deserialize)]
struct KeyPair {
    public_key: String,
    key_blob: String,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    ephemeral: String,
    ciphertext: String,
}

/// Unpacked next to the caches rather than in the store, so it never reaches a syncer
fn helper() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    let dir = PathBuf::from(home).join("Library/Caches/passbox");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("passbox-se");

    // Comparing bytes is cheaper than versioning, and a changed helper replaces itself
    if std::fs::read(&path).ok().as_deref() != Some(HELPER) {
        crate::store::write_private(&path, HELPER)?;
        let mut perms = std::fs::metadata(&path)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(path)
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut child = Command::new(helper()?)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start the Secure Enclave helper")?;
    if let Some(bytes) = stdin {
        child.stdin.as_mut().expect("piped").write_all(bytes)?;
    }
    drop(child.stdin.take());

    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(out.stdout)
}

/// Wrap the store key to a new Secure Enclave key. Neither step raises a prompt.
pub fn wrap(plaintext: &[u8]) -> Result<SeWrap> {
    let pair: KeyPair = serde_json::from_slice(&run(&["keygen"], None)?)?;
    let request = serde_json::json!({
        "public_key": pair.public_key,
        "plaintext": base64(plaintext),
    });
    let sealed: Sealed =
        serde_json::from_slice(&run(&["wrap"], Some(&serde_json::to_vec(&request)?))?)?;

    Ok(SeWrap {
        public_key: pair.public_key,
        key_blob: pair.key_blob,
        ephemeral: sealed.ephemeral,
        ciphertext: sealed.ciphertext,
    })
}

/// Raise a Touch ID prompt worded by `reason`, then open the wrap.
pub fn unwrap(wrap: &SeWrap, reason: &str) -> Result<Vec<u8>> {
    let request = serde_json::json!({
        "key_blob": wrap.key_blob,
        "ephemeral": wrap.ephemeral,
        "ciphertext": wrap.ciphertext,
    });
    run(
        &["unwrap", "--reason", reason],
        Some(&serde_json::to_vec(&request)?),
    )
}

/// The helper speaks base64, and a dependency for 20 lines of table lookup is not worth it
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    #[ignore = "needs a finger on the sensor"]
    fn secure_enclave_round_trip() {
        let key = b"AGE-SECRET-KEY-EXAMPLE";
        let wrap = wrap(key).unwrap();
        let back = unwrap(&wrap, "passbox is running its own test").unwrap();
        assert_eq!(back, key);
    }
}
