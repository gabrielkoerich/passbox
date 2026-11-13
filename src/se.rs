//! Secure Enclave wrapping, through the Swift helper that owns the Touch ID prompt.

use crate::store::write_private;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// The helper rides inside this binary so `cargo install` stays a single step
#[cfg(target_os = "macos")]
const HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/passbox-se"));

// A host build elsewhere exists for CI, where the test fake stands in for the Enclave
#[cfg(not(target_os = "macos"))]
const HELPER: &[u8] = &[];

/// Everything needed to open the store key on this machine, minus the fingerprint
#[derive(Serialize, Deserialize)]
pub(crate) struct SeWrap {
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

/// What sealing to a public key yields: the sender's one-time key and the ciphertext under it
#[derive(Serialize, Deserialize)]
pub(crate) struct Sealed {
    pub ephemeral: String,
    pub ciphertext: String,
}

/**
 * The test fake that replaces the helper, which exists only in a `mock-enclave` build. It has no
 * Enclave behind it, so it refuses any store outside the temp directory, where every test store
 * lives, and aborts rather than returning an error a caller could fall past
 **/
#[cfg(feature = "mock-enclave")]
fn fake_helper() -> Option<PathBuf> {
    let fake = std::env::var_os("PASSBOX_SE_HELPER")?;
    let store = std::env::var_os("PASSBOX_DIR").and_then(|d| std::fs::canonicalize(d).ok());
    let temp = std::fs::canonicalize(std::env::temp_dir()).ok();
    match (store, temp) {
        (Some(store), Some(temp)) if store.starts_with(&temp) => Some(PathBuf::from(fake)),
        _ => {
            eprintln!("passbox: PASSBOX_SE_HELPER is set for a store outside the temp directory");
            std::process::abort();
        }
    }
}

#[cfg(not(feature = "mock-enclave"))]
fn fake_helper() -> Option<PathBuf> {
    None
}

/// Unpacked next to the caches rather than in the store, so it never reaches a syncer
fn helper() -> Result<PathBuf> {
    if let Some(fake) = fake_helper() {
        return Ok(fake);
    }
    if HELPER.is_empty() {
        bail!("the Secure Enclave helper exists only in a macOS build");
    }
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    let dir = PathBuf::from(home).join("Library/Caches/passbox");
    std::fs::create_dir_all(&dir)?;
    // macOS titles the prompt with the binary name, so this file is what the user reads
    let path = dir.join("passbox");

    // Comparing bytes is cheaper than versioning, and a changed helper replaces itself
    if std::fs::read(&path).ok().as_deref() != Some(HELPER) {
        write_private(&path, HELPER)?;
        let mut perms = std::fs::metadata(&path)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(path)
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
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

    // Stdout carries the store key on unwrap. A buffer that never grows leaves no stray copy
    let mut out = Zeroizing::new(Vec::with_capacity(4096));
    child.stdout.take().expect("piped").read_to_end(&mut out)?;
    let mut err = Vec::new();
    child.stderr.take().expect("piped").read_to_end(&mut err)?;
    if !child.wait()?.success() {
        bail!("{}", String::from_utf8_lossy(&err).trim());
    }
    Ok(out)
}

// The tests set this, so a broken headless check fails them instead of asking for a fingerprint.
// The fake is not an Enclave, so it still runs
fn ensure_enabled() -> Result<()> {
    if fake_helper().is_some() {
        return Ok(());
    }
    if std::env::var_os("PASSBOX_NO_ENCLAVE").is_some() {
        bail!("the Secure Enclave is disabled by PASSBOX_NO_ENCLAVE");
    }
    Ok(())
}

/// Seal to a P-256 public key whose private half sits in some Secure Enclave, this Mac's or a
/// phone's. Sealing needs no prompt, the opening is what costs one
pub(crate) fn seal_to(public_key: &str, plaintext: &[u8]) -> Result<Sealed> {
    ensure_enabled()?;
    let request = serde_json::json!({
        "public_key": public_key,
        "plaintext": base64(plaintext),
    });
    Ok(serde_json::from_slice(&run(
        &["wrap"],
        Some(&serde_json::to_vec(&request)?),
    )?)?)
}

/// Wrap the store key to a new Secure Enclave key. Neither step raises a prompt.
pub(crate) fn wrap(plaintext: &[u8]) -> Result<SeWrap> {
    ensure_enabled()?;
    let pair: KeyPair = serde_json::from_slice(&run(&["keygen"], None)?)?;
    let sealed = seal_to(&pair.public_key, plaintext)?;

    Ok(SeWrap {
        public_key: pair.public_key,
        key_blob: pair.key_blob,
        ephemeral: sealed.ephemeral,
        ciphertext: sealed.ciphertext,
    })
}

/* Raise a Touch ID prompt worded by `reason`, then open the wrap. macOS renders the dialog as
"<binary> is trying to <reason>.", so `reason` has to be a verb phrase that finishes that
sentence, such as "release the password for github/token to claude-code". */
pub(crate) fn unwrap(wrap: &SeWrap, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (sender, outcome) = std::sync::mpsc::channel();
    let _prompt = unwrap_in_background(wrap, reason, move |plain| {
        let _ = sender.send(plain);
    })?;
    outcome
        .recv()
        .context("the Secure Enclave helper ended with no answer")?
}

/// A Touch ID prompt that is on screen and can be taken down, which `unwrap` cannot do
pub(crate) struct Prompt {
    child: std::sync::Arc<std::sync::Mutex<std::process::Child>>,
}

impl Prompt {
    /// Take the dialog down. The helper dies with it, and its outcome is then a failure nobody reads
    pub(crate) fn cancel(&self) {
        let _ = self.child.lock().expect("helper").kill();
    }
}

/**
 * The same prompt as `unwrap`, raised without waiting for it. `done` gets the store key or the
 * refusal on another thread, so the caller can wait on something else as well and call `cancel`
 * when that answers first
 **/
pub(crate) fn unwrap_in_background(
    wrap: &SeWrap,
    reason: &str,
    done: impl FnOnce(Result<Zeroizing<Vec<u8>>>) + Send + 'static,
) -> Result<Prompt> {
    ensure_enabled()?;
    let request = serde_json::json!({
        "key_blob": wrap.key_blob,
        "ephemeral": wrap.ephemeral,
        "ciphertext": wrap.ciphertext,
    });
    let mut child = Command::new(helper()?)
        .args(["unwrap", "--reason", reason])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start the Secure Enclave helper")?;
    let written = child
        .stdin
        .take()
        .expect("piped")
        .write_all(&serde_json::to_vec(&request)?);
    if let Err(e) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e).context("could not write to the Secure Enclave helper");
    }
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");

    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let waited = std::sync::Arc::clone(&child);
    std::thread::spawn(move || {
        // Both pipes close when the helper ends, whether it answered or was killed
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        let mut err = Vec::new();
        let read = stdout
            .read_to_end(&mut out)
            .and_then(|_| stderr.read_to_end(&mut err));
        let status = waited.lock().expect("helper").wait();
        done(match (read, status) {
            (Ok(_), Ok(status)) if status.success() => Ok(out),
            (Ok(_), Ok(_)) => Err(anyhow!("{}", String::from_utf8_lossy(&err).trim())),
            (Err(e), _) | (_, Err(e)) => Err(anyhow!("the Secure Enclave helper broke off: {e}")),
        });
    });
    Ok(Prompt { child })
}

/// The reverse of `base64`, for the keys and boxes a phone sends. None for anything malformed
pub(crate) fn unbase64(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    for chunk in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            };
            n |= u32::from(value) << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..chunk.len()]);
    }
    Some(out)
}

// The helper keeps running to clear the clipboard, so wait only for the line that confirms the
// pasteboard is set, then leave it. The value goes in on stdin, so it never reaches argv or ps
pub(crate) fn clip(value: &str, secs: u64) -> Result<()> {
    let mut child = Command::new(helper()?)
        .args(["clip", "--clear", &secs.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start the clipboard helper")?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(value.as_bytes())?;

    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().expect("piped")).read_line(&mut line)?;
    if line.trim() != "ok" {
        let mut err = String::new();
        let _ = child.stderr.take().expect("piped").read_to_string(&mut err);
        bail!("the clipboard helper failed: {}", err.trim());
    }
    Ok(())
}

/// The helper speaks base64, and a dependency for 20 lines of table lookup is not worth it
pub(crate) fn base64(bytes: &[u8]) -> String {
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
                let index =
                    usize::try_from((n >> (18 - 6 * i)) & 63).expect("six bits fit a usize");
                out.push(char::from(ALPHABET[index]));
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
    fn unbase64_reverses_base64_and_refuses_what_is_not() {
        for bytes in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            &[0xff, 0xfe, 0xfd, 0x00],
        ] {
            assert_eq!(unbase64(&base64(bytes)).unwrap(), bytes);
        }
        assert_eq!(unbase64("Zm9v").unwrap(), b"foo");
        assert!(unbase64("Zm9*").is_none());
        assert!(unbase64("Z").is_none());
    }

    #[test]
    #[ignore = "needs a finger on the sensor"]
    fn secure_enclave_round_trip() {
        let key = b"AGE-SECRET-KEY-EXAMPLE";
        let wrap = wrap(key).unwrap();
        let back = unwrap(&wrap, "passbox is running its own test").unwrap();
        assert_eq!(&back[..], key);
    }
}
