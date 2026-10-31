//! The token and the passphrase, moved out of the environment before anything else runs.

use anyhow::{Result, bail};
use std::io::Read;

const PASSPHRASE_ENV: &str = "PASSBOX_PASSPHRASE";

// A token opens its grants and the passphrase opens the whole store, so a command passbox runs
// for someone else inherits neither, or it could print them into a transcript
pub(crate) fn without_credentials(
    command: &mut std::process::Command,
) -> &mut std::process::Command {
    command
        .env_remove("PASSBOX_TOKEN")
        .env_remove(PASSPHRASE_ENV)
}

struct Held {
    token: Option<zeroize::Zeroizing<String>>,
    passphrase: Option<zeroize::Zeroizing<String>>,
}

static HELD: std::sync::OnceLock<Held> = std::sync::OnceLock::new();

/**
 * Moves the token and the passphrase out of the environment before anything else runs, so nothing
 * passbox starts can inherit them, git and the broker included. Unsetting a variable leaves its
 * bytes where exec placed them, and `ps eww` and `/proc/<pid>/environ` read that original block,
 * so the value is overwritten in place first
 **/
pub(crate) fn take_credentials() {
    let _ = HELD.set(Held {
        token: take_env("PASSBOX_TOKEN"),
        passphrase: take_env(PASSPHRASE_ENV),
    });
}

fn take_env(name: &str) -> Option<zeroize::Zeroizing<String>> {
    let value = zeroize::Zeroizing::new(std::env::var(name).ok()?);
    wipe_env_value(name);
    // SAFETY: called first thing in main, while this is the only thread
    unsafe { std::env::remove_var(name) };
    Some(value)
}

fn wipe_env_value(name: &str) {
    use zeroize::Zeroize;
    #[cfg(target_os = "macos")]
    // SAFETY: returns the C runtime's own pointer to its environment pointer
    let table = unsafe { libc::_NSGetEnviron() };
    #[cfg(target_os = "macos")]
    // SAFETY: that pointer is valid for the life of the process
    let mut entry = unsafe { *table };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: the C runtime's own pointer to the environment table
    let mut entry = unsafe { environ };
    let prefix = format!("{name}=");

    // The table is NUL terminated, and only the matched entry's value is written
    loop {
        // SAFETY: `entry` stays inside the table, which ends with a null pointer
        let line = unsafe { *entry };
        if line.is_null() {
            break;
        }

        // SAFETY: each entry is a NUL terminated C string
        let bytes = unsafe { std::ffi::CStr::from_ptr(line) }.to_bytes();
        if let Some(value) = bytes.strip_prefix(prefix.as_bytes()) {
            // SAFETY: the prefix is inside the entry, so its end is too
            let start = unsafe { line.add(prefix.len()) }.cast::<u8>();
            // SAFETY: the value runs from `start` for `value.len()` bytes inside the entry
            unsafe { std::slice::from_raw_parts_mut(start, value.len()) }.zeroize();
        }
        // SAFETY: this entry was not the terminator, so the next slot is in the table
        entry = unsafe { entry.add(1) };
    }
}

#[cfg(not(target_os = "macos"))]
unsafe extern "C" {
    static environ: *mut *mut libc::c_char;
}

static STDIN_TOKEN: std::sync::OnceLock<zeroize::Zeroizing<String>> = std::sync::OnceLock::new();

/// The token this process was started with, held outside the environment. `--token-stdin` wins
pub(crate) fn held_token() -> Option<&'static str> {
    if let Some(token) = STDIN_TOKEN.get() {
        return Some(token.as_str());
    }

    HELD.get()?.token.as_deref().map(String::as_str)
}

// One line, a byte at a time, so a buffer cannot take input the exec child should get
pub(crate) fn take_stdin_token() -> Result<()> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: fd 0 stays open, ManuallyDrop keeps this File from closing it
    let mut stdin = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    let mut token = zeroize::Zeroizing::new(String::new());
    let mut byte = [0u8; 1];
    while stdin.read(&mut byte)? == 1 && byte[0] != b'\n' {
        token.push(char::from(byte[0]));
    }
    let token = zeroize::Zeroizing::new(token.trim().to_string());
    if token.is_empty() {
        bail!("--token-stdin read no token");
    }

    let _ = STDIN_TOKEN.set(token);
    Ok(())
}

pub(crate) fn held_passphrase() -> Option<&'static str> {
    HELD.get()?.passphrase.as_deref().map(String::as_str)
}
