//! Ways into the store: init, a recovery passphrase, a YubiKey, another Mac, and where sync copies go.

#[cfg(feature = "host")]
use super::git::{ensure_store_gitignore, git_push, git_quietly};
use crate::store::Store;
#[cfg(feature = "host")]
use crate::unlock;
use crate::{ask, headless};
#[cfg(feature = "host")]
use crate::{sync, yubikey};
use age::x25519;
use anyhow::{Result, bail};
use secrecy::SecretString;

const MIN_PASSPHRASE: usize = 12;

#[cfg(feature = "host")]
pub(crate) fn run_sync(store: &Store, remote: Option<&str>) -> Result<()> {
    // An empty directory is a machine joining, and the wrap it needs arrives with the pull
    if store.is_initialised() && !store.has_portable_wrap() {
        bail!(
            "sync is off. No other machine could open this store, because the key is held by \
             this Mac's Secure Enclave alone. Add a way in first: `passbox sync --enable` for \
             a recovery passphrase, or `passbox yubikey-add` for a token."
        );
    }

    let sync::Destination { kind, target } = match remote {
        Some(given) => sync::Destination::guess(given),
        None => sync::default_destination(store)?,
    };
    let remote = target;

    match kind {
        // git carries its own history, so there is no directory to copy into
        sync::Kind::Git => git_push(store),
        sync::Kind::Rclone => {
            sync::sync_via_rclone(store, &remote)?;
            git_push(store);
        }
        sync::Kind::Directory => {
            let report = sync::sync(store, std::path::Path::new(&remote))?;
            eprintln!(
                "{} sent, {} received, {remote}",
                report.pushed, report.pulled
            );
            git_push(store);
        }
    }
    Ok(())
}

pub(crate) fn init(store: &Store) -> Result<()> {
    let key = store.init()?;
    eprintln!("store ready at {}", store.dir.display());

    // Without an Enclave there is nothing holding the key, so a passphrase is the only option
    #[cfg(not(feature = "host"))]
    let bound = false;
    #[cfg(feature = "host")]
    let bound = bind_machine(store, &key);
    if headless() || !bound {
        new_passphrase(store, &key)?;
    } else {
        eprintln!();
        eprintln!("This store opens on this Mac only. Lose it and the secrets are gone.");
        eprintln!("`passbox sync --enable` adds a passphrase and a copy on another machine.");
    }
    Ok(())
}

#[cfg(feature = "host")]
pub(crate) fn enable_sync(store: &Store) -> Result<()> {
    // How the copy is opened and where it goes are separate questions
    if store.has_portable_wrap() {
        eprintln!("the store already has a wrap that opens it elsewhere");
        return choose_remote(store);
    }

    eprintln!("Syncing puts a copy of this store where another machine can read it.");
    eprintln!("That copy needs a way in. Two choices:");
    eprintln!();
    eprintln!("  1) A YubiKey. Nothing in the copy can be attacked, and you keep the token.");
    eprintln!("  2) A passphrase. Works anywhere, and anyone holding the copy can grind it.");
    eprintln!();
    eprint!("Which? [1/2] ");

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim() {
        "1" => enable_with_yubikey(store)?,
        "2" => {
            let key = unlock(store, "turn on sync")?;
            new_passphrase(store, &key)?;
            eprintln!("sync is on, wraps/recovery.age now travels with the store");
        }
        other => bail!("expected 1 or 2, got {other}"),
    }
    choose_remote(store)
}

/// Asked once and remembered, so a later bare `passbox sync` cannot surprise you with iCloud
#[cfg(feature = "host")]
fn choose_remote(store: &Store) -> Result<()> {
    if let Some(moved) = sync::migrate(store)? {
        eprintln!(
            "{} now names {}, the old remote file is gone",
            sync::config_path(store).display(),
            moved.target
        );
        return Ok(());
    }

    // Only `sync --enable` reaches here, so a destination already set is one to offer changing
    // A broken file is one to replace, so it does not block choosing again
    if let Some(already) = sync::configured(store).unwrap_or(None) {
        eprintln!("copies currently go to {}", already.target);
        eprint!("Change that? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            return Ok(());
        }
    }

    eprintln!();
    eprintln!("Where should the copy go?");
    eprintln!();
    eprintln!("  1) iCloud Drive, a folder on this Mac that Apple replicates");
    eprintln!("  2) A directory you name, such as a USB stick or Dropbox");
    eprintln!("  3) A git remote, which also gives you history");
    eprintln!("  4) An rclone remote, for S3, B2, Drive and the rest");
    eprintln!();
    eprint!("Which? [1/2/3/4] ");

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;

    let engine = match answer.trim() {
        "1" => sync::Engine::Icloud { directory: None },
        "2" => {
            let dir = prompt("directory: ")?;
            let path = match (dir.strip_prefix("~/"), std::env::var_os("HOME")) {
                (Some(rest), Some(home)) => std::path::Path::new(&home)
                    .join(rest)
                    .to_string_lossy()
                    .to_string(),
                _ => dir,
            };
            sync::Engine::Directory { path }
        }
        "3" => sync::Engine::Git {
            remote: prompt("git remote, such as git@github.com:you/passbox-store.git: ")?,
        },
        "4" => sync::Engine::Rclone {
            remote: prompt("rclone remote, such as b2:passbox: ")?,
        },
        other => bail!("expected 1 to 4, got {other}"),
    };

    // Checked before anything is created, so a bad answer leaves no folder or repo behind
    let destination = engine.resolve()?;
    match destination.kind {
        sync::Kind::Directory => std::fs::create_dir_all(&destination.target)?,
        sync::Kind::Git => {
            ensure_store_gitignore(store)?;
            git_quietly(store, &["init"]);
            git_quietly(store, &["remote", "add", "origin", &destination.target]);
        }
        sync::Kind::Rclone => {}
    }
    sync::choose(store, engine)?;
    eprintln!(
        "copies go to {}, set in {}",
        destination.target,
        sync::config_path(store).display()
    );
    Ok(())
}

#[cfg(feature = "host")]
fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_string();
    if answer.is_empty() {
        bail!("nothing given");
    }
    Ok(answer)
}

#[cfg(feature = "host")]
fn enable_with_yubikey(store: &Store) -> Result<()> {
    let recipient = new_token(store)?;
    let key = unlock(store, "turn on sync with a YubiKey")?;
    let total = store.add_yubikey_recipient(&key, &recipient)?;
    eprintln!("sync is on, and the copy is useless without one of those {total} token(s)");
    eprintln!("add a second with `passbox yubikey-add`, or losing it loses the way back");
    Ok(())
}

/**
 * The plugged token the store does not hold yet. Setup runs only when no plugged token has an
 * identity, since generating on a token already added spends a slot and backs up nothing
 **/
#[cfg(feature = "host")]
fn new_token(store: &Store) -> Result<String> {
    yubikey::offer_install()?;
    let stored = store.yubikey_recipients();

    let plugged = yubikey::recipients()?;
    let found = if plugged.is_empty() {
        set_up_token()?;
        yubikey::recipients()?
    } else {
        plugged
    };
    let seen = found.len();
    let found = yubikey::not_added(found, &stored);
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    yubikey::choose(
        found,
        seen,
        terminal.then_some(|| {
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            Ok(answer)
        }),
    )
}

#[cfg(feature = "host")]
fn set_up_token() -> Result<()> {
    eprintln!("No age identity on the token yet. Generating one uses a PIV slot.");
    match yubikey::piv_slots_in_use() {
        Some(slots) if !slots.is_empty() => {
            eprintln!("The PIV applet already holds:");
            for slot in &slots {
                eprintln!("  {slot}");
            }
            eprintln!("A free slot is used, and your OpenPGP keys are a separate applet.");
        }
        Some(_) => eprintln!("The PIV applet is empty, and OpenPGP is a separate applet."),
        None => eprintln!("Could not read the PIV applet. Install ykman to check it first."),
    }
    // Fail here rather than after the plugin has asked for a PIN it cannot use
    yubikey::management_key_is_supported()?;
    eprint!("Generate one now? [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        bail!("run `age-plugin-yubikey --generate` when ready, then try again");
    }
    yubikey::offer_to_stop_scdaemon()?;
    yubikey::generate()
}

/// Sync needs this: no other machine can open the store without it
fn new_passphrase(store: &Store, key: &x25519::Identity) -> Result<()> {
    let pass = ask("recovery passphrase: ")?;
    if pass.chars().count() < MIN_PASSPHRASE {
        bail!("use at least {MIN_PASSPHRASE} characters, a copy of this leaves the Mac");
    }
    if !headless() && ask("again: ")? != pass {
        bail!("passphrases do not match");
    }
    store.create_recovery_wrap_with_factor(key, SecretString::from(pass), test_work_factor())
}

/// Only a debug build will weaken the KDF, so a release binary cannot be talked into it
fn test_work_factor() -> Option<u8> {
    #[cfg(debug_assertions)]
    {
        std::env::var("PASSBOX_SCRYPT_LOG_N")
            .ok()
            .and_then(|v| v.parse().ok())
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// True when the Enclave took the key. An older Mac or CI cannot, and falls back to a passphrase.
#[cfg(feature = "host")]
fn bind_machine(store: &Store, key: &x25519::Identity) -> bool {
    if headless() {
        return false;
    }
    match store.create_se_wrap(key) {
        Ok(()) => {
            eprintln!("bound to this Mac, reads will ask for your fingerprint");
            true
        }
        Err(e) => {
            eprintln!("no Secure Enclave here ({e:#}), reads will ask for the passphrase");
            false
        }
    }
}

/**
 * A YubiKey wrap replaces the passphrase for recovery. Nothing in a synced copy can then be
 * attacked offline, because the private half never leaves the token
 **/
#[cfg(feature = "host")]
pub(crate) fn yubikey_add(store: &Store, recipient: Option<&str>) -> Result<()> {
    let recipient = match recipient {
        Some(r) => {
            yubikey::offer_install()?;
            r.to_string()
        }
        None => new_token(store)?,
    };
    let key = unlock(store, "wrap the store key to a YubiKey")?;
    let total = store.add_yubikey_recipient(&key, &recipient)?;
    eprintln!("wrapped to {recipient}");
    eprintln!("{total} token(s) can now open this store on any machine");
    if total == 1 {
        eprintln!("add a second with `passbox yubikey-add`, or losing it loses the way back");
    }
    check_token(store, &key, &recipient)
}

/// Opens the wrap with the new token alone, the one proof that it is a way back
#[cfg(feature = "host")]
fn check_token(store: &Store, key: &x25519::Identity, recipient: &str) -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(());
    }
    eprint!("Check the new token now? Unplug every other YubiKey first. [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }

    // The plugin opens with whichever token it finds, so a second one would pass for this one
    let plugged = yubikey::recipients()?;
    if plugged.len() != 1 || plugged[0].recipient != recipient {
        bail!("plug in only the new token, then run `passbox yubikey-add {recipient}` again");
    }
    eprintln!("Touch the YubiKey.");
    if store.unlock_with_yubikey()?.to_public() != key.to_public() {
        bail!("the new token opened a different key, do not rely on it");
    }
    eprintln!("the new token opens this store");
    Ok(())
}

#[cfg(feature = "host")]
pub(crate) fn machine_add(store: &Store) -> Result<()> {
    if store.has_se_wrap() {
        bail!(
            "this Mac is already bound, its wrap is {}",
            store.se_wrap_path().display()
        );
    }
    let key = if store.has_yubikey_wrap() && yubikey::installed() {
        eprintln!("Touch the YubiKey to bind this Mac.");
        store.unlock_with_yubikey()?
    } else {
        eprintln!("Binding this Mac needs the recovery passphrase once.");
        store.unlock_with_passphrase(SecretString::from(ask("recovery passphrase: ")?))?
    };
    store.create_se_wrap(&key)?;
    eprintln!("bound, reads on this Mac will ask for your fingerprint");
    Ok(())
}
