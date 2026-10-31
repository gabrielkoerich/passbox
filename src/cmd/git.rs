//! The store as a git repository: a commit on every write, the mirror, and the push.

use crate::store::Store;
#[cfg(feature = "host")]
use crate::sync;
use anyhow::{Context, Result};

/* git carries the encrypted secrets and nothing that opens them. The Enclave wraps are useless
off the Mac that made them, so they stay out. The recovery wrap only exists once sync is on, and
then it belongs in the backup, because without it the backup cannot be restored anywhere. */
pub(crate) fn ensure_store_gitignore(store: &Store) -> Result<()> {
    let path = store.dir.join(".gitignore");
    if !path.exists() {
        std::fs::write(
            &path,
            "broker.sock\nnames\nremote\nconfig.toml\nstore/.versions/\nwraps/se-*.json\ngrants-*.age\nwindows-*.json\n",
        )?;
    }
    Ok(())
}

/// Saves cd-ing into the store. Values stay encrypted, so git only ever sees opaque files.
pub(crate) fn git(store: &Store, args: &[String]) -> Result<()> {
    ensure_store_gitignore(store)?;
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(args)
        .status()
        .context("git is not on PATH")?;
    std::process::exit(status.code().unwrap_or(1));
}

/// One place for everything a write should trigger, so a new command cannot forget half of it
pub(crate) fn written(store: &Store, what: &str) {
    commit(store, what);
    mirror(store);
    push(store);
}

/// Optional history alongside the copy. A subject naming an entry would undo the encrypted names.
fn in_git(store: &Store) -> bool {
    store.dir.join(".git").exists()
}

pub(crate) fn git_quietly(store: &Store, args: &[&str]) {
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/* Commit on every write, the way `pass` does once its store is a repo. Nothing is committed
until someone runs `passbox git init`, so this is a choice rather than a surprise, and it is
worth knowing what the choice costs: git history is permanent, so a secret removed from the
store stays in the history, still readable by the store key.

Subjects name the operation and not the entry, since a subject naming a secret would undo the
work of keeping names out of filenames. */
fn commit(store: &Store, what: &str) {
    if !in_git(store) {
        return;
    }
    let _ = ensure_store_gitignore(store);
    git_quietly(store, &["add", "-A"]);
    git_quietly(store, &["commit", "-m", what]);
}

/* A write that is only on this Mac is a write you can lose. Committing gives history, but the
copy elsewhere is what survives the machine, so a write updates it too.

Only a directory that was already chosen. An rclone remote is a slow round trip and stays on
`passbox sync`, git pushes separately in `push`.

Best effort by design. The value is already written and encrypted; failing the command because a
USB stick was unplugged would be the tail wagging the dog. Set PASSBOX_NO_AUTOSYNC to turn it
off for a script that writes in a loop. */
#[cfg(feature = "host")]
fn mirror(store: &Store) {
    if std::env::var_os("PASSBOX_NO_AUTOSYNC").is_some() {
        return;
    }
    let remote = match sync::configured(store) {
        Ok(Some(chosen)) if chosen.kind == sync::Kind::Directory => chosen.target,
        Ok(_) => return,
        Err(e) => {
            eprintln!("not copied: {e:#}");
            return;
        }
    };
    match sync::sync(store, std::path::Path::new(&remote)) {
        Ok(report) if report.pushed > 0 => eprintln!("{} copied to {remote}", report.pushed),
        Ok(_) => {}
        Err(e) => eprintln!("passbox: {e:#}"),
    }
}

#[cfg(not(feature = "host"))]
fn mirror(_store: &Store) {}

#[cfg(feature = "host")]
pub(crate) fn git_push(store: &Store) {
    if !in_git(store) {
        return;
    }
    commit(store, "update");
    push(store);
}

/// A commit only on this Mac is lost with it, so a repo with a remote pushes on every write.
/// Best effort like the mirror, and `-u` so a remote added with no upstream still works
fn push(store: &Store) {
    if !in_git(store) {
        return;
    }
    let remotes = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .arg("remote")
        .output();
    let Some(remote) = remotes.ok().and_then(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .map(str::to_string)
    }) else {
        return;
    };
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(["push", "-q", "-u", &remote, "HEAD"])
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => eprintln!(
            "not pushed to {remote}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => eprintln!("not pushed to {remote}: {e}"),
    }
}
