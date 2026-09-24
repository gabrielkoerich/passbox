//! Copies the store to and from a directory. No shared mutable file, so there is nothing to merge.

use crate::store::Store;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// iCloud Drive is an ordinary directory on macOS, so the default needs no account and no network
pub fn default_remote() -> Result<PathBuf> {
    if let Some(set) = std::env::var_os("PASSBOX_REMOTE") {
        return Ok(PathBuf::from(set));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join("Library/Mobile Documents/com~apple~CloudDocs/passbox"))
}

/// The socket is a live endpoint and the versions are this machine's own history
fn skip(relative: &Path) -> bool {
    let text = relative.to_string_lossy();
    text == "broker.sock" || text.starts_with("store/.versions")
}

fn walk(root: &Path, base: &Path, out: &mut BTreeMap<PathBuf, SystemTime>) -> Result<()> {
    if !base.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(base)? {
        let path = entry?.path();
        let relative = path.strip_prefix(root)?.to_path_buf();
        if skip(&relative) {
            continue;
        }
        if path.is_dir() {
            walk(root, &path, out)?;
        } else {
            out.insert(relative, fs::metadata(&path)?.modified()?);
        }
    }
    Ok(())
}

/// Copy preserving the modification time, so the next run does not copy it straight back
fn copy(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to)?;
    let when = fs::metadata(from)?.modified()?;
    fs::File::options()
        .write(true)
        .open(to)?
        .set_modified(when)?;
    Ok(())
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Report {
    pub pushed: usize,
    pub pulled: usize,
}

/// Union both sides, newest modification time wins, and keep whatever it replaced.
pub fn sync(store: &Store, remote: &Path) -> Result<Report> {
    if remote.to_string_lossy().contains(':') {
        bail!(
            "{} looks like an rclone remote, not a directory",
            remote.display()
        );
    }
    fs::create_dir_all(remote)?;

    let mut here = BTreeMap::new();
    let mut there = BTreeMap::new();
    walk(&store.dir, &store.dir, &mut here)?;
    walk(remote, remote, &mut there)?;

    let mut report = Report::default();
    let names: Vec<PathBuf> = here.keys().chain(there.keys()).cloned().collect();

    for name in names {
        let ours = here.get(&name);
        let theirs = there.get(&name);
        let from_here = store.dir.join(&name);
        let from_there = remote.join(&name);

        match (ours, theirs) {
            (Some(_), None) => {
                copy(&from_here, &from_there)?;
                report.pushed += 1;
            }
            (None, Some(_)) => {
                keep_losing_version(store, &name)?;
                copy(&from_there, &from_here)?;
                report.pulled += 1;
            }
            (Some(ours), Some(theirs)) if ours > theirs => {
                copy(&from_here, &from_there)?;
                report.pushed += 1;
            }
            (Some(ours), Some(theirs)) if theirs > ours => {
                keep_losing_version(store, &name)?;
                copy(&from_there, &from_here)?;
                report.pulled += 1;
            }
            _ => {}
        }
    }
    Ok(report)
}

/// A secret about to be overwritten from the far side goes into the versions first
fn keep_losing_version(store: &Store, relative: &Path) -> Result<()> {
    let Some(id) = secret_id(relative) else {
        return Ok(());
    };
    store.keep_version(&id)
}

fn secret_id(relative: &Path) -> Option<String> {
    if relative.parent() != Some(Path::new("store")) {
        return None;
    }
    if relative.extension()?.to_str()? != "age" {
        return None;
    }
    Some(relative.file_stem()?.to_str()?.to_string())
}

/// rclone covers every backend it supports, and nobody on the default path needs it installed
pub fn sync_via_rclone(store: &Store, remote: &str) -> Result<()> {
    let status = std::process::Command::new("rclone")
        .arg("bisync")
        .arg(&store.dir)
        .arg(remote)
        .args(["--filter", "- broker.sock"])
        .args(["--filter", "- .versions/**"])
        .arg("--resync-mode=newer")
        .status()
        .context("rclone is not on PATH, install it or point PASSBOX_REMOTE at a directory")?;

    if !status.success() {
        bail!("rclone bisync failed, try once with --resync");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DEFAULT_WINDOW_SECS, Mode, Secret, new_id, now};
    use secrecy::SecretString;

    fn store(dir: &Path) -> (Store, age::x25519::Identity) {
        let store = Store {
            dir: dir.to_path_buf(),
        };
        let pass = SecretString::from("hunter2".to_string());
        let key = store.init().unwrap();
        store.create_recovery_wrap(&key, pass).unwrap();
        (store, key)
    }

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.to_string(),
            mode: Mode::Window,
            window_secs: DEFAULT_WINDOW_SECS,
            value: value.to_string(),
            created: now(),
            updated: now(),
        }
    }

    #[test]
    fn each_side_gets_what_the_other_added() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        let (one, key) = store(a.path());
        one.put(
            &new_id(),
            &secret("from/one", "1"),
            &one.recipient().unwrap(),
        )
        .unwrap();
        sync(&one, remote.path()).unwrap();

        // The second machine joins by pulling the whole store, keys included
        let two = Store {
            dir: b.path().to_path_buf(),
        };
        sync(&two, remote.path()).unwrap();
        two.put(
            &new_id(),
            &secret("from/two", "2"),
            &two.recipient().unwrap(),
        )
        .unwrap();
        sync(&two, remote.path()).unwrap();
        sync(&one, remote.path()).unwrap();

        assert_eq!(one.names(&key).unwrap(), vec!["from/one", "from/two"]);
        assert_eq!(two.names(&key).unwrap(), vec!["from/one", "from/two"]);
    }

    #[test]
    fn a_delete_on_one_side_reaches_the_other_and_stays_deleted() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        let (one, key) = store(a.path());
        let id = new_id();
        one.put(
            &id,
            &secret("banking/login", "swordfish"),
            &one.recipient().unwrap(),
        )
        .unwrap();
        sync(&one, remote.path()).unwrap();

        let two = Store {
            dir: b.path().to_path_buf(),
        };
        sync(&two, remote.path()).unwrap();
        assert_eq!(two.names(&key).unwrap(), vec!["banking/login"]);

        one.delete(&id).unwrap();
        sync(&one, remote.path()).unwrap();
        sync(&two, remote.path()).unwrap();
        assert!(two.names(&key).unwrap().is_empty());

        // The tombstone is what stops the far side putting it back
        sync(&two, remote.path()).unwrap();
        sync(&one, remote.path()).unwrap();
        assert!(one.names(&key).unwrap().is_empty());
        assert!(two.names(&key).unwrap().is_empty());
    }

    #[test]
    fn the_losing_side_of_a_clash_is_kept() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        let (one, key) = store(a.path());
        let id = new_id();
        one.put(&id, &secret("db/pass", "first"), &one.recipient().unwrap())
            .unwrap();
        sync(&one, remote.path()).unwrap();

        let two = Store {
            dir: b.path().to_path_buf(),
        };
        sync(&two, remote.path()).unwrap();

        // Two writes the newer value, so one loses and keeps its own as a version
        std::thread::sleep(std::time::Duration::from_millis(1100));
        two.put(&id, &secret("db/pass", "second"), &two.recipient().unwrap())
            .unwrap();
        sync(&two, remote.path()).unwrap();
        sync(&one, remote.path()).unwrap();

        assert_eq!(one.load(&id, &key).unwrap().value, "second");
        assert!(!one.versions(&id).unwrap().is_empty());
    }

    #[test]
    fn syncing_twice_changes_nothing_the_second_time() {
        let a = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        let (one, _key) = store(a.path());
        one.put(&new_id(), &secret("a/b", "v"), &one.recipient().unwrap())
            .unwrap();

        sync(&one, remote.path()).unwrap();
        let second = sync(&one, remote.path()).unwrap();
        assert_eq!(
            second,
            Report {
                pushed: 0,
                pulled: 0
            }
        );
    }

    #[test]
    fn the_socket_and_the_versions_stay_at_home() {
        let a = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        let (one, _key) = store(a.path());
        let id = new_id();
        one.put(&id, &secret("a/b", "v1"), &one.recipient().unwrap())
            .unwrap();
        one.put(&id, &secret("a/b", "v2"), &one.recipient().unwrap())
            .unwrap();
        fs::write(one.socket_path(), b"").unwrap();

        sync(&one, remote.path()).unwrap();
        assert!(!remote.path().join("broker.sock").exists());
        assert!(!remote.path().join("store/.versions").exists());
    }

    #[test]
    fn an_rclone_remote_is_not_treated_as_a_directory() {
        let a = tempfile::tempdir().unwrap();
        let (one, _key) = store(a.path());
        assert!(sync(&one, Path::new("b2:passbox")).is_err());
    }
}
