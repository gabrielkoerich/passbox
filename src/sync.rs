//! Copies the store to and from a directory. No shared mutable file, so there is nothing to merge.

use crate::store::Store;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(PartialEq, Eq, Debug)]
pub enum Kind {
    Directory,
    Rclone,
    Git,
}

/// A destination is a directory unless it looks like a git URL or an rclone remote
pub fn classify(remote: &str) -> Kind {
    let remote = remote.trim();
    if remote.starts_with("git@")
        || remote.starts_with("ssh://")
        || remote.ends_with(".git")
        || remote.starts_with("https://")
    {
        return Kind::Git;
    }
    if remote.starts_with('/') || remote.starts_with('~') || remote.starts_with('.') {
        return Kind::Directory;
    }
    if remote.contains(':') {
        return Kind::Rclone;
    }
    Kind::Directory
}

/// Where a chosen destination is kept, so a later bare `passbox sync` goes to the same place
pub fn remote_path(store: &Store) -> PathBuf {
    store.dir.join("remote")
}

pub fn configured_remote(store: &Store) -> Option<String> {
    std::fs::read_to_string(remote_path(store))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The environment wins, then whatever was chosen, then iCloud Drive
pub fn default_remote(store: &Store) -> Result<String> {
    if let Some(set) = std::env::var_os("PASSBOX_REMOTE") {
        return Ok(set.to_string_lossy().to_string());
    }
    if let Some(chosen) = configured_remote(store) {
        return Ok(chosen);
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library/Mobile Documents/com~apple~CloudDocs/passbox")
        .to_string_lossy()
        .to_string())
}

/* The socket is a live endpoint and the versions are this machine's own history. Grants stay put
too, since one that travelled would let a machine you have not touched inherit an approval given
here. The chosen remote is machine local, because a USB path on one Mac means nothing on another. */
fn skip(relative: &Path) -> bool {
    let text = relative.to_string_lossy();
    text == "broker.sock"
        || text == "remote"
        || text.starts_with("store/.versions")
        || (text.starts_with("grants-") && text.ends_with(".age"))
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
        store
            .create_recovery_wrap_with_factor(&key, pass, Some(10))
            .unwrap();
        (store, key)
    }

    fn secret(name: &str, value: &str) -> Secret {
        Secret {
            name: name.to_string(),
            mode: Mode::Window,
            window_secs: DEFAULT_WINDOW_SECS,
            lease_secs: 0,
            value: value.to_string(),
            created: now(),
            updated: now(),
        }
    }

    #[test]
    fn destinations_are_classified_by_shape() {
        assert_eq!(classify("/Volumes/stick/passbox"), Kind::Directory);
        assert_eq!(classify("~/Dropbox/passbox"), Kind::Directory);
        assert_eq!(classify("b2:passbox"), Kind::Rclone);
        assert_eq!(classify("drive:passbox"), Kind::Rclone);
        assert_eq!(classify("git@github.com:you/store.git"), Kind::Git);
        assert_eq!(classify("https://github.com/you/store.git"), Kind::Git);
        assert_eq!(classify("ssh://git@host/store"), Kind::Git);
    }

    /// A git URL also contains a colon, so it must be tested before the rclone shape
    #[test]
    fn a_git_url_is_not_read_as_an_rclone_remote() {
        assert_ne!(classify("git@github.com:you/store.git"), Kind::Rclone);
    }

    #[test]
    fn a_chosen_remote_outlives_the_shell() {
        let tmp = tempfile::tempdir().unwrap();
        let (one, _key) = store(tmp.path());
        assert!(configured_remote(&one).is_none());

        crate::store::write_private(&remote_path(&one), b"/Volumes/stick/passbox").unwrap();
        assert_eq!(
            configured_remote(&one).as_deref(),
            Some("/Volumes/stick/passbox")
        );
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

    /// An approval given on this Mac must not arrive on a machine you never touched
    #[test]
    fn grants_never_travel() {
        let a = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let (one, _key) = store(a.path());

        let grant = crate::project::Grant {
            dir: "/x".into(),
            hash: "h".into(),
            secrets: vec!["a/b".into()],
            until: now() + 600,
        };
        crate::project::save(&one, &[grant]).unwrap();
        sync(&one, remote.path()).unwrap();

        let leaked: Vec<_> = fs::read_dir(remote.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("grants-"))
            .collect();
        assert!(leaked.is_empty(), "{leaked:?}");
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
