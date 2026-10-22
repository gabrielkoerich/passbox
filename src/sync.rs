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

/// The old one-line destination, read when there is no config and replaced by the next `--enable`
pub fn remote_path(store: &Store) -> PathBuf {
    store.dir.join("remote")
}

/// Machine local, since a USB path on one Mac means nothing on another
pub fn config_path(store: &Store) -> PathBuf {
    store.dir.join("config.toml")
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sync: Option<Engine>,
    // Checked by the broker against the plugin manifests, see `plugin::windows`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plugins: Option<toml::Table>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(tag = "engine", rename_all = "lowercase", deny_unknown_fields)]
pub enum Engine {
    Icloud {
        #[serde(skip_serializing_if = "Option::is_none")]
        directory: Option<String>,
    },
    Directory {
        path: String,
    },
    Git {
        remote: String,
    },
    Rclone {
        remote: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Destination {
    pub kind: Kind,
    pub target: String,
}

impl Destination {
    /// For `--remote`, `PASSBOX_REMOTE` and the old file, which name no engine
    pub fn guess(target: &str) -> Self {
        Destination {
            kind: classify(target),
            target: target.trim().to_string(),
        }
    }
}

fn icloud_root() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join("Library/Mobile Documents/com~apple~CloudDocs"))
}

fn clean(what: &str, value: &str) -> Result<()> {
    if value.is_empty() || value != value.trim() || value.chars().any(char::is_control) {
        bail!("{what} {value:?} is empty, has a space at either end, or holds a control character");
    }
    Ok(())
}

impl Engine {
    /// Checked on every read, so a stray keystroke in the file is an error and never a new folder
    pub fn resolve(&self) -> Result<Destination> {
        let (kind, target) = match self {
            Engine::Icloud { directory } => {
                let name = directory.as_deref().unwrap_or(".passbox");
                clean("directory", name)?;
                if name.contains('/') || name == "." || name == ".." {
                    bail!("directory {name:?} must be one folder name inside iCloud Drive");
                }
                let target = icloud_root()?.join(name).to_string_lossy().to_string();
                (Kind::Directory, target)
            }
            Engine::Directory { path } => {
                clean("path", path)?;
                if !Path::new(path).is_absolute() {
                    bail!("path {path:?} must be absolute");
                }
                (Kind::Directory, path.clone())
            }
            Engine::Git { remote } => {
                clean("remote", remote)?;
                if classify(remote) != Kind::Git {
                    bail!("remote {remote:?} is not a git URL");
                }
                (Kind::Git, remote.clone())
            }
            Engine::Rclone { remote } => {
                clean("remote", remote)?;
                if classify(remote) != Kind::Rclone {
                    bail!("remote {remote:?} is not an rclone remote such as b2:passbox");
                }
                (Kind::Rclone, remote.clone())
            }
        };
        Ok(Destination { kind, target })
    }
}

/// The chosen destination: the config, then the old `remote` file, then nothing
pub fn configured(store: &Store) -> Result<Option<Destination>> {
    let path = config_path(store);
    if let Ok(text) = fs::read_to_string(&path) {
        let invalid = || format!("{} is not valid", path.display());
        let config: Config = toml::from_str(&text).with_context(invalid)?;
        if let Some(engine) = config.sync {
            return engine.resolve().map(Some).with_context(invalid);
        }
    }
    let old = legacy(store)?;
    if old.is_some() {
        eprintln!("{}", legacy_warning(store));
    }
    Ok(old)
}

fn legacy_warning(store: &Store) -> String {
    format!(
        "passbox: {} is deprecated and stops being read in v3, run `passbox sync --enable` to \
         move it to {}",
        remote_path(store).display(),
        config_path(store).display()
    )
}

fn legacy(store: &Store) -> Result<Option<Destination>> {
    let Ok(text) = fs::read_to_string(remote_path(store)) else {
        return Ok(None);
    };
    let text = text.trim();
    // A YubiKey touched while editing the file types a code and a newline into the path
    if text.contains(['\n', '\r']) {
        bail!(
            "{} holds more than one line, write the destination on one line",
            remote_path(store).display()
        );
    }
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(Destination::guess(text)))
}

/// Writes the old `remote` file to the config with the same destination, for `--enable`
pub fn migrate(store: &Store) -> Result<Option<Destination>> {
    if config_path(store).exists() {
        return Ok(None);
    }
    let Some(old) = legacy(store)? else {
        return Ok(None);
    };
    let engine = match old.kind {
        Kind::Git => Engine::Git { remote: old.target },
        Kind::Rclone => Engine::Rclone { remote: old.target },
        Kind::Directory => match Path::new(&old.target).strip_prefix(icloud_root()?) {
            Ok(name) if name == Path::new(".passbox") => Engine::Icloud { directory: None },
            Ok(name) if name.components().count() == 1 => Engine::Icloud {
                directory: Some(name.to_string_lossy().to_string()),
            },
            _ => Engine::Directory { path: old.target },
        },
    };
    choose(store, engine).map(Some)
}

/// Written by `--enable`, and it replaces the old `remote` file
pub fn choose(store: &Store, engine: Engine) -> Result<Destination> {
    let destination = engine.resolve()?;
    // The plugin windows in the same file are the owner's, so choosing a destination keeps them
    let plugins = fs::read_to_string(config_path(store))
        .ok()
        .and_then(|text| toml::from_str::<Config>(&text).ok())
        .and_then(|c| c.plugins);
    let text = toml::to_string(&Config {
        sync: Some(engine),
        plugins,
    })?;
    crate::store::write_private(&config_path(store), text.as_bytes())?;
    let _ = fs::remove_file(remote_path(store));
    Ok(destination)
}

/// The environment wins, then whatever was chosen, then iCloud Drive
pub fn default_destination(store: &Store) -> Result<Destination> {
    if let Some(set) = std::env::var_os("PASSBOX_REMOTE") {
        return Ok(Destination::guess(&set.to_string_lossy()));
    }
    if let Some(chosen) = configured(store)? {
        return Ok(chosen);
    }
    Engine::Icloud { directory: None }.resolve()
}

/* What never syncs, in rclone filter syntax so `sync_via_rclone` excludes the same list. A
leading `/` anchors the pattern at the store root, without one it matches a file name anywhere.
Matching ignores case, as macOS and iCloud Drive do. */
const NEVER_SYNCED: &[&str] = &[
    // Live endpoints, and the public keys this machine rebuilds whenever the store key opens
    "/broker.sock",
    "/ssh-agent.sock",
    "/ssh-keys.pub",
    // A client's broker address, which on another Mac would send its reads to this one's host
    "/host",
    // A USB path on one Mac means nothing on another
    "/remote",
    "/config.toml",
    "/names",
    "/plugins/**",
    // The repo is this machine's history, and the remote is a mirror rather than a clone
    "/.git/**",
    "/.gitignore",
    "/store/.versions/**",
    // A copy cut off before its rename, never a real file
    "*.partial",
    // A grant that travelled would let a machine you have not touched inherit an approval
    "/grants-*.age",
    "/windows-*.json",
];

fn matches(pattern: &str, relative: &str) -> bool {
    let (pattern, relative) = (pattern.to_lowercase(), relative.to_lowercase());
    let (pattern, text) = match pattern.strip_prefix('/') {
        Some(rooted) => (rooted, relative.as_str()),
        None => (
            pattern.as_str(),
            relative.rsplit('/').next().unwrap_or(&relative),
        ),
    };
    if let Some(dir) = pattern.strip_suffix("/**") {
        return text == dir || text.starts_with(&format!("{dir}/"));
    }
    match pattern.split_once('*') {
        Some((head, tail)) => {
            text.len() >= head.len() + tail.len()
                && text.starts_with(head)
                && text.ends_with(tail)
                && !text[head.len()..text.len() - tail.len()].contains('/')
        }
        None => text == pattern,
    }
}

fn skip(relative: &Path) -> bool {
    let text = relative.to_string_lossy();
    NEVER_SYNCED.iter().any(|p| matches(p, &text))
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
        let meta = fs::metadata(&path)?;
        if meta.is_dir() {
            walk(root, &path, out)?;
        } else if meta.is_file() {
            out.insert(relative, meta.modified()?);
        }
    }
    Ok(())
}

/// Copy preserving the modification time, so the next run does not copy it straight back. The
/// rename makes it whole or absent, since a cut-off copy would look newest and win the next sync
fn copy(from: &Path, to: &Path) -> Result<()> {
    let parent = to.parent().context("a copy needs a parent directory")?;
    fs::create_dir_all(parent)?;
    let mut partial = to.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    fs::copy(from, &partial)?;
    let when = fs::metadata(from)?.modified()?;
    fs::File::options()
        .write(true)
        .open(&partial)?
        .set_modified(when)?;
    fs::rename(&partial, to)?;
    Ok(())
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Report {
    pub pushed: usize,
    pub pulled: usize,
}

/* Only choosing a destination creates it, so a path that changed by accident or a stick that is
unplugged fails here instead of getting a fresh mirror that splits the store. A folder holding
other files is refused too, since the union would copy all of them into the store. */
fn check_destination(store: &Store, remote: &Path) -> Result<()> {
    let shown = remote.display();
    let again = "run `passbox sync --enable` to choose again";
    if !remote.is_absolute() {
        bail!("{shown} is not an absolute path, {again}");
    }
    if !remote.is_dir() {
        bail!("{shown} does not exist. Create it, or {again}");
    }
    let unreadable = || format!("could not read {shown}, nothing synced");
    let there = remote.canonicalize().with_context(unreadable)?;
    let here = store.dir.canonicalize()?;
    if there.starts_with(&here) || here.starts_with(&there) {
        bail!(
            "{shown} overlaps the store at {}, {again}",
            store.dir.display()
        );
    }
    let mirror = remote.join("store").is_dir() || remote.join("wraps").is_dir();
    let empty = fs::read_dir(remote)
        .with_context(unreadable)?
        .filter_map(|e| e.ok())
        .all(|e| e.file_name() == ".DS_Store");
    if !mirror && !empty {
        bail!("{shown} holds other files and no passbox copy, {again} with an empty folder");
    }
    Ok(())
}

/// Union both sides, newest modification time wins, and keep whatever it replaced.
pub fn sync(store: &Store, remote: &Path) -> Result<Report> {
    if remote.to_string_lossy().contains(':') {
        bail!(
            "{} looks like an rclone remote, not a directory",
            remote.display()
        );
    }
    check_destination(store, remote)?;

    let mut here = BTreeMap::new();
    let mut there = BTreeMap::new();
    walk(&store.dir, &store.dir, &mut here)?;
    walk(remote, remote, &mut there)
        .with_context(|| format!("could not read {}, nothing synced", remote.display()))?;

    let mut report = Report::default();
    let (mut failed, mut first) = (0, None);
    let names: Vec<PathBuf> = here.keys().chain(there.keys()).cloned().collect();

    for name in names {
        let ours = here.get(&name);
        let theirs = there.get(&name);
        let from_here = store.dir.join(&name);
        let from_there = remote.join(&name);
        let push = || copy(&from_here, &from_there);
        let pull = || {
            keep_losing_version(store, &name)?;
            copy(&from_there, &from_here)
        };

        // A tombstone loses to its secret written after it, so rm then add of one name sticks
        let done = match (ours, theirs) {
            (None, Some(theirs)) if outlived(&here, &name, *theirs) => {
                fs::remove_file(&from_there).map_err(Into::into)
            }
            (Some(ours), None) if outlived(&there, &name, *ours) => {
                fs::remove_file(&from_here).map_err(Into::into)
            }
            (Some(_), None) => push().map(|()| report.pushed += 1),
            (None, Some(_)) => pull().map(|()| report.pulled += 1),
            (Some(ours), Some(theirs)) if ours > theirs => push().map(|()| report.pushed += 1),
            (Some(ours), Some(theirs)) if theirs > ours => pull().map(|()| report.pulled += 1),
            _ => Ok(()),
        };
        // One summary for the run, since a folder macOS refuses would fail every file the same way
        if let Err(e) = done {
            first.get_or_insert_with(|| format!("{}: {e:#}", name.display()));
            failed += 1;
        }
    }

    if let Some(first) = first {
        bail!(
            "could not sync {failed} {} to {}, the copy there is incomplete: {first}",
            if failed == 1 { "file" } else { "files" },
            remote.display()
        );
    }
    Ok(report)
}

/* A tombstone on one side and a secret with the same id written after it on the other side is a
delete undone by `add`, which reuses the id so `restore` still reaches the old versions. Copying
the tombstone over would hide the new value again */
fn outlived(side: &BTreeMap<PathBuf, SystemTime>, tomb: &Path, deleted: SystemTime) -> bool {
    if tomb.parent() != Some(Path::new("store"))
        || tomb.extension().and_then(|e| e.to_str()) != Some("tomb")
    {
        return false;
    }
    side.get(&tomb.with_extension("age"))
        .is_some_and(|written| *written > deleted)
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

fn rclone_args(store: &Store, remote: &str) -> Vec<std::ffi::OsString> {
    let mut args = vec![
        "bisync".into(),
        store.dir.clone().into(),
        remote.into(),
        "--ignore-case".into(),
    ];
    for pattern in NEVER_SYNCED {
        args.push("--exclude".into());
        args.push(pattern.into());
    }
    args.push("--resync-mode=newer".into());
    args
}

/// rclone covers every backend it supports, and nobody on the default path needs it installed
pub fn sync_via_rclone(store: &Store, remote: &str) -> Result<()> {
    let status = std::process::Command::new("rclone")
        .args(rclone_args(store, remote))
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
    use crate::store::{Secret, new_id, now};
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
        assert!(configured(&one).unwrap().is_none());

        crate::store::write_private(&remote_path(&one), b"/Volumes/stick/passbox\n").unwrap();
        let chosen = configured(&one).unwrap().unwrap();
        assert_eq!(chosen.target, "/Volumes/stick/passbox");
        assert_eq!(chosen.kind, Kind::Directory);
    }

    #[test]
    fn choosing_writes_a_config_that_wins_over_the_old_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (one, _key) = store(tmp.path());
        crate::store::write_private(&remote_path(&one), b"/old/place").unwrap();

        let engine = Engine::Directory {
            path: "/Volumes/stick/passbox".into(),
        };
        fs::write(
            config_path(&one),
            "[plugins.windows]\n\"things3.logbook\" = \"1h\"\n",
        )
        .unwrap();
        // Windows alone name no destination, so the old file still answers
        assert_eq!(configured(&one).unwrap().unwrap().target, "/old/place");
        choose(&one, engine).unwrap();
        assert!(!remote_path(&one).exists(), "the old file is replaced");
        let text = fs::read_to_string(config_path(&one)).unwrap();
        assert!(text.contains("engine = \"directory\""), "{text}");
        assert!(text.contains("\"things3.logbook\" = \"1h\""), "{text}");
        assert_eq!(
            configured(&one).unwrap().unwrap().target,
            "/Volumes/stick/passbox"
        );
    }

    #[test]
    fn migrating_keeps_the_old_destination_and_names_its_engine() {
        let tmp = tempfile::tempdir().unwrap();
        let (one, _key) = store(tmp.path());
        let icloud = icloud_root().unwrap();
        let cases = [
            (
                icloud.join(".passbox").display().to_string(),
                "engine = \"icloud\"\n",
            ),
            (
                icloud.join("vault").display().to_string(),
                "directory = \"vault\"",
            ),
            ("/Volumes/stick/passbox".into(), "engine = \"directory\""),
            ("git@github.com:me/store.git".into(), "engine = \"git\""),
            ("b2:passbox".into(), "engine = \"rclone\""),
        ];
        for (old, expected) in cases {
            let _ = fs::remove_file(config_path(&one));
            crate::store::write_private(&remote_path(&one), old.as_bytes()).unwrap();
            assert_eq!(migrate(&one).unwrap().unwrap().target, old);
            let text = fs::read_to_string(config_path(&one)).unwrap();
            assert!(text.contains(expected), "{old}: {text}");
            assert!(!remote_path(&one).exists(), "{old}");
            assert_eq!(configured(&one).unwrap().unwrap().target, old);
        }

        // A config already written is left alone, and so is a store with no old file
        crate::store::write_private(&remote_path(&one), b"/elsewhere").unwrap();
        assert_eq!(migrate(&one).unwrap(), None);
        assert!(remote_path(&one).exists());
    }

    #[test]
    fn the_engine_names_the_kind_and_icloud_names_one_folder() {
        let parse = |text: &str| toml::from_str::<Config>(text).map(|c| c.sync.unwrap().resolve());
        let icloud = parse("[sync]\nengine = \"icloud\"\n").unwrap().unwrap();
        assert!(
            icloud.target.ends_with("com~apple~CloudDocs/.passbox"),
            "{icloud:?}"
        );
        let named = parse("[sync]\nengine = \"icloud\"\ndirectory = \"vault\"\n");
        assert!(named.unwrap().unwrap().target.ends_with("CloudDocs/vault"));

        // A path holding a colon stays a directory, since the engine says so
        let odd = parse("[sync]\nengine = \"directory\"\npath = \"/Volumes/a:b\"\n");
        assert_eq!(odd.unwrap().unwrap().kind, Kind::Directory);
        let git = parse("[sync]\nengine = \"git\"\nremote = \"git@github.com:you/s.git\"\n");
        assert_eq!(git.unwrap().unwrap().kind, Kind::Git);
    }

    #[test]
    fn a_config_that_makes_no_sense_is_refused() {
        let refused = |text: &str| {
            toml::from_str::<Config>(text)
                .map_err(anyhow::Error::from)
                .and_then(|c| c.sync.context("no sync")?.resolve())
                .is_err()
        };
        assert!(refused(
            "[sync]\nengine = \"icloud\"\ndirectory = \".ccdbkdtdu\npassbox\"\n"
        ));
        assert!(refused(
            "[sync]\nengine = \"icloud\"\ndirectory = \"a/b\"\n"
        ));
        assert!(refused("[sync]\nengine = \"icloud\"\ndirectory = \"..\"\n"));
        assert!(refused(
            "[sync]\nengine = \"icloud\"\ndirectory = \" .passbox\"\n"
        ));
        assert!(refused(
            "[sync]\nengine = \"directory\"\npath = \"relative\"\n"
        ));
        assert!(
            refused("[sync]\nengine = \"directory\"\n"),
            "a path is required"
        );
        assert!(
            refused("[sync]\nengine = \"dropbox\"\n"),
            "an unknown engine"
        );
        assert!(
            refused("[sync]\nengine = \"icloud\"\npath = \"/x\"\n"),
            "a key the engine has not"
        );
        assert!(refused(
            "[sync]\nengine = \"git\"\nremote = \"/not/a/url\"\n"
        ));
        assert!(refused(
            "[sync]\nengine = \"rclone\"\nremote = \"no-colon\"\n"
        ));
        assert!(
            refused("[sync]\nengine = \"icloud\"\n.ccdbkdtdu\n"),
            "a stray line"
        );
        assert!(
            refused("[sync]\nengine = \"icloud\"\n[other]\n"),
            "an unknown section"
        );
    }

    #[test]
    fn only_an_empty_folder_or_a_passbox_copy_is_a_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let (one, _key) = store(&tmp.path().join("store"));
        let refused = |remote: &Path| check_destination(&one, remote).is_err();

        assert!(refused(Path::new("relative/passbox")));
        assert!(refused(&tmp.path().join("missing")));
        assert!(refused(&one.dir));
        assert!(refused(&one.dir.join("store")));
        assert!(refused(tmp.path()), "a folder holding the store");

        let dropbox = tmp.path().join("dropbox");
        fs::create_dir_all(&dropbox).unwrap();
        fs::write(dropbox.join(".DS_Store"), "").unwrap();
        assert!(!refused(&dropbox), "an empty folder is a new mirror");
        fs::write(dropbox.join("taxes.pdf"), "").unwrap();
        assert!(refused(&dropbox), "a folder with other files");
        fs::create_dir(dropbox.join("store")).unwrap();
        assert!(!refused(&dropbox), "a passbox copy");
    }

    #[test]
    fn a_remote_split_by_a_yubikey_touch_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (one, _key) = store(tmp.path());
        crate::store::write_private(&remote_path(&one), b"/icloud/.ccdbkdtdu\npassbox\n").unwrap();
        assert!(configured(&one).is_err());
        assert!(default_destination(&one).is_err());

        // and the same touch inside the config fails the parse
        fs::write(
            config_path(&one),
            "[sync]\nengine = \"icloud\"\ndirectory = \".ccdbkdtdu\npassbox\"\n",
        )
        .unwrap();
        assert!(configured(&one).is_err());
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
    fn rm_then_add_of_one_name_survives_the_sync() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();

        let (one, key) = store(a.path());
        let id = new_id();
        let recipient = one.recipient().unwrap();
        one.put(&id, &secret("db/token", "old"), &recipient)
            .unwrap();
        sync(&one, remote.path()).unwrap();
        let two = Store {
            dir: b.path().to_path_buf(),
        };
        sync(&two, remote.path()).unwrap();

        one.delete(&id).unwrap();
        sync(&one, remote.path()).unwrap();
        // add reuses the id of a deleted name, as `passbox add` does
        std::thread::sleep(std::time::Duration::from_millis(1100));
        one.put(&id, &secret("db/token", "new"), &recipient)
            .unwrap();
        sync(&one, remote.path()).unwrap();
        sync(&one, remote.path()).unwrap();
        assert_eq!(one.names(&key).unwrap(), vec!["db/token"]);
        assert_eq!(one.load(&id, &key).unwrap().value, "new");
        assert!(!remote.path().join(format!("store/{id}.tomb")).exists());
        assert!(
            !one.versions(&id).unwrap().is_empty(),
            "the old value stays restorable"
        );

        // The other machine still holds the tombstone it pulled, and the new value outlives it
        sync(&two, remote.path()).unwrap();
        sync(&two, remote.path()).unwrap();
        assert_eq!(two.names(&key).unwrap(), vec!["db/token"]);
        assert_eq!(two.load(&id, &key).unwrap().value, "new");
        sync(&one, remote.path()).unwrap();
        assert_eq!(one.names(&key).unwrap(), vec!["db/token"]);
    }

    /* A repo in the store used to be copied into the mirror, which swamped the sync and left
    the secrets behind. The remote is a mirror, not a clone. */
    #[test]
    fn a_repo_is_not_copied_to_the_mirror() {
        assert!(skip(Path::new(".git")));
        assert!(skip(Path::new(".git/config")));
        assert!(skip(Path::new(".git/objects/ab/cdef")));
        assert!(skip(Path::new(".gitignore")));
        assert!(skip(Path::new("store/0a1b.age.partial")));
        assert!(!skip(Path::new("store/abc123.age")));
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
    fn a_socket_in_the_store_does_not_stop_the_copy() {
        let a = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let (one, key) = store(a.path());
        for name in ["a/b", "c/d"] {
            one.put(&new_id(), &secret(name, "v"), &one.recipient().unwrap())
                .unwrap();
        }
        // Both sort before `store/`, and the second is a name no skip rule knows
        let _agent = std::os::unix::net::UnixListener::bind(one.ssh_agent_path()).unwrap();
        let _stray = std::os::unix::net::UnixListener::bind(one.dir.join("future.sock")).unwrap();
        fs::write(one.ssh_keys_path(), "ssh-ed25519 AAAA laptop\n").unwrap();

        sync(&one, remote.path()).unwrap();
        assert!(!remote.path().join("ssh-agent.sock").exists());
        assert!(!remote.path().join("future.sock").exists());
        assert!(!remote.path().join("ssh-keys.pub").exists());
        let two = Store {
            dir: remote.path().to_path_buf(),
        };
        assert_eq!(two.names(&key).unwrap(), vec!["a/b", "c/d"]);
    }

    #[test]
    fn a_failed_copy_warns_and_the_rest_still_copy() {
        let a = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let (one, key) = store(a.path());
        let (blocked, other) = (new_id(), new_id());
        one.put(&blocked, &secret("a/b", "v"), &one.recipient().unwrap())
            .unwrap();
        one.put(&other, &secret("c/d", "v"), &one.recipient().unwrap())
            .unwrap();
        // A directory where the copy writes its partial file makes that one copy fail
        fs::create_dir_all(remote.path().join(format!("store/{blocked}.age.partial"))).unwrap();

        let err = sync(&one, remote.path()).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.starts_with("could not sync 1 file to "), "{text}");
        assert!(text.contains(&format!("store/{blocked}.age")), "{text}");
        assert!(!remote.path().join(format!("store/{blocked}.age")).exists());
        let two = Store {
            dir: remote.path().to_path_buf(),
        };
        assert_eq!(two.names(&key).unwrap(), vec!["c/d"]);
    }

    #[test]
    fn an_unwritable_destination_fails_once_with_a_summary() {
        use std::os::unix::fs::PermissionsExt;
        let a = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let (one, _key) = store(a.path());
        one.put(&new_id(), &secret("a/b", "v"), &one.recipient().unwrap())
            .unwrap();
        fs::set_permissions(remote.path(), fs::Permissions::from_mode(0o500)).unwrap();

        let result = sync(&one, remote.path());
        fs::set_permissions(remote.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let text = format!("{:#}", result.unwrap_err());
        assert!(text.starts_with("could not sync "), "{text}");
        assert!(text.contains("the copy there is incomplete"), "{text}");
        assert!(
            text.contains(&remote.path().display().to_string()),
            "{text}"
        );
        assert!(fs::read_dir(remote.path()).unwrap().next().is_none());
    }

    #[test]
    fn rclone_excludes_everything_the_directory_sync_skips() {
        let one = Store {
            dir: PathBuf::from("/tmp/store"),
        };
        let args = rclone_args(&one, "b2:passbox");
        for pattern in NEVER_SYNCED {
            assert!(
                args.windows(2)
                    .any(|w| w[0] == "--exclude" && w[1] == *pattern),
                "{pattern} is not excluded: {args:?}"
            );
        }
        for path in [
            "ssh-keys.pub",
            "plugins/x/manifest.toml",
            "store/.versions/ab/1.age",
            "store/ab.age.partial",
            "grants-mac.age",
            "windows-mac.json",
        ] {
            assert!(skip(Path::new(path)), "{path}");
        }
        assert!(args.iter().any(|a| a == "--ignore-case"), "{args:?}");
        assert!(!skip(Path::new("audit-mac.log")));
        assert!(!skip(Path::new("wraps/se-mac.json")));
    }

    /* Every file passbox keeps for this machine alone. The audit log and the Enclave wrap are per
    host too, but they carry the host in the name so every Mac's copy can travel without a clash. */
    #[test]
    fn every_machine_local_file_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let one = Store {
            dir: tmp.path().to_path_buf(),
        };
        for path in [
            one.socket_path(),
            one.ssh_agent_path(),
            one.ssh_keys_path(),
            one.host_path(),
            one.plugins_dir(),
            one.dir.join("names"),
            one.dir.join(".git"),
            one.dir.join(".gitignore"),
            remote_path(&one),
            config_path(&one),
            crate::project::path(&one),
            crate::plugin::approval_path(&one),
        ] {
            let relative = path.strip_prefix(&one.dir).unwrap();
            assert!(skip(relative), "{} would sync", relative.display());
        }
    }

    #[test]
    fn the_skip_ignores_case_as_macos_does() {
        assert!(skip(Path::new("Grants-M4.age")));
        assert!(skip(Path::new("BROKER.SOCK")));
        assert!(skip(Path::new("Store/.Versions/ab/1.age")));
        assert!(!skip(Path::new("Store/ab.age")));
    }

    #[test]
    fn the_old_remote_file_warning_names_v3() {
        let tmp = tempfile::tempdir().unwrap();
        let one = Store {
            dir: tmp.path().to_path_buf(),
        };
        assert!(legacy_warning(&one).contains("stops being read in v3"));
    }

    #[test]
    fn an_rclone_remote_is_not_treated_as_a_directory() {
        let a = tempfile::tempdir().unwrap();
        let (one, _key) = store(a.path());
        assert!(sync(&one, Path::new("b2:passbox")).is_err());
    }
}
