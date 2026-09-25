//! One age file per secret. The filename is a random id, the name lives inside the ciphertext.

use crate::crypto;
use age::x25519;
use anyhow::{Context, Result, anyhow, bail};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const DEFAULT_WINDOW_SECS: u64 = 300;
const KEEP_VERSIONS: usize = 5;
pub const TOMB_TTL_SECS: u64 = 90 * 24 * 60 * 60;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// No prompt, for a token an agent reads all day
    Open,
    /// One prompt per agent and secret per window
    Window,
    /// A prompt on every read
    Always,
    /// Never released to an agent, interactive `get` only
    Never,
}

impl FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Mode::Open),
            "window" => Ok(Mode::Window),
            "always" => Ok(Mode::Always),
            "never" => Ok(Mode::Never),
            other => bail!("unknown mode {other}, expected open, window, always or never"),
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Mode::Open => "open",
            Mode::Window => "window",
            Mode::Always => "always",
            Mode::Never => "never",
        };
        f.write_str(s)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub mode: Mode,
    pub window_secs: u64,
    /* How long the broker may keep THIS value after one approval. A window still asks for a
    fingerprint when it lapses, which no unattended job can answer. A lease holds the one value
    instead of the store key, so the job keeps running and the approval it got extends to that
    secret alone. Zero, the default, means no lease. */
    #[serde(default)]
    pub lease_secs: u64,
    pub value: String,
    pub created: u64,
    pub updated: u64,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn new_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn open() -> Result<Self> {
        let dir = match std::env::var_os("PASSBOX_DIR") {
            Some(d) => PathBuf::from(d),
            None => home()?.join(".passbox"),
        };
        Ok(Store { dir })
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.dir.join("store")
    }
    pub fn versions_dir(&self) -> PathBuf {
        self.secrets_dir().join(".versions")
    }
    pub fn wraps_dir(&self) -> PathBuf {
        self.dir.join("wraps")
    }
    fn recipient_path(&self) -> PathBuf {
        self.wraps_dir().join("recipient")
    }
    fn recovery_path(&self) -> PathBuf {
        self.wraps_dir().join("recovery.age")
    }
    /// Opened by the token rather than by a passphrase, so the file is inert on its own
    pub fn yubikey_wrap_path(&self) -> PathBuf {
        self.wraps_dir().join("yubikey.age")
    }
    pub fn has_yubikey_wrap(&self) -> bool {
        self.yubikey_wrap_path().exists()
    }

    /// One wrap per machine, because a Secure Enclave key cannot leave the Mac that made it
    pub fn se_wrap_path(&self) -> PathBuf {
        self.wraps_dir().join(format!("se-{}.json", hostname()))
    }
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("broker.sock")
    }
    /// Per machine, so two Macs never append to the same file through a syncer
    pub fn audit_path(&self) -> PathBuf {
        self.dir.join(format!("audit-{}.log", hostname()))
    }
    pub fn is_initialised(&self) -> bool {
        self.recipient_path().exists()
    }
    pub fn has_se_wrap(&self) -> bool {
        self.se_wrap_path().exists()
    }

    /// Generate the store key and write no wrap. The recipient stays in the clear so writing a
    /// secret never needs an unlock. The caller decides which wraps to add.
    pub fn init(&self) -> Result<x25519::Identity> {
        if self.is_initialised() {
            bail!("{} is already initialised", self.dir.display());
        }
        private_dir(&self.dir)?;
        private_dir(&self.secrets_dir())?;
        private_dir(&self.versions_dir())?;
        private_dir(&self.wraps_dir())?;

        let key = x25519::Identity::generate();
        write_private(
            &self.recipient_path(),
            key.to_public().to_string().as_bytes(),
        )?;
        Ok(key)
    }

    pub fn has_recovery_wrap(&self) -> bool {
        self.recovery_path().exists()
    }

    /// A wrap that opens the store away from this Mac. Sync is worth nothing without one.
    pub fn has_portable_wrap(&self) -> bool {
        self.has_recovery_wrap() || self.has_yubikey_wrap()
    }

    /* The passphrase wrap is the only thing that opens the store away from this Mac, which makes
    it both what syncing needs and the one file worth attacking in a synced copy. It is written
    when the user asks for sync, never before. */
    pub fn create_recovery_wrap(
        &self,
        key: &x25519::Identity,
        passphrase: SecretString,
    ) -> Result<()> {
        self.create_recovery_wrap_with_factor(key, passphrase, None)
    }

    /* The age crate calibrates scrypt to about a second of work on this machine, which is the
    right default and the wrong thing to pay sixty times over in a test suite. `log_n` lowers it,
    and only a debug build will read the environment variable that asks for that. */
    pub fn create_recovery_wrap_with_factor(
        &self,
        key: &x25519::Identity,
        passphrase: SecretString,
        log_n: Option<u8>,
    ) -> Result<()> {
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        if let Some(log_n) = log_n {
            recipient.set_work_factor(log_n);
        }
        self.write_recovery_wrap(key, recipient, &self.recovery_path())
    }

    /// The same wrap written wherever the caller wants it, for a backup that never syncs
    pub fn export_recovery_wrap(
        &self,
        key: &x25519::Identity,
        passphrase: SecretString,
        to: &Path,
        log_n: Option<u8>,
    ) -> Result<()> {
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        if let Some(log_n) = log_n {
            recipient.set_work_factor(log_n);
        }
        self.write_recovery_wrap(key, recipient, to)
    }

    fn write_recovery_wrap(
        &self,
        key: &x25519::Identity,
        recipient: age::scrypt::Recipient,
        to: &Path,
    ) -> Result<()> {
        let mut text = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let wrapped = crypto::encrypt(text.as_bytes(), &[Box::new(recipient)])?;
        text.zeroize();
        write_private(to, &wrapped)
    }

    /// Recipients are public, so they sit in the clear beside the wrap they opened
    pub fn yubikey_recipients_path(&self) -> PathBuf {
        self.wraps_dir().join("yubikey.recipients")
    }

    pub fn yubikey_recipients(&self) -> Vec<String> {
        fs::read_to_string(self.yubikey_recipients_path())
            .map(|raw| {
                raw.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /* age takes any number of recipients, so a second token is added to the same wrap rather
    than replacing it. Adding one re-encrypts to every recipient, which is why it needs the key. */
    #[cfg(feature = "host")]
    pub fn add_yubikey_recipient(&self, key: &x25519::Identity, recipient: &str) -> Result<usize> {
        let mut all = self.yubikey_recipients();
        let recipient = recipient.trim().to_string();
        if !all.contains(&recipient) {
            all.push(recipient);
        }

        let mut to = Vec::new();
        for text in &all {
            to.push(crate::yubikey::recipient(text)?);
        }

        let mut plain = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let wrapped = crypto::encrypt(plain.as_bytes(), &to)?;
        plain.zeroize();

        write_private(&self.yubikey_wrap_path(), &wrapped)?;
        write_private(&self.yubikey_recipients_path(), all.join("\n").as_bytes())?;
        Ok(all.len())
    }

    /// The token prompts for a touch itself, so passbox raises nothing here
    #[cfg(feature = "host")]
    pub fn unlock_with_yubikey(&self) -> Result<x25519::Identity> {
        let wrapped = fs::read(self.yubikey_wrap_path()).context("no YubiKey wrap")?;
        let mut raw = crypto::decrypt(&wrapped, &[crate::yubikey::identity()?])
            .context("the YubiKey refused, or it is not the one this was wrapped to")?;
        let text = String::from_utf8(raw.clone()).context("the wrap is not a key")?;
        raw.zeroize();
        x25519::Identity::from_str(text.trim()).map_err(|e| anyhow!("bad store key: {e}"))
    }

    pub fn recipient(&self) -> Result<x25519::Recipient> {
        let raw = fs::read_to_string(self.recipient_path())
            .with_context(|| format!("no store at {}, run `passbox init`", self.dir.display()))?;
        x25519::Recipient::from_str(raw.trim()).map_err(|e| anyhow!("bad recipient file: {e}"))
    }

    pub fn unlock_with_passphrase(&self, passphrase: SecretString) -> Result<x25519::Identity> {
        let wrapped = fs::read(self.recovery_path()).context("no recovery wrap")?;
        let mut raw = crypto::decrypt(
            &wrapped,
            &[Box::new(age::scrypt::Identity::new(passphrase))],
        )
        .context("wrong passphrase")?;
        let text = String::from_utf8(raw.clone()).context("recovery wrap is not a key")?;
        raw.zeroize();
        x25519::Identity::from_str(text.trim()).map_err(|e| anyhow!("bad store key: {e}"))
    }

    /// Bind the store key to this Mac's Secure Enclave. Neither step raises a prompt.
    #[cfg(feature = "host")]
    pub fn create_se_wrap(&self, key: &x25519::Identity) -> Result<()> {
        let mut text = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let wrap = crate::se::wrap(text.as_bytes())?;
        text.zeroize();
        write_private(&self.se_wrap_path(), &serde_json::to_vec(&wrap)?)
    }

    /// Raise a Touch ID prompt worded by `reason`, then open the store key.
    #[cfg(feature = "host")]
    pub fn unlock_with_se(&self, reason: &str) -> Result<x25519::Identity> {
        let raw =
            fs::read(self.se_wrap_path()).context("no Secure Enclave wrap on this machine")?;
        let wrap: crate::se::SeWrap = serde_json::from_slice(&raw)?;
        let mut plain = crate::se::unwrap(&wrap, reason)?;
        let text = String::from_utf8(plain.clone()).context("the wrap is not a key")?;
        plain.zeroize();
        x25519::Identity::from_str(text.trim()).map_err(|e| anyhow!("bad store key: {e}"))
    }

    /// Ids with a secret file and no tombstone.
    pub fn ids(&self) -> Result<Vec<String>> {
        let mut out = self.ids_with_files()?;
        out.retain(|id| !self.tomb_path(id).exists());
        Ok(out)
    }

    /// Every id that still has a file, tombstoned or not. A delete that arrived through a
    /// sync leaves the file in place, so undeleting it is a matter of dropping the tombstone.
    pub fn ids_with_files(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("age") {
                continue;
            }
            if let Some(id) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(id.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn untomb(&self, id: &str) -> Result<()> {
        let tomb = self.tomb_path(id);
        if tomb.exists() {
            fs::remove_file(tomb)?;
        }
        Ok(())
    }

    pub fn secret_path(&self, id: &str) -> PathBuf {
        self.secrets_dir().join(format!("{id}.age"))
    }
    pub fn tomb_path(&self, id: &str) -> PathBuf {
        self.secrets_dir().join(format!("{id}.tomb"))
    }

    pub fn load(&self, id: &str, key: &x25519::Identity) -> Result<Secret> {
        self.load_path(&self.secret_path(id), key)
    }

    pub fn load_path(&self, path: &Path, key: &x25519::Identity) -> Result<Secret> {
        let raw = fs::read(path)?;
        let mut plain = crypto::decrypt(&raw, &[Box::new(key.clone())])?;
        let secret = serde_json::from_slice(&plain).context("secret file is not valid json");
        plain.zeroize();
        secret
    }

    pub fn find(&self, name: &str, key: &x25519::Identity) -> Result<Option<(String, Secret)>> {
        for id in self.ids()? {
            let secret = self.load(&id, key)?;
            if secret.name == name {
                return Ok(Some((id, secret)));
            }
        }
        Ok(None)
    }

    /* A plaintext list of names, so listing does not need the store key.

    Listing used to unlock the store, which is the largest privilege there is for the smallest
    question, and left the key warm in the broker afterwards. The cost is that this one file
    names what you hold. It never leaves the machine: sync skips it and a store that is a git
    repo ignores it, so a copy elsewhere still says nothing. */
    pub fn index_path(&self) -> PathBuf {
        self.dir.join("names")
    }

    pub fn index_read(&self) -> Option<Vec<String>> {
        let text = fs::read_to_string(self.index_path()).ok()?;
        let names: Vec<String> = text
            .lines()
            .map(str::to_string)
            .filter(|l| !l.is_empty())
            .collect();
        (!names.is_empty()).then_some(names)
    }

    pub fn index_write(&self, names: &[String]) -> Result<()> {
        let mut all = names.to_vec();
        all.sort();
        all.dedup();
        write_private(&self.index_path(), all.join("\n").as_bytes())
    }

    fn index_edit(&self, f: impl FnOnce(&mut Vec<String>)) -> Result<()> {
        // No index yet means nothing to keep in step, and `ls` will build one when it is asked
        let Some(mut names) = self.index_read() else {
            return Ok(());
        };
        f(&mut names);
        self.index_write(&names)
    }

    pub fn index_add(&self, name: &str) -> Result<()> {
        self.index_edit(|names| names.push(name.to_string()))
    }

    pub fn index_remove(&self, name: &str) -> Result<()> {
        self.index_edit(|names| names.retain(|n| n != name))
    }

    /// A sync can bring names this machine has never seen, so the next `ls` rebuilds
    pub fn index_clear(&self) -> Result<()> {
        match fs::remove_file(self.index_path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    pub fn names(&self, key: &x25519::Identity) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for id in self.ids()? {
            out.push(self.load(&id, key)?.name.clone());
        }
        out.sort();
        Ok(out)
    }

    /// Encrypt and write, keeping the previous file as a version.
    pub fn put(&self, id: &str, secret: &Secret, recipient: &x25519::Recipient) -> Result<()> {
        private_dir(&self.secrets_dir())?;
        let json = serde_json::to_vec(secret)?;
        let ct = crypto::encrypt(&json, &[Box::new(recipient.clone())])?;
        self.keep_version(id)?;
        write_private(&self.secret_path(id), &ct)?;
        let tomb = self.tomb_path(id);
        if tomb.exists() {
            fs::remove_file(tomb)?;
        }
        self.index_add(&secret.name)?;
        Ok(())
    }

    /// Move the current file into `.versions`, trimming to the newest KEEP_VERSIONS.
    pub fn keep_version(&self, id: &str) -> Result<()> {
        let current = self.secret_path(id);
        if !current.exists() {
            return Ok(());
        }
        let dir = self.versions_dir().join(id);
        private_dir(&dir)?;
        let mut stamp = now();
        while dir.join(format!("{stamp}.age")).exists() {
            stamp += 1;
        }
        fs::rename(&current, dir.join(format!("{stamp}.age")))?;

        let mut kept = self.versions(id)?;
        while kept.len() > KEEP_VERSIONS {
            let (_, oldest) = kept.remove(0);
            fs::remove_file(oldest)?;
        }
        Ok(())
    }

    /// Versions for an id, oldest first.
    pub fn versions(&self, id: &str) -> Result<Vec<(u64, PathBuf)>> {
        let dir = self.versions_dir().join(id);
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let stamp = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok());
            if let Some(stamp) = stamp {
                out.push((stamp, path));
            }
        }
        out.sort_by_key(|(stamp, _)| *stamp);
        Ok(out)
    }

    /// Version the current file, then leave a tombstone so the delete survives a sync.
    pub fn delete(&self, id: &str) -> Result<()> {
        self.keep_version(id)?;
        write_private(&self.tomb_path(id), now().to_string().as_bytes())
    }

    /// Drop tombstones older than the TTL, along with the versions they guard.
    pub fn prune_tombs(&self) -> Result<usize> {
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let mut pruned = 0;
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("tomb") {
                continue;
            }
            let stamp = fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0);
            if now().saturating_sub(stamp) < TOMB_TTL_SECS {
                continue;
            }
            if let Some(id) = path.file_stem().and_then(|s| s.to_str()) {
                let versions = self.versions_dir().join(id);
                if versions.exists() {
                    fs::remove_dir_all(versions)?;
                }
            }
            fs::remove_file(&path)?;
            pruned += 1;
        }
        Ok(pruned)
    }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

pub fn hostname() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Write through a temporary file so a crash cannot leave a half written secret.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /* The index exists so listing does not unlock the store. These pin the two halves of that:
    it answers without a key, and it stays true as the store changes. */
    #[test]
    fn the_index_answers_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            dir: dir.path().to_path_buf(),
        };
        store
            .index_write(&["b/two".to_string(), "a/one".to_string()])
            .unwrap();
        assert_eq!(
            store.index_read().unwrap(),
            vec!["a/one".to_string(), "b/two".to_string()]
        );
    }

    #[test]
    fn a_removed_name_leaves_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            dir: dir.path().to_path_buf(),
        };
        store
            .index_write(&["a/one".to_string(), "b/two".to_string()])
            .unwrap();
        store.index_remove("a/one").unwrap();
        assert_eq!(store.index_read().unwrap(), vec!["b/two".to_string()]);
    }

    #[test]
    fn a_pull_invalidates_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            dir: dir.path().to_path_buf(),
        };
        store.index_write(&["a/one".to_string()]).unwrap();
        store.index_clear().unwrap();
        assert!(store.index_read().is_none());
        store.index_clear().unwrap(); // clearing twice is not an error
    }

    fn store() -> (tempfile::TempDir, Store, x25519::Identity) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let pass = SecretString::from("hunter2".to_string());
        let key = store.init().unwrap();
        store
            .create_recovery_wrap_with_factor(&key, pass, Some(10))
            .unwrap();
        (tmp, store, key)
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
    fn round_trip_by_name() {
        let (_tmp, store, key) = store();
        let r = store.recipient().unwrap();
        store
            .put(&new_id(), &secret("github/token", "ghp_abc"), &r)
            .unwrap();

        let (_id, found) = store.find("github/token", &key).unwrap().unwrap();
        assert_eq!(found.value, "ghp_abc");
        assert!(store.find("missing", &key).unwrap().is_none());
    }

    #[test]
    fn filename_never_holds_the_name() {
        let (_tmp, store, _key) = store();
        let r = store.recipient().unwrap();
        store
            .put(&new_id(), &secret("github/token", "ghp_abc"), &r)
            .unwrap();

        for id in store.ids().unwrap() {
            assert!(!id.contains("github"));
            assert!(!id.contains("token"));
            let raw = fs::read(store.secret_path(&id)).unwrap();
            assert!(!String::from_utf8_lossy(&raw).contains("github"));
        }
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let (_tmp, store, _key) = store();
        let wrong = SecretString::from("hunter3".to_string());
        assert!(store.unlock_with_passphrase(wrong).is_err());
    }

    #[test]
    fn overwrite_keeps_a_version() {
        let (_tmp, store, key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "old"), &r).unwrap();
        store.put(&id, &secret("db", "new"), &r).unwrap();

        assert_eq!(store.load(&id, &key).unwrap().value, "new");
        assert_eq!(store.versions(&id).unwrap().len(), 1);
    }

    #[test]
    fn versions_are_trimmed() {
        let (_tmp, store, _key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        for i in 0..KEEP_VERSIONS + 4 {
            store.put(&id, &secret("db", &format!("v{i}")), &r).unwrap();
        }
        assert_eq!(store.versions(&id).unwrap().len(), KEEP_VERSIONS);
    }

    #[test]
    fn delete_leaves_a_tombstone_and_hides_the_id() {
        let (_tmp, store, _key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "v"), &r).unwrap();
        store.delete(&id).unwrap();

        assert!(store.ids().unwrap().is_empty());
        assert!(store.tomb_path(&id).exists());
        assert_eq!(store.versions(&id).unwrap().len(), 1);
    }

    #[test]
    fn writing_again_clears_the_tombstone() {
        let (_tmp, store, key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "v"), &r).unwrap();
        store.delete(&id).unwrap();
        store.put(&id, &secret("db", "back"), &r).unwrap();

        assert_eq!(store.ids().unwrap().len(), 1);
        assert_eq!(store.load(&id, &key).unwrap().value, "back");
    }

    #[test]
    fn fresh_tombstones_survive_pruning() {
        let (_tmp, store, _key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "v"), &r).unwrap();
        store.delete(&id).unwrap();

        assert_eq!(store.prune_tombs().unwrap(), 0);
        write_private(&store.tomb_path(&id), b"1").unwrap();
        assert_eq!(store.prune_tombs().unwrap(), 1);
        assert!(!store.versions_dir().join(&id).exists());
    }

    /* The reference `age` CLI is a separate implementation in another language. If it can open
    what we wrote, the files are standard age files rather than something only this crate reads,
    and the store stays recoverable with off the shelf tools if passbox ever goes away. */
    #[test]
    fn a_secret_file_opens_with_the_reference_age_cli() {
        let Ok(age_cli) = which("age") else {
            eprintln!("skipped, the age CLI is not installed");
            return;
        };
        let (tmp, store, key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "swordfish"), &r).unwrap();

        let identity = tmp.path().join("identity.txt");
        fs::write(
            &identity,
            secrecy::ExposeSecret::expose_secret(&key.to_string()),
        )
        .unwrap();

        let out = std::process::Command::new(age_cli)
            .arg("--decrypt")
            .arg("-i")
            .arg(&identity)
            .arg(store.secret_path(&id))
            .output()
            .unwrap();

        assert!(
            out.status.success(),
            "age refused our file: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let plain = String::from_utf8_lossy(&out.stdout);
        assert!(plain.contains("swordfish"), "{plain}");
        assert!(plain.contains("\"name\":\"db\""), "{plain}");
    }

    fn which(tool: &str) -> Result<PathBuf> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .output()?;
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            bail!("{tool} not found");
        }
        Ok(PathBuf::from(path))
    }

    #[test]
    fn a_tampered_audit_line_is_refused() {
        let (_tmp, store, key) = store();
        let line = crypto::encrypt_line(b"{\"at\":1}", &store.recipient().unwrap()).unwrap();

        assert!(crypto::decrypt_line(&line, &key).is_ok());

        let mut bytes = line.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(crypto::decrypt_line(&tampered, &key).is_err());
    }

    /// A flipped byte must fail rather than hand back something that looks like a secret
    #[test]
    fn a_tampered_secret_file_is_refused() {
        let (_tmp, store, key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "swordfish"), &r).unwrap();

        let path = store.secret_path(&id);
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let opened = store.load(&id, &key);
        assert!(opened.is_err(), "a tampered file decrypted");
    }

    #[test]
    fn a_truncated_secret_file_is_refused() {
        let (_tmp, store, key) = store();
        let r = store.recipient().unwrap();
        let id = new_id();
        store.put(&id, &secret("db", "swordfish"), &r).unwrap();

        let path = store.secret_path(&id);
        let raw = fs::read(&path).unwrap();
        fs::write(&path, &raw[..raw.len() / 2]).unwrap();

        assert!(store.load(&id, &key).is_err());
    }

    #[test]
    fn a_tampered_recovery_wrap_is_refused() {
        let (_tmp, store, _key) = store();
        let path = store.wraps_dir().join("recovery.age");
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        let pass = SecretString::from("hunter2".to_string());
        assert!(store.unlock_with_passphrase(pass).is_err());
    }

    #[test]
    fn yubikey_recipients_accumulate_on_disk() {
        let (_tmp, store, _key) = store();
        assert!(store.yubikey_recipients().is_empty());

        write_private(
            &store.yubikey_recipients_path(),
            b"age1yubikey1aaa\nage1yubikey1bbb\n",
        )
        .unwrap();
        assert_eq!(
            store.yubikey_recipients(),
            vec!["age1yubikey1aaa", "age1yubikey1bbb"]
        );
    }

    #[test]
    fn a_yubikey_wrap_counts_as_a_way_off_this_mac() {
        let (_tmp, store, _key) = store();
        assert!(
            store.has_portable_wrap(),
            "the test store has a passphrase wrap"
        );

        fs::remove_file(store.wraps_dir().join("recovery.age")).unwrap();
        assert!(!store.has_portable_wrap());

        write_private(&store.yubikey_wrap_path(), b"x").unwrap();
        assert!(store.has_portable_wrap());
    }

    #[test]
    fn init_refuses_twice() {
        let (_tmp, store, _key) = store();
        assert!(store.init().is_err());
    }
}
