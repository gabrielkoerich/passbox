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

    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
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
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("broker.sock")
    }
    pub fn audit_path(&self) -> PathBuf {
        self.dir.join(format!("audit-{}.log", hostname()))
    }

    pub fn is_initialised(&self) -> bool {
        self.recipient_path().exists()
    }

    /// Generate the store key and write both wraps. The recipient stays in the clear so
    /// writing a secret never needs an unlock.
    pub fn init(&self, passphrase: SecretString) -> Result<()> {
        if self.is_initialised() {
            bail!("{} is already initialised", self.dir.display());
        }
        private_dir(&self.dir)?;
        private_dir(&self.secrets_dir())?;
        private_dir(&self.versions_dir())?;
        private_dir(&self.wraps_dir())?;

        let key = x25519::Identity::generate();
        let recipient = key.to_public();

        let wrapped = crypto::encrypt(
            secrecy::ExposeSecret::expose_secret(&key.to_string()).as_bytes(),
            &[Box::new(age::scrypt::Recipient::new(passphrase))],
        )?;
        write_private(&self.recovery_path(), &wrapped)?;
        write_private(&self.recipient_path(), recipient.to_string().as_bytes())?;
        Ok(())
    }

    pub fn recipient(&self) -> Result<x25519::Recipient> {
        let raw = fs::read_to_string(self.recipient_path())
            .with_context(|| format!("no store at {}, run `passbox init`", self.dir.display()))?;
        x25519::Recipient::from_str(raw.trim()).map_err(|e| anyhow!("bad recipient file: {e}"))
    }

    pub fn unlock_with_passphrase(&self, passphrase: SecretString) -> Result<x25519::Identity> {
        let wrapped = fs::read(self.recovery_path()).context("no recovery wrap")?;
        let mut raw = crypto::decrypt(&wrapped, &[Box::new(age::scrypt::Identity::new(passphrase))])
            .context("wrong passphrase")?;
        let text = String::from_utf8(raw.clone()).context("recovery wrap is not a key")?;
        raw.zeroize();
        x25519::Identity::from_str(text.trim()).map_err(|e| anyhow!("bad store key: {e}"))
    }

    /// Ids with a secret file and no tombstone.
    pub fn ids(&self) -> Result<Vec<String>> {
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
            let id = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            if self.tomb_path(&id).exists() {
                continue;
            }
            out.push(id);
        }
        out.sort();
        Ok(out)
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
        secret.map_err(Into::into)
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

    fn store() -> (tempfile::TempDir, Store, x25519::Identity) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::at(tmp.path());
        let pass = SecretString::from("hunter2".to_string());
        store.init(pass.clone()).unwrap();
        let key = store.unlock_with_passphrase(pass).unwrap();
        (tmp, store, key)
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
    fn round_trip_by_name() {
        let (_tmp, store, key) = store();
        let r = store.recipient().unwrap();
        store.put(&new_id(), &secret("github/token", "ghp_abc"), &r).unwrap();

        let (_id, found) = store.find("github/token", &key).unwrap().unwrap();
        assert_eq!(found.value, "ghp_abc");
        assert!(store.find("missing", &key).unwrap().is_none());
    }

    #[test]
    fn filename_never_holds_the_name() {
        let (_tmp, store, _key) = store();
        let r = store.recipient().unwrap();
        store.put(&new_id(), &secret("github/token", "ghp_abc"), &r).unwrap();

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

    #[test]
    fn init_refuses_twice() {
        let (_tmp, store, _key) = store();
        assert!(store.init(SecretString::from("x".to_string())).is_err());
    }
}
