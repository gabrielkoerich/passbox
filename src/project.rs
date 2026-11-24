/* A project declares which secrets it needs in `.passbox.toml`. The file is a request, never a
grant: an agent can write one itself, so approving it takes a fingerprint. The approval is bound
to the file's hash, so adding a secret to the manifest invalidates it and asks again.

Grants are machine local and never sync. A grant that travelled would let a machine you have not
touched inherit approvals you gave on this one. */

use crate::crypto;
use crate::store::{self, Store};
use age::x25519;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/* A ceiling on how long one approval can carry. Without it a caller names its own expiry and
a token becomes a password that never lapses, which is the thing this exists to avoid. */
pub(crate) const MAX_GRANT_SECS: u64 = 86_400;

pub(crate) const MANIFEST: &str = ".passbox.toml";
const DEFAULT_GRANT_SECS: u64 = 3600;
const MAX_PROJECT_SECS: u64 = 12 * 3600;

#[derive(Deserialize, Default)]
struct ManifestFile {
    #[serde(default)]
    secrets: Vec<String>,
    window_secs: Option<u64>,
}

pub(crate) struct Manifest {
    pub dir: PathBuf,
    pub secrets: Vec<String>,
    pub window_secs: u64,
    pub hash: String,
}

/// Walk up from `from`, so running in a subdirectory of the project still finds it
pub(crate) fn find(from: &Path) -> Option<Manifest> {
    let mut dir = from;
    loop {
        let candidate = dir.join(MANIFEST);
        if candidate.is_file() {
            return read(&candidate).ok();
        }
        dir = dir.parent()?;
    }
}

fn read(path: &Path) -> Result<Manifest> {
    let raw = std::fs::read(path)?;
    let parsed: ManifestFile =
        toml::from_str(&String::from_utf8_lossy(&raw)).context("bad .passbox.toml")?;

    Ok(Manifest {
        dir: path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        secrets: parsed.secrets,
        window_secs: parsed
            .window_secs
            .unwrap_or(DEFAULT_GRANT_SECS)
            .min(MAX_PROJECT_SECS),
        hash: hash(&raw),
    })
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Grant {
    pub dir: String,
    pub hash: String,
    pub secrets: Vec<String>,
    pub until: u64,
}

impl Grant {
    /// A grant covers a secret only while the manifest it was approved for is unchanged
    pub(crate) fn covers(&self, manifest: &Manifest, secret: &str, now: u64) -> bool {
        self.until > now
            && self.hash == manifest.hash
            && self.dir == manifest.dir.to_string_lossy()
            && self.secrets.iter().any(|s| s == secret)
    }
}

pub(crate) fn path(store: &Store) -> PathBuf {
    store.dir.join(format!("grants-{}.age", store::hostname()))
}

pub(crate) fn load(store: &Store, key: &x25519::Identity) -> Vec<Grant> {
    let Ok(raw) = std::fs::read(path(store)) else {
        return Vec::new();
    };
    let Ok(plain) = crypto::decrypt(&raw, &[Box::new(key.clone())]) else {
        return Vec::new();
    };
    let grants: Vec<Grant> = serde_json::from_slice(&plain).unwrap_or_default();

    // Dropping the expired ones on read keeps the file from growing without bound
    let now = store::now();
    grants.into_iter().filter(|g| g.until > now).collect()
}

/// Encrypting needs only the public recipient, so recording a grant costs no extra unlock
pub(crate) fn save(store: &Store, grants: &[Grant]) -> Result<()> {
    let recipient = store.recipient()?;
    let json = serde_json::to_vec(grants)?;
    let sealed = crypto::encrypt(&json, &[Box::new(recipient)])?;
    store::write_private(&path(store), &sealed)
}

/// Seconds as config.toml writes them, such as `24h` or `90s`
pub(crate) fn span(secs: u64) -> String {
    match secs {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// `90s`, `30m` or `24h`
pub(crate) fn duration(text: &str) -> Result<u64> {
    let refuse = || anyhow!("{text:?} is not a duration such as \"90s\", \"30m\" or \"24h\"");
    let unit = match text.chars().last() {
        Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        _ => return Err(refuse()),
    };
    let count: u64 = text[..text.len() - 1]
        .parse()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(refuse)?;
    Ok(count.saturating_mul(unit))
}

// Plain text like the section, so a MAC under the store key stops a process forging its own
#[derive(Serialize, Deserialize)]
pub(crate) struct Approval {
    pub hash: String,
    mac: String,
}

/// The domain keeps a record for one section from passing as a record for the other
fn mac(key: &x25519::Identity, domain: &str, hash: &str) -> String {
    use age::secrecy::ExposeSecret;
    let mut digest = Sha256::new();
    digest.update(format!("passbox {domain} windows\n").as_bytes());
    digest.update(key.to_string().expose_secret().as_bytes());
    digest.update(b"\n");
    digest.update(hash.as_bytes());
    hex::encode(digest.finalize())
}

pub(crate) fn approved_at(path: &std::path::Path) -> Option<Approval> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub(crate) fn approve_at(
    path: &std::path::Path,
    domain: &str,
    key: &x25519::Identity,
    hash: &str,
) -> Result<()> {
    let record = Approval {
        hash: hash.to_string(),
        mac: mac(key, domain, hash),
    };
    store::write_private(path, &serde_json::to_vec(&record)?)
}

impl Approval {
    pub(crate) fn verify(&self, key: &x25519::Identity) -> bool {
        self.verify_for("plugin", key)
    }

    pub(crate) fn verify_for(&self, domain: &str, key: &x25519::Identity) -> bool {
        self.mac == mac(key, domain, &self.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approval_record_verifies_only_under_the_key_that_made_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("windows.json");
        let key = x25519::Identity::generate();
        approve_at(&path, "plugin", &key, "h1").unwrap();
        let record = approved_at(&path).unwrap();
        assert_eq!(record.hash, "h1");
        assert!(record.verify(&key));
        assert!(!record.verify(&x25519::Identity::generate()));
        let forged = Approval {
            hash: "h2".into(),
            mac: record.mac,
        };
        assert!(!forged.verify(&key));
    }

    fn manifest(dir: &Path, body: &str) -> Manifest {
        std::fs::write(dir.join(MANIFEST), body).unwrap();
        find(dir).unwrap()
    }

    #[test]
    fn a_manifest_is_found_from_a_subdirectory() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("src/inner");
        std::fs::create_dir_all(&deep).unwrap();
        manifest(tmp.path(), "secrets = [\"a/b\"]\n");

        let found = find(&deep).unwrap();
        assert_eq!(found.secrets, vec!["a/b"]);
        assert_eq!(found.dir, tmp.path());
    }

    #[test]
    fn no_manifest_anywhere_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(find(tmp.path()).is_none());
    }

    #[test]
    fn a_grant_covers_only_what_the_manifest_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(tmp.path(), "secrets = [\"a/b\"]\n");
        let grant = Grant {
            dir: m.dir.to_string_lossy().to_string(),
            hash: m.hash.clone(),
            secrets: m.secrets.clone(),
            until: 1000,
        };

        assert!(grant.covers(&m, "a/b", 999));
        assert!(!grant.covers(&m, "other/secret", 999));
    }

    #[test]
    fn a_grant_expires() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(tmp.path(), "secrets = [\"a/b\"]\n");
        let grant = Grant {
            dir: m.dir.to_string_lossy().to_string(),
            hash: m.hash.clone(),
            secrets: m.secrets.clone(),
            until: 1000,
        };
        assert!(!grant.covers(&m, "a/b", 1000));
        assert!(!grant.covers(&m, "a/b", 1001));
    }

    /// The property the whole design rests on: editing the file cannot widen what it opens
    #[test]
    fn adding_a_secret_to_the_manifest_voids_the_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let before = manifest(tmp.path(), "secrets = [\"a/b\"]\n");
        let grant = Grant {
            dir: before.dir.to_string_lossy().to_string(),
            hash: before.hash.clone(),
            secrets: before.secrets.clone(),
            until: 9999,
        };
        assert!(grant.covers(&before, "a/b", 1));

        let after = manifest(tmp.path(), "secrets = [\"a/b\", \"stolen/key\"]\n");
        assert_ne!(before.hash, after.hash);
        assert!(!grant.covers(&after, "a/b", 1));
        assert!(!grant.covers(&after, "stolen/key", 1));
    }

    #[test]
    fn a_window_is_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let m = manifest(tmp.path(), "secrets = []\nwindow_secs = 999999\n");
        assert_eq!(m.window_secs, MAX_PROJECT_SECS);
    }

    /// A grant file that has been edited must read as no grants, never as a grant
    #[test]
    fn a_tampered_grant_file_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let key = store.init().unwrap();
        save(
            &store,
            &[Grant {
                dir: "/x".into(),
                hash: "h".into(),
                secrets: vec!["a".into()],
                until: store::now() + 600,
            }],
        )
        .unwrap();
        assert_eq!(load(&store, &key).len(), 1);

        let file = path(&store);
        let mut raw = std::fs::read(&file).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&file, &raw).unwrap();

        assert!(
            load(&store, &key).is_empty(),
            "a tampered grant was honoured"
        );
    }

    #[test]
    fn grants_survive_a_round_trip_and_expired_ones_are_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let key = store.init().unwrap();

        let live = Grant {
            dir: "/x".into(),
            hash: "h".into(),
            secrets: vec!["a".into()],
            until: store::now() + 600,
        };
        let dead = Grant {
            dir: "/y".into(),
            hash: "h".into(),
            secrets: vec!["b".into()],
            until: 1,
        };
        save(&store, &[live, dead]).unwrap();

        let back = load(&store, &key);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].dir, "/x");
    }
}
