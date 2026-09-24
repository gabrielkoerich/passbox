/* A project declares which secrets it needs in `.passbox.toml`. The file is a request, never a
grant: an agent can write one itself, so approving it takes a fingerprint. The approval is bound
to the file's hash, so adding a secret to the manifest invalidates it and asks again.

Grants are machine local and never sync. A grant that travelled would let a machine you have not
touched inherit approvals you gave on this one. */

use crate::crypto;
use crate::store::{self, Store};
use age::x25519;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = ".passbox.toml";
const DEFAULT_GRANT_SECS: u64 = 3600;
const MAX_GRANT_SECS: u64 = 12 * 3600;

#[derive(Deserialize, Default)]
struct ManifestFile {
    #[serde(default)]
    secrets: Vec<String>,
    window_secs: Option<u64>,
}

pub struct Manifest {
    pub dir: PathBuf,
    pub secrets: Vec<String>,
    pub window_secs: u64,
    pub hash: String,
}

/// Walk up from `from`, so running in a subdirectory of the project still finds it
pub fn find(from: &Path) -> Option<Manifest> {
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
            .min(MAX_GRANT_SECS),
        hash: hash(&raw),
    })
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Grant {
    pub dir: String,
    pub hash: String,
    pub secrets: Vec<String>,
    pub until: u64,
}

impl Grant {
    /// A grant covers a secret only while the manifest it was approved for is unchanged
    pub fn covers(&self, manifest: &Manifest, secret: &str, now: u64) -> bool {
        self.until > now
            && self.hash == manifest.hash
            && self.dir == manifest.dir.to_string_lossy()
            && self.secrets.iter().any(|s| s == secret)
    }
}

fn path(store: &Store) -> PathBuf {
    store.dir.join(format!("grants-{}.age", store::hostname()))
}

pub fn load(store: &Store, key: &x25519::Identity) -> Vec<Grant> {
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
pub fn save(store: &Store, grants: &[Grant]) -> Result<()> {
    let recipient = store.recipient()?;
    let json = serde_json::to_vec(grants)?;
    let sealed = crypto::encrypt(&json, &[Box::new(recipient)])?;
    store::write_private(&path(store), &sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(m.window_secs, MAX_GRANT_SECS);
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
