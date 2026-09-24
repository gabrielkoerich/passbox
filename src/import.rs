//! Bring entries across from `pass`, decrypting through GPG and re-encrypting to the store key.

use crate::store::{DEFAULT_WINDOW_SECS, Mode, Secret, Store, new_id, now};
use age::x25519;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub fn store_dir() -> PathBuf {
    if let Some(set) = std::env::var_os("PASSWORD_STORE_DIR") {
        return PathBuf::from(set);
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".password-store"))
        .unwrap_or_default()
}

/// Entry names are paths under the store with the `.gpg` taken off, which is how pass names them
pub fn entries(dir: &Path) -> Result<Vec<String>> {
    let mut found = Vec::new();
    walk(dir, dir, &mut found)?;
    found.sort();
    Ok(found)
}

fn walk(root: &Path, at: &Path, out: &mut Vec<String>) -> Result<()> {
    if !at.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(at)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            walk(root, &path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("gpg")
            && let Ok(relative) = path.strip_prefix(root)
        {
            out.push(relative.with_extension("").to_string_lossy().to_string());
        }
    }
    Ok(())
}

/// No prefix takes everything. A prefix takes that entry, or the namespace under it.
pub fn select(all: &[String], prefix: Option<&str>) -> Vec<String> {
    let Some(prefix) = prefix else {
        return all.to_vec();
    };
    let namespace = format!("{}/", prefix.trim_end_matches('/'));
    all.iter()
        .filter(|name| *name == prefix || name.starts_with(&namespace))
        .cloned()
        .collect()
}

/* The whole body is kept, not just the first line. pass entries commonly carry `key: value` lines
under the password, and bean's `get_fields` reads them, so trimming to line one would lose data. */
fn show(entry: &str) -> Result<String> {
    let out = std::process::Command::new("pass")
        .arg("show")
        .arg(entry)
        .output()
        .context("pass is not on PATH")?;

    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let body = String::from_utf8(out.stdout).context("entry is not text")?;
    Ok(body.trim_end_matches('\n').to_string())
}

pub struct Report {
    pub imported: usize,
    pub skipped: usize,
}

pub fn import(
    store: &Store,
    names: &[String],
    key: Option<&x25519::Identity>,
    mode: Mode,
    force: bool,
) -> Result<Report> {
    let recipient = store.recipient()?;
    let mut report = Report {
        imported: 0,
        skipped: 0,
    };

    for name in names {
        let existing = match key {
            Some(key) => store.find(name, key)?.map(|(id, _)| id),
            None => None,
        };
        if existing.is_some() && !force {
            eprintln!("skipping {name}, already in the store");
            report.skipped += 1;
            continue;
        }

        let mut value = show(name)?;
        let secret = Secret {
            name: name.clone(),
            mode,
            window_secs: DEFAULT_WINDOW_SECS,
            value: value.clone(),
            created: now(),
            updated: now(),
        };
        value.zeroize();

        store.put(&existing.unwrap_or_else(new_id), &secret, &recipient)?;
        report.imported += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn entry_names_mirror_the_pass_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("fred-api-key.gpg"));
        touch(&root.join("bean/hl-mainnet-pk.gpg"));
        touch(&root.join("r2/storage/access-key-id.gpg"));

        let found = entries(root).unwrap();
        assert_eq!(
            found,
            vec![
                "bean/hl-mainnet-pk",
                "fred-api-key",
                "r2/storage/access-key-id"
            ]
        );
    }

    /// The git directory and the gpg-id file are not entries
    #[test]
    fn housekeeping_files_are_not_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("real.gpg"));
        touch(&root.join(".gpg-id"));
        touch(&root.join(".git/objects/ab/cdef.gpg"));
        touch(&root.join("README.md"));

        assert_eq!(entries(root).unwrap(), vec!["real"]);
    }

    fn names() -> Vec<String> {
        [
            "bean/hl-mainnet-pk",
            "bean/fred-api-key",
            "beanstalk/other",
            "r2/storage/id",
            "top",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn no_prefix_takes_everything() {
        assert_eq!(select(&names(), None).len(), 5);
    }

    /// `bean` must not drag in `beanstalk`, which is why the match is on a trailing slash
    #[test]
    fn a_namespace_does_not_match_a_longer_name() {
        let picked = select(&names(), Some("bean"));
        assert_eq!(picked, vec!["bean/hl-mainnet-pk", "bean/fred-api-key"]);
    }

    #[test]
    fn a_full_entry_name_takes_just_that_one() {
        assert_eq!(select(&names(), Some("top")), vec!["top"]);
        assert_eq!(
            select(&names(), Some("r2/storage/id")),
            vec!["r2/storage/id"]
        );
    }

    #[test]
    fn a_trailing_slash_is_tolerated() {
        assert_eq!(select(&names(), Some("bean/")).len(), 2);
    }

    #[test]
    fn an_unknown_prefix_selects_nothing() {
        assert!(select(&names(), Some("nope")).is_empty());
    }

    #[test]
    fn an_empty_store_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(entries(tmp.path()).unwrap().is_empty());
    }
}
