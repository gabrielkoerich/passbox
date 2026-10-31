//! Bring entries across from `pass`, decrypting through GPG and re-encrypting to the store key.

use super::{Entry, Fetched, Source, under};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

fn store_dir() -> PathBuf {
    if let Some(set) = std::env::var_os("PASSWORD_STORE_DIR") {
        return PathBuf::from(set);
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".password-store"))
        .unwrap_or_default()
}

/// Entry names are paths under the store with the `.gpg` taken off, which is how pass names them
fn entries(dir: &Path) -> Result<Vec<String>> {
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
use crate::store::select;

/* The whole body is kept, not just the first line. pass entries commonly carry `key: value` lines
under the password, and `get --field` reads them, so trimming to line one would lose data. */
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

/// `pass`, read through its own CLI so GPG and its agent decrypt as they always do
pub(crate) struct Pass;

impl Source for Pass {
    type Handle = String;

    fn name(&self) -> &'static str {
        "pass"
    }

    /// Names are the entry paths, so an import keeps the layout pass shows
    fn entries(&self, from: Option<&str>, prefix: Option<&str>) -> Result<Vec<Entry<String>>> {
        let dir = store_dir();
        let all = entries(&dir)?;
        if all.is_empty() {
            bail!("no pass entries under {}", dir.display());
        }

        let picked = select(&all, from);
        if picked.is_empty() {
            bail!(
                "nothing in pass matches {}, of {} entries",
                from.unwrap_or("*"),
                all.len()
            );
        }
        Ok(picked
            .into_iter()
            .map(|entry| Entry {
                name: under(prefix, &entry),
                label: entry.clone(),
                handle: entry,
            })
            .collect())
    }

    fn fetch(&self, entry: &String) -> Result<Fetched> {
        Ok(Fetched::Value {
            value: show(entry)?,
            notes: Vec::new(),
            blob: false,
        })
    }
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
        touch(&root.join("api-key.gpg"));
        touch(&root.join("acme/signing-key.gpg"));
        touch(&root.join("r2/storage/access-key-id.gpg"));

        let found = entries(root).unwrap();
        assert_eq!(
            found,
            vec!["acme/signing-key", "api-key", "r2/storage/access-key-id"]
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
            "acme/signing-key",
            "acme/api-key",
            "acmecorp/other",
            "r2/storage/id",
            "top",
        ]
        .iter()
        .copied()
        .map(String::from)
        .collect()
    }

    #[test]
    fn no_prefix_takes_everything() {
        assert_eq!(select(&names(), None).len(), 5);
    }

    /// `acme` must not drag in `acmecorp`, which is why the match is on a trailing slash
    #[test]
    fn a_namespace_does_not_match_a_longer_name() {
        let picked = select(&names(), Some("acme"));
        assert_eq!(picked, vec!["acme/signing-key", "acme/api-key"]);
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
        assert_eq!(select(&names(), Some("acme/")).len(), 2);
    }

    #[test]
    fn an_unknown_prefix_selects_nothing() {
        assert_eq!(select(&names(), Some("nope")), Vec::<String>::new());
    }

    #[test]
    fn an_empty_store_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(entries(tmp.path()).unwrap(), Vec::<String>::new());
    }
}
