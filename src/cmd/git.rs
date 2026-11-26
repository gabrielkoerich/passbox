//! The store as a git repository: a commit on every write, the mirror, and the push.

use crate::store::{MACHINE_LOCAL, Store, machine_local, now, path_matches};
#[cfg(feature = "host")]
use crate::sync;
use anyhow::{Context, Result, bail};

/* git carries the encrypted secrets and nothing that opens them. The Enclave wraps are useless
off the Mac that made them, so they stay out. The recovery wrap only exists once sync is on, and
then it belongs in the backup, because without it the backup cannot be restored anywhere. */

/// Everything sync leaves out, and the Enclave wraps, which sync carries since each names its Mac
fn ignored() -> impl Iterator<Item = &'static str> {
    MACHINE_LOCAL
        .iter()
        .copied()
        .filter(|line| !line.starts_with("/.git"))
        .chain(["/wraps/se-*.json", "*.from-git-*"])
}

/* git checks out whatever a commit tracks, and a pulled .gitignore can unignore anything, so the
ignore lines go in .git/info/exclude, which no pull changes, and every tracked path is checked
with passbox's own list rather than git's ignore rules. A machine local file git tracks was
pulled, or committed by an older passbox. It moves into .git/passbox, where no checkout writes,
and only then leaves the index. One that cannot move stops passbox, so nothing is deleted and
nothing git brought is read */
pub(crate) fn ensure_store_gitignore(store: &Store) -> Result<()> {
    if !in_git(store) {
        return Ok(());
    }
    let info = store.dir.join(".git/info");
    std::fs::create_dir_all(&info)?;
    let exclude = info.join("exclude");
    let text = std::fs::read_to_string(&exclude).unwrap_or_default();
    let missing: Vec<&str> = ignored()
        .filter(|line| !text.lines().any(|l| l == *line))
        .collect();
    if !missing.is_empty() {
        let gap = if text.is_empty() || text.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        std::fs::write(&exclude, format!("{text}{gap}{}\n", missing.join("\n")))?;
    }

    let tracked = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(["ls-files", "-z", "--cached"])
        .output()
        .context("git is not on PATH")?;
    if !tracked.status.success() {
        bail!(
            "git could not list what it tracks in {}: {}",
            store.dir.display(),
            String::from_utf8_lossy(&tracked.stderr).trim()
        );
    }
    // A plugin moves as a folder, so no file of it is left to run
    let mut aside = std::collections::BTreeSet::new();
    for file in tracked.stdout.split(|b| *b == 0).filter(|f| !f.is_empty()) {
        let file = String::from_utf8_lossy(file).to_string();
        if !kept_out(&file) {
            continue;
        }
        let top = match file.split_once('/') {
            Some((dir, rest)) if dir.eq_ignore_ascii_case("plugins") => {
                format!("{dir}/{}", rest.split('/').next().unwrap_or(rest))
            }
            _ => file,
        };
        aside.insert(top);
    }
    let mut stuck = Vec::new();
    for (n, path) in aside.into_iter().enumerate() {
        let from = store.dir.join(&path);
        let to = store
            .dir
            .join(".git/passbox/from-git")
            .join(format!("{path}-{}-{n}", now()));
        // A link is moved as a link, never followed
        if std::fs::symlink_metadata(&from).is_ok() {
            let moved = to
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::rename(&from, &to));
            if let Err(e) = moved {
                stuck.push(format!("{path}: {e}"));
                continue;
            }
            eprintln!(
                "{path} was tracked by git, pulled or committed by an older passbox, so it moved to {}",
                to.display()
            );
        }
        git_quietly(
            store,
            &[
                "--literal-pathspecs",
                "rm",
                "-r",
                "--cached",
                "--quiet",
                "--ignore-unmatch",
                "--",
                &path,
            ],
        );
    }
    if !stuck.is_empty() {
        bail!(
            "git tracks files that belong to this Mac alone, and passbox could not set them aside, \
             so it will not read the store until they are out of git and gone:\n{}",
            stuck.join("\n")
        );
    }
    Ok(())
}

/// A pulled .gitignore can unignore a machine local file, which `add -A` then stages. It leaves
/// the index and stays where it is, since it is this Mac's own
fn unstage(store: &Store) {
    let Ok(staged) = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(["ls-files", "-z", "--cached"])
        .output()
    else {
        return;
    };
    for file in staged.stdout.split(|b| *b == 0).filter(|f| !f.is_empty()) {
        let file = String::from_utf8_lossy(file);
        if kept_out(&file) {
            git_quietly(
                store,
                &[
                    "--literal-pathspecs",
                    "rm",
                    "--cached",
                    "--quiet",
                    "--",
                    &file,
                ],
            );
        }
    }
}

/// What git must not carry: every machine local path, the .gitignore itself aside, and the
/// Enclave wraps, which sync carries since each names its Mac. Every path passbox writes is ASCII,
/// and macOS folds case and accents in ways a text match misses, so any other path is kept out
fn kept_out(relative: &str) -> bool {
    !relative.is_ascii()
        || !relative.eq_ignore_ascii_case(".gitignore")
            && (machine_local(relative) || path_matches("/wraps/se-*.json", relative))
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
    // A pull may have checked out a machine local file, which goes aside before anything reads it
    ensure_store_gitignore(store)?;
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
    unstage(store);
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

#[cfg(test)]
mod tests {
    use super::kept_out;

    #[test]
    fn a_path_macos_would_fold_onto_a_machine_local_file_is_kept_out() {
        assert!(kept_out("config.toml"));
        assert!(kept_out("CONFIG.toml"));
        // A ligature and a decomposed accent, which a text match does not fold
        assert!(kept_out("con\u{fb01}g.toml"));
        assert!(kept_out("store/cafe\u{301}.age"));
        assert!(!kept_out("store/abc.age"));
        assert!(!kept_out(".gitignore"));
        // Where 2.4.2 set a pulled file aside, which must not sync or be committed
        assert!(kept_out("config.toml.from-git-1764171726-0"));
        assert!(kept_out("plugins/demo.from-git-1764171726-1/run.sh"));
        assert!(kept_out(".from-git/config.toml-1764171726-0"));
    }
}
