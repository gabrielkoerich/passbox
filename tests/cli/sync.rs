//! Copying the store to a directory or a git remote.

use super::*;

/// Sync is off until asked for, so a fresh store holds nothing an offline attacker could grind
#[test]
fn sync_is_refused_until_it_is_enabled() {
    let remote = tempfile::tempdir().unwrap();
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    // The store this test builds is headless, so it already carries a recovery wrap
    std::fs::remove_file(cli.path().join("wraps/recovery.age")).unwrap();

    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.env("PASSBOX_REMOTE", remote.path());
    let out = cmd.arg("sync").output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "sync ran with no recovery wrap");
    assert!(err.contains("sync is off"), "{err}");
    assert_eq!(std::fs::read_dir(remote.path()).unwrap().count(), 0);
}

/// `--enable` asks where copies go, then syncs there in the same run
#[test]
fn sync_enable_picks_a_directory_and_copies_into_it() {
    let remote = tempfile::tempdir().unwrap();
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    let answers = format!("2\n{}\n", remote.path().display());
    let err = cli.note(&["sync", "--enable"], Some(&answers));

    assert!(err.contains("already has a wrap"), "{err}");
    assert!(err.contains("copies go to"), "{err}");
    assert!(
        std::fs::read_dir(remote.path()).unwrap().count() > 0,
        "nothing was copied: {err}"
    );
}

/// A git remote makes the store a repo and pushes it, and a second `--enable` asks before changing it
#[test]
fn sync_enable_picks_a_git_remote_and_pushes_the_store() {
    let remote = tempfile::tempdir().unwrap();
    let bare = remote.path().join("store.git");
    let made = Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&bare)
        .status()
        .unwrap();
    assert!(made.success(), "could not make the bare repo");
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    let err = cli.note(
        &["sync", "--enable"],
        Some(&format!("3\n{}\n", bare.display())),
    );
    assert!(err.contains("copies go to"), "{err}");
    let log = Command::new("git")
        .arg("-C")
        .arg(&bare)
        .args(["log", "--oneline"])
        .output()
        .unwrap();
    assert!(
        log.status.success() && !log.stdout.is_empty(),
        "nothing was pushed: {err}"
    );

    let again = cli.note(&["sync", "--enable"], Some("n\n"));
    assert!(again.contains("copies currently go to"), "{again}");
    assert!(again.contains("Change that?"), "{again}");
}

#[test]
fn the_store_gitignore_keeps_the_enclave_wraps_out_of_a_backup() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    cli.run(&["git", "init"], None).unwrap();

    let ignore = std::fs::read_to_string(cli.path().join(".gitignore")).unwrap();
    assert!(ignore.contains("wraps/se-*.json"), "{ignore}");
    assert!(ignore.contains("wraps/phone-*.json"), "{ignore}");

    // A store whose .gitignore was written before phones gets the line on its next git command
    std::fs::write(cli.path().join(".gitignore"), "wraps/se-*.json").unwrap();
    cli.run(&["git", "status"], None).unwrap();
    let ignore = std::fs::read_to_string(cli.path().join(".gitignore")).unwrap();
    assert_eq!(ignore, "wraps/se-*.json\nwraps/phone-*.json\n");
}

#[test]
fn git_runs_inside_the_store_and_ignores_the_socket() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    cli.run(&["git", "init"], None).unwrap();

    let ignore = std::fs::read_to_string(cli.path().join(".gitignore")).unwrap();
    assert!(ignore.contains("broker.sock"), "{ignore}");
    assert!(ignore.contains("store/.versions/"), "{ignore}");

    // The passthrough reaches the store, not whatever directory the caller stood in
    let out = cli.run(&["git", "status", "--short"], None).unwrap();
    assert!(out.contains("wraps/"), "{out}");
    assert!(!out.contains("broker.sock"), "{out}");
}

#[test]
fn a_write_pushes_when_the_repo_has_a_remote() {
    let cli = Cli::new();
    let bare = tempfile::tempdir().unwrap();
    let git = |dir: &std::path::Path, args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(git(bare.path(), &["init", "-q", "--bare"]).status.success());

    cli.run(&["git", "init"], None).unwrap();
    cli.run(&["add", "a/one"], Some("v"))
        .expect("a write with no remote still succeeds");

    let url = bare.path().to_string_lossy().to_string();
    cli.run(&["git", "remote", "add", "origin", &url], None)
        .unwrap();
    cli.run(&["add", "a/two"], Some("v")).unwrap();

    let local = git(cli.path(), &["rev-parse", "HEAD"]).stdout;
    let pushed = git(bare.path(), &["rev-parse", "HEAD"]).stdout;
    assert_eq!(local, pushed, "the write should reach the remote");
}

#[test]
fn a_missing_secret_fails_loudly() {
    let cli = Cli::new();
    let err = cli.read("nope").unwrap_err();
    assert!(err.contains("no secret named nope"), "{err}");
}

#[test]
fn the_old_remote_file_still_syncs_and_says_it_is_deprecated() {
    let cli = Cli::new();
    let mirror = tempfile::tempdir().unwrap();
    let remote = mirror.path().to_string_lossy().to_string();
    std::fs::write(cli.dir.path().join("remote"), &remote).unwrap();

    let out = cli.cmd(PASSPHRASE).arg("sync").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(mirror.path().join("wraps").is_dir(), "{stderr}");
    assert!(stderr.contains("deprecated"), "{stderr}");
}

#[test]
fn enable_moves_the_old_remote_file_into_the_config() {
    let cli = Cli::new();
    let mirror = tempfile::tempdir().unwrap();
    let remote = mirror.path().to_string_lossy().to_string();
    std::fs::write(cli.dir.path().join("remote"), &remote).unwrap();
    cli.run(&["add", "before/move"], Some("value-before"))
        .unwrap();
    cli.run(&["sync"], None).unwrap();

    let out = cli
        .cmd(PASSPHRASE)
        .args(["sync", "--enable"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!cli.dir.path().join("remote").exists(), "{stderr}");
    let config = std::fs::read_to_string(cli.dir.path().join("config.toml")).unwrap();
    assert!(config.contains("engine = \"directory\""), "{config}");
    assert!(config.contains(&remote), "{config}");

    // A write after the move reaches the same mirror through the config alone
    cli.run(&["add", "after/move"], Some("value-after"))
        .unwrap();
    let out = cli.cmd(PASSPHRASE).arg("sync").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("deprecated"), "{stderr}");

    let two = Cli::empty();
    two.sync(mirror.path());
    for store in [&cli, &two] {
        for (name, value) in [
            ("before/move", "value-before"),
            ("after/move", "value-after"),
        ] {
            assert_eq!(store.read(name).unwrap(), value);
        }
    }
}

// The #25 incident: a destination edited by accident must stop the copy and create nothing
#[test]
fn a_write_follows_the_config_and_a_broken_one_creates_nothing() {
    let cli = Cli::new();
    let mirror = tempfile::tempdir().unwrap();
    let config = cli.dir.path().join("config.toml");
    let body = format!(
        "[sync]\nengine = \"directory\"\npath = \"{}\"\n",
        mirror.path().display()
    );
    std::fs::write(&config, body).unwrap();

    cli.run(&["add", "one/secret"], Some("value")).expect("add");
    assert!(
        mirror.path().join("store").is_dir(),
        "the write should reach the configured mirror"
    );

    let stray = mirror.path().join("gone");
    let body = format!(
        "[sync]\nengine = \"directory\"\npath = \"{}\"\n",
        stray.display()
    );
    std::fs::write(&config, body).unwrap();
    cli.run(&["add", "two/secret"], Some("value"))
        .expect("the write itself still succeeds");
    assert!(!stray.exists(), "a missing destination must not be created");

    std::fs::write(&config, "[sync]\nengine = \"icloud\"\n.ccdbkdtdu\n").unwrap();
    let out = cli.cmd(PASSPHRASE).arg("sync").output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a broken config must stop sync");
    assert!(stderr.contains("config.toml is not valid"), "{stderr}");
}

/* Git and the mirror answer different questions and a write does both. They were only ever
tested apart, and together the repo was being copied into the mirror, which swamped the sync
and left the secrets behind: one commit, nothing backed up, and no error saying so. */
#[test]
fn a_write_commits_and_mirrors_without_copying_the_repo() {
    let cli = Cli::new();
    let remote = tempfile::tempdir().unwrap();

    cli.run(&["git", "init"], None).expect("git init");
    std::fs::write(
        cli.dir.path().join("remote"),
        remote.path().to_string_lossy().as_bytes(),
    )
    .expect("choose a remote");

    cli.run(&["add", "one/secret"], Some("value")).expect("add");

    let commits = Command::new("git")
        .args(["-C", &cli.dir.path().to_string_lossy(), "log", "--oneline"])
        .output()
        .expect("git log");
    let log = String::from_utf8_lossy(&commits.stdout);
    assert_eq!(
        log.lines().count(),
        1,
        "the write should commit once: {log}"
    );
    assert!(
        !log.contains("one/secret"),
        "a subject must not name the entry: {log}"
    );

    let mirrored: Vec<_> = std::fs::read_dir(remote.path().join("store"))
        .expect("the mirror should hold a store")
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "age"))
        .collect();
    assert_eq!(mirrored.len(), 1, "the write should reach the mirror");

    assert!(
        !remote.path().join(".git").exists(),
        "the repo is this machine's history and must not be mirrored"
    );

    // and a delete travels too, rather than leaving the copy holding a secret you removed
    cli.run(&["rm", "one/secret"], None).expect("rm");
    let tombs = std::fs::read_dir(remote.path().join("store"))
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "tomb"))
        .count();
    assert_eq!(tombs, 1, "a delete should reach the mirror as a tombstone");
}

/// Writing in a loop should be able to opt out of the copy
#[test]
fn autosync_can_be_turned_off() {
    let cli = Cli::new();
    let remote = tempfile::tempdir().unwrap();
    std::fs::write(
        cli.dir.path().join("remote"),
        remote.path().to_string_lossy().as_bytes(),
    )
    .unwrap();

    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.env("PASSBOX_NO_AUTOSYNC", "1");
    let mut child = cmd
        .args(["add", "quiet/one"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"value").unwrap();
    assert!(child.wait().unwrap().success());

    assert!(
        !remote.path().join("store").exists(),
        "PASSBOX_NO_AUTOSYNC should stop the copy"
    );
}
