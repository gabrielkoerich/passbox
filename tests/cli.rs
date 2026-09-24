//! Drives the built binary, so it covers what unit tests cannot: argument handling and exit codes.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PASSPHRASE: &str = "correct horse battery staple";

struct Cli {
    dir: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        let cli = Cli::empty();
        cli.run(&["init"], None).expect("init");
        cli
    }

    /// A machine that has no store yet, which is how a second Mac starts
    fn empty() -> Self {
        Cli {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn sync(&self, remote: &Path) {
        let (ok, _, stderr) = {
            let mut cmd = self.cmd(PASSPHRASE);
            cmd.env("PASSBOX_REMOTE", remote);
            let out = cmd.arg("sync").output().unwrap();
            (
                out.status.success(),
                String::new(),
                String::from_utf8_lossy(&out.stderr).to_string(),
            )
        };
        assert!(ok, "sync failed: {stderr}");
    }

    fn cmd(&self, passphrase: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_passbox"));
        cmd.env("PASSBOX_DIR", self.dir.path());
        cmd.env("PASSBOX_PASSPHRASE", passphrase);
        // A one second KDF per store is the right default and the wrong thing to pay here
        cmd.env("PASSBOX_SCRYPT_LOG_N", "10");
        cmd
    }

    /// Stdout on success, stderr on failure, so a test can assert on either
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        self.run_as(PASSPHRASE, args, stdin)
    }

    fn run_as(
        &self,
        passphrase: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> Result<String, String> {
        let (ok, stdout, stderr) = self.exec(passphrase, args, stdin);
        if ok { Ok(stdout) } else { Err(stderr) }
    }

    /// The confirmation a command prints, which goes to stderr to keep stdout pipeable
    fn note(&self, args: &[&str], stdin: Option<&str>) -> String {
        let (ok, _, stderr) = self.exec(PASSPHRASE, args, stdin);
        assert!(ok, "{args:?} failed: {stderr}");
        stderr
    }

    fn exec(&self, passphrase: &str, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut child = self
            .cmd(passphrase)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());

        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[test]
fn add_get_and_list() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();
    cli.run(&["add", "banking/login"], Some("swordfish"))
        .unwrap();

    assert_eq!(cli.run(&["get", "github/token"], None).unwrap(), "ghp_abc");
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "banking/login\ngithub/token\n"
    );
}

#[test]
fn nothing_on_disk_reveals_a_name() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();

    for entry in std::fs::read_dir(cli.path().join("store")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(!name.contains("github"), "{name} holds the secret name");
        if path.is_file() {
            let raw = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&raw);
            assert!(
                !text.contains("github"),
                "{name} holds the name in the clear"
            );
            assert!(
                !text.contains("ghp_abc"),
                "{name} holds the value in the clear"
            );
        }
    }
}

/// Replacing a value must not widen access, which is the bug the first smoke run found
#[test]
fn replacing_a_value_keeps_the_mode() {
    let cli = Cli::new();
    cli.run(&["add", "banking/login", "--mode", "never"], Some("old"))
        .unwrap();
    let out = cli.note(&["add", "banking/login"], Some("new"));

    assert!(out.contains("never"), "mode was reset: {out}");
    assert_eq!(cli.run(&["get", "banking/login"], None).unwrap(), "new");
}

#[test]
fn an_explicit_mode_still_wins() {
    let cli = Cli::new();
    cli.run(&["add", "db/pass"], Some("v")).unwrap();
    cli.run(&["mode", "db/pass", "never"], None).unwrap();
    let out = cli.note(&["add", "db/pass", "--mode", "open"], Some("v2"));
    assert!(out.contains("open"), "{out}");
}

#[test]
fn an_overwrite_is_recoverable() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("good")).unwrap();
    cli.run(&["add", "github/token"], Some("bad")).unwrap();
    assert_eq!(cli.run(&["get", "github/token"], None).unwrap(), "bad");

    cli.run(&["restore", "github/token", "--index", "0"], None)
        .unwrap();
    assert_eq!(cli.run(&["get", "github/token"], None).unwrap(), "good");
}

#[test]
fn a_deleted_secret_is_still_recoverable() {
    let cli = Cli::new();
    cli.run(&["add", "banking/login"], Some("swordfish"))
        .unwrap();
    cli.run(&["rm", "banking/login"], None).unwrap();

    assert_eq!(cli.run(&["ls"], None).unwrap(), "");
    assert!(cli.run(&["get", "banking/login"], None).is_err());

    cli.run(&["restore", "banking/login", "--index", "0"], None)
        .unwrap();
    assert_eq!(
        cli.run(&["get", "banking/login"], None).unwrap(),
        "swordfish"
    );
}

#[test]
fn a_wrong_passphrase_is_refused() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();

    let err = cli
        .run_as("wrong", &["get", "github/token"], None)
        .unwrap_err();
    assert!(err.contains("passphrase"), "{err}");
    assert!(!err.contains("ghp_abc"));
}

#[test]
fn an_empty_value_is_refused() {
    let cli = Cli::new();
    assert!(cli.run(&["add", "empty"], Some("")).is_err());
}

#[test]
fn exec_injects_into_the_child_environment() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();

    let out = cli
        .run(
            &[
                "exec",
                "--env",
                "GITHUB_TOKEN=github/token",
                "--",
                "sh",
                "-c",
                "printf %s \"$GITHUB_TOKEN\"",
            ],
            None,
        )
        .unwrap();
    assert_eq!(out, "ghp_abc");
}

#[test]
fn exec_pipes_a_secret_on_stdin() {
    let cli = Cli::new();
    cli.run(&["add", "db/password"], Some("swordfish")).unwrap();

    let out = cli
        .run(&["exec", "--stdin", "db/password", "--", "cat"], None)
        .unwrap();
    assert_eq!(out, "swordfish");
}

/// The mode is enforced by passbox, not by the Enclave, so it holds with no hardware
#[test]
fn exec_refuses_a_never_secret() {
    let cli = Cli::new();
    cli.run(
        &["add", "banking/login", "--mode", "never"],
        Some("swordfish"),
    )
    .unwrap();

    let err = cli
        .run(
            &[
                "exec",
                "--env",
                "P=banking/login",
                "--",
                "sh",
                "-c",
                "echo $P",
            ],
            None,
        )
        .unwrap_err();
    assert!(err.contains("never"), "{err}");
    assert!(!err.contains("swordfish"));

    assert_eq!(
        cli.run(&["get", "banking/login"], None).unwrap(),
        "swordfish"
    );
}

#[test]
fn exec_passes_the_child_exit_code_through() {
    let cli = Cli::new();
    let err = cli.run(&["exec", "--", "sh", "-c", "exit 3"], None);
    assert!(err.is_err());
}

/// A synced delete leaves the file in place with a tombstone over it, which `restore` must find
#[test]
fn a_secret_deleted_on_another_machine_can_still_be_restored() {
    let remote = tempfile::tempdir().unwrap();
    let one = Cli::new();
    one.run(&["add", "github/token"], Some("ghp_abc")).unwrap();
    one.sync(remote.path());

    let two = Cli::empty();
    two.sync(remote.path());
    assert_eq!(two.run(&["get", "github/token"], None).unwrap(), "ghp_abc");

    two.run(&["rm", "github/token"], None).unwrap();
    two.sync(remote.path());
    one.sync(remote.path());
    assert_eq!(one.run(&["ls"], None).unwrap(), "");

    one.run(&["restore", "github/token", "--index", "0"], None)
        .unwrap();
    assert_eq!(one.run(&["get", "github/token"], None).unwrap(), "ghp_abc");
}

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

#[test]
fn the_store_gitignore_keeps_the_enclave_wraps_out_of_a_backup() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    cli.run(&["git", "init"], None).unwrap();

    let ignore = std::fs::read_to_string(cli.path().join(".gitignore")).unwrap();
    assert!(ignore.contains("wraps/se-*.json"), "{ignore}");
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

/* pass entries carry `key: value` lines under the password, and bean's get_fields reads them, so
the import has to keep the whole body rather than the first line. */
#[test]
fn importing_from_pass_keeps_the_whole_entry() {
    let cli = Cli::new();
    let fake = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();

    for name in ["bean/hl-mainnet-pk", "bean/fred-api-key", "beanstalk/other"] {
        let path = store.path().join(format!("{name}.gpg"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"x").unwrap();
    }

    let shim = fake.path().join("pass");
    std::fs::write(
        &shim,
        "#!/bin/sh\nprintf 'topsecret\\nlogin: gb\\nurl: https://example.com'\n",
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let out = cli
        .cmd(PASSPHRASE)
        .env("PASSWORD_STORE_DIR", store.path())
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args(["import-pass", "bean"])
        .output()
        .unwrap();
    let note = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{note}");
    assert!(note.contains("importing 2 of 3"), "{note}");

    // The namespace filter must not have dragged in beanstalk
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "bean/fred-api-key\nbean/hl-mainnet-pk\n"
    );

    let body = cli.run(&["get", "bean/hl-mainnet-pk"], None).unwrap();
    assert_eq!(body, "topsecret\nlogin: gb\nurl: https://example.com");
}

#[test]
fn importing_twice_skips_what_is_already_there() {
    let cli = Cli::new();
    let fake = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    std::fs::write(store.path().join("solo.gpg"), b"x").unwrap();

    let shim = fake.path().join("pass");
    std::fs::write(&shim, "#!/bin/sh\nprintf 'value'\n").unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let run = || {
        let out = cli
            .cmd(PASSPHRASE)
            .env("PASSWORD_STORE_DIR", store.path())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    fake.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .arg("import-pass")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stderr).to_string()
    };

    assert!(run().contains("imported 1, skipped 0"));
    let second = run();
    assert!(second.contains("imported 0, skipped 1"), "{second}");
}

#[test]
fn a_missing_secret_fails_loudly() {
    let cli = Cli::new();
    let err = cli.run(&["get", "nope"], None).unwrap_err();
    assert!(err.contains("no secret named nope"), "{err}");
}
