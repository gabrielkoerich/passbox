//! Drives the built binary, so it covers what unit tests cannot: argument handling and exit codes.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PASSPHRASE: &str = "hunter2";

struct Cli {
    dir: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        let cli = Cli {
            dir: tempfile::tempdir().unwrap(),
        };
        cli.run(&["init"], None).expect("init");
        cli
    }

    fn cmd(&self, passphrase: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_passbox"));
        cmd.env("PASSBOX_DIR", self.dir.path());
        cmd.env("PASSBOX_PASSPHRASE", passphrase);
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
fn a_missing_secret_fails_loudly() {
    let cli = Cli::new();
    let err = cli.run(&["get", "nope"], None).unwrap_err();
    assert!(err.contains("no secret named nope"), "{err}");
}
