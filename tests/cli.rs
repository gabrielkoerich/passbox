//! Drives the built binary, so it covers what unit tests cannot: argument handling and exit codes.

use std::io::{BufRead, Write};
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
        // A test must never reach the developer's fingerprint, whatever else breaks
        cmd.env("PASSBOX_NO_ENCLAVE", "1");
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

    assert_eq!(
        cli.run(&["get", "--reveal", "github/token"], None).unwrap(),
        "ghp_abc"
    );
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "banking/login\ngithub/token\n"
    );
}

#[test]
fn get_refuses_a_capture_without_reveal() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    // stdout is a pipe in the harness, the same shape as an agent capturing the value
    let err = cli.run(&["get", "a/b"], None).unwrap_err();
    assert!(err.contains("not a terminal"), "{err}");
    assert!(err.contains("passbox copy"), "{err}");
    // --reveal is the deliberate capture path
    assert_eq!(cli.run(&["get", "--reveal", "a/b"], None).unwrap(), "v");
}

#[test]
#[ignore = "needs a clipboard session"]
fn copy_puts_the_value_on_the_clipboard() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("sekret")).unwrap();
    cli.run(&["copy", "a/b", "--clear", "60"], None).unwrap();
    let board = std::process::Command::new("pbpaste").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&board.stdout), "sekret");
}

/// One behaviour, no modes: a read works, and the old mode flag and subcommand are gone
#[test]
fn there_are_no_modes() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    assert_eq!(cli.run(&["get", "--reveal", "a/b"], None).unwrap(), "v");
    assert!(
        cli.run(&["add", "a/b", "--mode", "never"], Some("v"))
            .is_err()
    );
    assert!(cli.run(&["mode", "a/b", "never"], None).is_err());
}

#[test]
fn a_plugin_installs_runs_and_is_removed() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"demo\"\ndescription = \"test\"\n\n\
         [[tool]]\nname = \"say\"\nparams = [\"msg\"]\n\
         run = [\"printf\", \"%s\", \"{msg}\"]\n",
    )
    .unwrap();

    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);
    assert!(
        cli.run(&["plugin", "list"], None)
            .unwrap()
            .contains("demo say")
    );
    // a headless store takes the passphrase path, so no prompt, and params substitute
    assert_eq!(
        cli.run(&["plugin", "demo", "say", "--msg", "hi"], None)
            .unwrap(),
        "hi"
    );
    // a missing required parameter is refused before anything runs
    assert!(
        cli.run(&["plugin", "demo", "say"], None)
            .unwrap_err()
            .contains("needs --msg")
    );
    cli.note(&["plugin", "remove", "demo"], None);
    assert!(!cli.run(&["plugin", "list"], None).unwrap().contains("demo"));
}

#[test]
fn a_first_party_plugin_installs_by_name() {
    let cli = Cli::new();
    cli.note(&["plugin", "add", "things3"], None);
    let list = cli.run(&["plugin", "list"], None).unwrap();
    assert!(list.contains("things3 add"), "{list}");
    assert!(list.contains("things3 search"), "{list}");
    // a second install is refused rather than silently overwriting
    assert!(
        cli.run(&["plugin", "add", "things3"], None)
            .unwrap_err()
            .contains("already installed")
    );
}

#[test]
fn a_plugin_runs_only_its_defined_actions() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"demo\"\ndescription = \"x\"\n\n\
         [[tool]]\nname = \"say\"\nparams = [\"msg\"]\nrun = [\"echo\", \"{msg}\"]\n",
    )
    .unwrap();
    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);
    // An action the manifest does not define is refused, never run
    let err = cli
        .run(&["plugin", "demo", "delete-everything"], None)
        .unwrap_err();
    assert!(err.contains("has no action delete-everything"), "{err}");
    // So is an undefined parameter on a real action
    let err = cli
        .run(
            &["plugin", "demo", "say", "--msg", "hi", "--evil", "x"],
            None,
        )
        .unwrap_err();
    assert!(err.contains("no parameter evil"), "{err}");
}

#[test]
fn a_plugin_name_cannot_delete_outside_the_plugins_directory() {
    let cli = Cli::new();
    cli.note(&["plugin", "add", "things3"], None);
    let victim = cli.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("keep.txt"), "important").unwrap();
    // ../victim resolves outside plugins/, and remove must refuse it
    let err = cli
        .run(&["plugin", "remove", "../victim"], None)
        .unwrap_err();
    assert!(err.contains("invalid plugin name"), "{err}");
    assert!(
        victim.join("keep.txt").exists(),
        "the traversal deleted a directory"
    );
}

#[test]
fn plugin_update_overwrites_an_installed_plugin() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    let write = |version: &str, desc: &str| {
        std::fs::write(
            src.path().join("plugin.toml"),
            format!(
                "name = \"demo\"\ndescription = \"{desc}\"\nversion = \"{version}\"\n\n\
                 [[tool]]\nname = \"say\"\nrun = [\"echo\", \"hi\"]\n"
            ),
        )
        .unwrap();
    };
    write("1.0.0", "one");
    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);
    assert!(
        cli.run(&["plugin", "add", src.path().to_str().unwrap()], None)
            .unwrap_err()
            .contains("already installed")
    );
    write("2.0.0", "two");
    cli.note(&["plugin", "update", src.path().to_str().unwrap()], None);
    assert!(
        cli.run(&["plugin", "list"], None)
            .unwrap()
            .contains("demo 2.0.0")
    );
}

#[test]
fn a_stale_first_party_plugin_is_flagged_for_update() {
    let cli = Cli::new();
    cli.note(&["plugin", "add", "things3"], None);
    // Rewrite the installed version to an older one, as a brew upgrade would leave it behind
    let toml = cli.path().join("plugins/things3/plugin.toml");
    let older = std::fs::read_to_string(&toml)
        .unwrap()
        .replace("version = \"1.0.0\"", "version = \"0.1.0\"");
    std::fs::write(&toml, older).unwrap();
    let list = cli.run(&["plugin", "list"], None).unwrap();
    assert!(list.contains("update available: 0.1.0 -> 1.0.0"), "{list}");
}

#[test]
fn a_caller_cwd_plugin_runs_where_it_was_invoked() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"here\"\ndescription = \"x\"\ncwd = \"caller\"\n\n\
         [[tool]]\nname = \"pwd\"\nrun = [\"pwd\"]\n",
    )
    .unwrap();
    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);
    // With cwd = caller it prints the invoking directory, not the plugin's install directory
    let out = cli.run(&["plugin", "here", "pwd"], None).unwrap();
    assert_eq!(
        out.trim(),
        std::env::current_dir().unwrap().to_str().unwrap(),
        "{out}"
    );
}

#[test]
fn a_missing_required_command_is_refused_with_an_install_hint() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"needs\"\ndescription = \"x\"\n\
         requires = \"no-such-command-xyz\"\ninstall = \"brew install foo\"\n\n\
         [[tool]]\nname = \"go\"\nrun = [\"echo\", \"hi\"]\n",
    )
    .unwrap();
    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);
    let err = cli.run(&["plugin", "needs", "go"], None).unwrap_err();
    assert!(err.contains("needs `no-such-command-xyz`"), "{err}");
    assert!(err.contains("brew install foo"), "{err}");
}

#[test]
fn a_headless_read_is_audited() {
    let cli = Cli::new();
    cli.run(&["add", "a/one"], Some("v1")).unwrap();
    cli.run(&["add", "a/two"], Some("v2")).unwrap();
    cli.run(&["get", "--reveal", "a/one"], None).unwrap();
    cli.run(
        &["exec", "--env", "X=a/one", "--env", "Y=a/two", "--", "true"],
        None,
    )
    .unwrap();
    let log = cli.run(&["audit", "--tail", "50"], None).unwrap();
    // one release from get, two from the exec
    let released = log
        .lines()
        .filter(|l| l.contains("\"decision\":\"released\""))
        .count();
    assert_eq!(released, 3, "{log}");
}

/// The whole store directory, not only `store/`, which is how a plaintext name list once slipped by
#[test]
fn nothing_on_disk_reveals_a_name() {
    let cli = Cli::new();
    // What a version before 0.13.43 left behind, which the next command must remove
    std::fs::write(cli.path().join("names"), "github/token\n").unwrap();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();
    cli.run(&["ls"], None).unwrap();
    cli.run(&["get", "--reveal", "github/token"], None).unwrap();

    let mut dirs = vec![cli.path().to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            assert!(!name.contains("github"), "{name} holds the secret name");
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).to_string();
            assert!(
                !text.contains("github"),
                "{} holds the name in the clear",
                path.display()
            );
            assert!(
                !text.contains("ghp_abc"),
                "{} holds the value in the clear",
                path.display()
            );
        }
    }
}

#[test]
fn an_overwrite_is_recoverable() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("good")).unwrap();
    cli.run(&["add", "github/token"], Some("bad")).unwrap();
    assert_eq!(
        cli.run(&["get", "--reveal", "github/token"], None).unwrap(),
        "bad"
    );

    cli.run(&["restore", "github/token", "--index", "0"], None)
        .unwrap();
    assert_eq!(
        cli.run(&["get", "--reveal", "github/token"], None).unwrap(),
        "good"
    );
}

#[test]
fn a_deleted_secret_is_still_recoverable() {
    let cli = Cli::new();
    cli.run(&["add", "banking/login"], Some("swordfish"))
        .unwrap();
    cli.run(&["rm", "banking/login"], None).unwrap();

    assert_eq!(cli.run(&["ls"], None).unwrap(), "");
    assert!(
        cli.run(&["get", "--reveal", "banking/login"], None)
            .is_err()
    );

    cli.run(&["restore", "banking/login", "--index", "0"], None)
        .unwrap();
    assert_eq!(
        cli.run(&["get", "--reveal", "banking/login"], None)
            .unwrap(),
        "swordfish"
    );
}

#[test]
fn a_wrong_passphrase_is_refused() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();

    let err = cli
        .run_as("wrong", &["get", "--reveal", "github/token"], None)
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
    assert_eq!(
        two.run(&["get", "--reveal", "github/token"], None).unwrap(),
        "ghp_abc"
    );

    two.run(&["rm", "github/token"], None).unwrap();
    two.sync(remote.path());
    one.sync(remote.path());
    assert_eq!(one.run(&["ls"], None).unwrap(), "");

    one.run(&["restore", "github/token", "--index", "0"], None)
        .unwrap();
    assert_eq!(
        one.run(&["get", "--reveal", "github/token"], None).unwrap(),
        "ghp_abc"
    );
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

    let body = cli
        .run(&["get", "--reveal", "bean/hl-mainnet-pk"], None)
        .unwrap();
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
    let err = cli.run(&["get", "--reveal", "nope"], None).unwrap_err();
    assert!(err.contains("no secret named nope"), "{err}");
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
        .filter_map(|e| e.ok())
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
        .filter_map(|e| e.ok())
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

/// The Mac's broker as a client with PASSBOX_HOST reaches it, on loopback. Each connection is one
/// request, answered by `answer` and handed back so a test can check what the client asked for
fn fake_host(
    answer: impl Fn(&serde_json::Value) -> Result<String, String> + Send + 'static,
) -> (String, std::sync::mpsc::Receiver<serde_json::Value>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (seen, requests) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            let response = match answer(&request) {
                Ok(value) => serde_json::json!({ "ok": true, "value": value, "error": null }),
                Err(error) => serde_json::json!({ "ok": false, "value": null, "error": error }),
            };
            seen.send(request).unwrap();
            writeln!(stream, "{response}").unwrap();
        }
    });
    (addr, requests)
}

/// A client run with a configured host, and with or without a token already held
fn on_host(cli: &Cli, host: &str, token: Option<&str>, args: &[&str]) -> (bool, String, String) {
    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.env("PASSBOX_HOST", host).env_remove("PASSBOX_TOKEN");
    if let Some(token) = token {
        cmd.env("PASSBOX_TOKEN", token);
    }
    let out = cmd.args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ops(requests: &std::sync::mpsc::Receiver<serde_json::Value>) -> Vec<serde_json::Value> {
    requests.try_iter().collect()
}

#[test]
fn grant_on_a_client_goes_to_the_host_and_keeps_the_token_off_stderr() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|_| Ok("tok-7f3a\na/b\nc/d".into()));
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &["grant", "a/b", "c/d"]);

    assert!(ok, "{stderr}");
    assert_eq!(stdout, "tok-7f3a\n");
    // stderr lands in scrollback, CI logs and agent transcripts, so the token must not be there
    assert!(
        !stderr.contains("tok-7f3a"),
        "the token leaked to stderr: {stderr}"
    );
    assert!(stderr.contains("a/b") && stderr.contains("c/d"), "{stderr}");

    let seen = ops(&requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["op"], "grant");
    assert_eq!(seen[0]["names"], serde_json::json!(["a/b", "c/d"]));
}

#[test]
fn exec_with_many_secrets_asks_the_host_once() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["op"].as_str() {
        Some("grant") => Ok("tok-1\na/b\nc/d".into()),
        Some("get") if r["token"] == "tok-1" => Ok(format!("v-{}", r["name"].as_str().unwrap())),
        _ => Err("a read without the batch token".into()),
    });
    let script = "printf %s, \"$A\"; cat";
    let args = [
        "exec", "--env", "A=a/b", "--stdin", "c/d", "--", "sh", "-c", script,
    ];
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &args);

    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v-a/b,v-c/d");
    let seen = ops(&requests);
    let kinds: Vec<&str> = seen.iter().map(|r| r["op"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["grant", "get", "get"]);
    // A short token, so it is useless once the batch is read
    assert_eq!(seen[0]["ttl"], 30);
}

#[test]
fn exec_reads_one_by_one_when_the_grant_is_refused() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["op"].as_str() {
        Some("grant") => Err("denied".into()),
        Some("get") if r["token"] == "" => Ok(format!("v-{}", r["name"].as_str().unwrap())),
        _ => Err("unexpected request".into()),
    });
    let args = [
        "exec",
        "--env",
        "A=a/b",
        "--env",
        "B=c/d",
        "--",
        "sh",
        "-c",
        "printf %s,%s \"$A\" \"$B\"",
    ];
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &args);

    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v-a/b,v-c/d");
    let kinds: Vec<String> = ops(&requests)
        .iter()
        .map(|r| r["op"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["grant", "get", "get"]);
}

#[test]
fn exec_with_one_secret_or_a_held_token_mints_no_grant() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| Ok(format!("v-{}", r["name"].as_str().unwrap())));

    let one = [
        "exec",
        "--env",
        "A=a/b",
        "--",
        "sh",
        "-c",
        "printf %s \"$A\"",
    ];
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &one);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v-a/b");
    let seen = ops(&requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["op"], "get");

    let two = ["exec", "--env", "A=a/b", "--env", "B=c/d", "--", "true"];
    let (ok, _, stderr) = on_host(&cli, &host, Some("held"), &two);
    assert!(ok, "{stderr}");
    let seen = ops(&requests);
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|r| r["op"] == "get" && r["token"] == "held"),
        "{seen:?}"
    );
}

/// Prints the two credential variables as the child sees them, so an empty pair means it got neither
const SHOW_CREDENTIALS: &str = "printf '[%s][%s]' \"$PASSBOX_TOKEN\" \"$PASSBOX_PASSPHRASE\"";

fn with_token(cli: &Cli, args: &[&str]) -> std::process::Output {
    cli.cmd(PASSPHRASE)
        .env("PASSBOX_TOKEN", "tok-leak")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn exec_children_never_see_the_token_or_the_passphrase() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    let out = with_token(
        &cli,
        &["exec", "--env", "A=a/b", "--", "sh", "-c", SHOW_CREDENTIALS],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[][]");

    // Asking for a secret under that name on purpose still works
    let out = with_token(
        &cli,
        &[
            "exec",
            "--env",
            "PASSBOX_TOKEN=a/b",
            "--",
            "sh",
            "-c",
            SHOW_CREDENTIALS,
        ],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[v][]");
}

#[test]
fn passbox_wipes_the_credentials_from_its_own_environment() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    // The child reads its parent's environment the way any process running as the user can
    let out = with_token(
        &cli,
        &[
            "exec",
            "--env",
            "A=a/b",
            "--",
            "sh",
            "-c",
            "ps eww -o command= -p $PPID",
        ],
    );
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(
        seen.contains("PASSBOX_DIR="),
        "ps did not show the environment: {seen}"
    );
    assert!(
        !seen.contains("tok-leak"),
        "the token is still in the environment: {seen}"
    );
    assert!(
        !seen.contains(PASSPHRASE),
        "the passphrase is still in the environment: {seen}"
    );
}

#[test]
fn plugin_commands_never_see_the_token_or_the_passphrase() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    let manifest = format!(
        "name = \"envcheck\"\ndescription = \"test\"\n\n[[tool]]\nname = \"show\"\nrun = [\"sh\", \"-c\", {}]\n",
        toml_string(SHOW_CREDENTIALS)
    );
    std::fs::write(src.path().join("plugin.toml"), manifest).unwrap();
    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);

    let out = with_token(&cli, &["plugin", "envcheck", "show"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[][]");
}

#[test]
fn mcp_run_with_secret_never_hands_the_token_or_the_passphrase_to_the_agent() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v-secret")).unwrap();

    let script = format!("{SHOW_CREDENTIALS}; printf '[%s]' \"$S\"");
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "run_with_secret", "arguments": {
            "secret": "a/b", "env_var": "S", "command": ["sh", "-c", script]
        }}
    });
    let mut child = cli
        .cmd(PASSPHRASE)
        .env("PASSBOX_TOKEN", "tok-leak")
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{call}").unwrap();
    let out = child.wait_with_output().unwrap();
    let reply = String::from_utf8_lossy(&out.stdout);

    assert!(reply.contains("[][][[redacted by passbox]]"), "{reply}");
    assert!(
        !reply.contains("tok-leak"),
        "the token reached the agent: {reply}"
    );
    assert!(
        !reply.contains(PASSPHRASE),
        "the passphrase reached the agent: {reply}"
    );
}

/// A TOML basic string holding `text`, so a shell script with quotes survives the manifest
fn toml_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

#[test]
fn a_test_can_never_reach_the_secure_enclave() {
    use std::os::unix::process::CommandExt;

    let cli = Cli::empty();
    let mut cmd = cli.cmd(PASSPHRASE);
    // No passphrase makes init try to bind the Enclave, which is what a broken headless check does
    cmd.env_remove("PASSBOX_PASSPHRASE")
        .arg("init")
        .stdin(Stdio::null());
    // No controlling terminal, so the passphrase init falls back to cannot wait on a keyboard
    // SAFETY: setsid is async-signal-safe and touches nothing in this process
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disabled by PASSBOX_NO_ENCLAVE"),
        "{stderr}"
    );
    assert!(!stderr.contains("bound to this Mac"), "{stderr}");
}

const NEEDS_FAKE: &str = "needs --features mock-enclave";

/// The fake enclave binary, which only exists in a `--features mock-enclave` build
fn fake_enclave() -> &'static str {
    match option_env!("CARGO_BIN_EXE_fake-enclave") {
        Some(path) => path,
        None => panic!("{NEEDS_FAKE}"),
    }
}

/// A store bound to the fake enclave. Reads go through a real broker, and every prompt a person
/// would have seen is written to a log the test reads back
struct Bound {
    cli: Cli,
    log: tempfile::TempDir,
}

impl Bound {
    fn new() -> Self {
        let bound = Bound {
            cli: Cli::empty(),
            log: tempfile::tempdir().unwrap(),
        };
        bound.run(&["init"], None).expect("init");
        bound.run(&["add", "demo/one"], Some("value-one")).unwrap();
        bound.run(&["add", "demo/two"], Some("value-two")).unwrap();
        // Replacing the second name needs the key, so setup raises a prompt of its own
        bound.forget_prompts();
        bound
    }

    fn cmd(&self) -> Command {
        let mut cmd = self.cli.cmd(PASSPHRASE);
        cmd.env_remove("PASSBOX_PASSPHRASE")
            .env("PASSBOX_SE_HELPER", fake_enclave())
            .env("PASSBOX_FAKE_ENCLAVE_LOG", self.log.path().join("prompts"))
            .env("PASSBOX_AGENT", "test-agent");
        cmd
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut child = self
            .cmd()
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
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }

    fn prompts(&self) -> Vec<String> {
        std::fs::read_to_string(self.log.path().join("prompts"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn forget_prompts(&self) {
        let _ = std::fs::remove_file(self.log.path().join("prompts"));
    }

    /// `all` refuses every prompt from here on, a number refuses that many, and `unavailable`
    /// fails the way a closed lid does
    fn deny(&self, how_many: &str) {
        std::fs::write(self.log.path().join("prompts.deny"), how_many).unwrap();
    }

    /// The audit log, read with its own prompt allowed
    fn audit(&self) -> String {
        self.deny("0");
        self.run(&["audit", "--tail", "100"], None).unwrap()
    }
}

/// Whether the audit log holds a record of `decision` for `secret`
fn decided(log: &str, secret: &str, decision: &str) -> bool {
    log.lines().any(|l| {
        l.contains(&format!("\"secret\":\"{secret}\""))
            && l.contains(&format!("\"decision\":\"{decision}\""))
    })
}

const SHOW_AB: &str = "printf %s,%s \"$A\" \"$B\"";

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn every_read_prompts() {
    let bound = Bound::new();
    for _ in 0..2 {
        let out = bound.run(
            &[
                "exec",
                "--env",
                "A=demo/one",
                "--",
                "sh",
                "-c",
                "printf %s \"$A\"",
            ],
            None,
        );
        assert_eq!(out.unwrap(), "value-one");
    }
    assert_eq!(
        bound.prompts(),
        ["release the password for demo/one to test-agent"; 2]
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn listing_prompts() {
    let bound = Bound::new();
    let names = bound.run(&["ls"], None).unwrap();
    assert!(names.contains("one") && names.contains("two"), "{names}");
    assert_eq!(bound.prompts(), ["list your secret names for test-agent"]);
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_grant_prompts_once_and_its_token_reads_without_a_prompt() {
    let bound = Bound::new();
    let token = bound
        .run(&["grant", "demo/one", "demo/two", "--for", "60"], None)
        .unwrap();
    assert_eq!(
        bound.prompts(),
        ["grant demo/one, demo/two to test-agent for 60s"]
    );

    let out = bound
        .cmd()
        .env("PASSBOX_TOKEN", token.trim())
        .args([
            "exec",
            "--env",
            "A=demo/one",
            "--env",
            "B=demo/two",
            "--",
            "sh",
            "-c",
            SHOW_AB,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "value-one,value-two");
    assert_eq!(bound.prompts().len(), 1, "a token read raised a prompt");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn exec_with_many_secrets_prompts_once_through_the_broker() {
    let bound = Bound::new();
    let args = [
        "exec",
        "--env",
        "A=demo/one",
        "--env",
        "B=demo/two",
        "--",
        "sh",
        "-c",
        SHOW_AB,
    ];
    assert_eq!(bound.run(&args, None).unwrap(), "value-one,value-two");
    assert_eq!(
        bound.prompts(),
        ["grant demo/one, demo/two to test-agent for 30s"]
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_denied_prompt_fails_the_read_and_is_audited() {
    let bound = Bound::new();
    bound.deny("1");
    let err = bound
        .run(&["exec", "--env", "A=demo/one", "--", "true"], None)
        .unwrap_err();
    assert!(err.contains("denied"), "{err}");
    assert_eq!(
        bound.prompts(),
        ["release the password for demo/one to test-agent"]
    );

    let log = bound.audit();
    assert!(decided(&log, "demo/one", "denied"), "{log}");
    assert!(!decided(&log, "demo/one", "released"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_prompt_that_cannot_be_shown_is_audited_as_failed() {
    let bound = Bound::new();
    bound.deny("unavailable");
    let err = bound.run(&["ls"], None).unwrap_err();
    assert!(err.contains("unavailable"), "{err}");

    let log = bound.audit();
    assert!(decided(&log, "<list>", "prompt failed"), "{log}");
    assert!(!decided(&log, "<list>", "denied"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn exec_falls_back_to_one_prompt_each_when_the_grant_is_denied() {
    let bound = Bound::new();
    bound.deny("1");
    let args = [
        "exec",
        "--env",
        "A=demo/one",
        "--env",
        "B=demo/two",
        "--",
        "sh",
        "-c",
        SHOW_AB,
    ];
    assert_eq!(bound.run(&args, None).unwrap(), "value-one,value-two");
    assert_eq!(
        bound.prompts(),
        [
            "grant demo/one, demo/two to test-agent for 30s",
            "release the password for demo/one to test-agent",
            "release the password for demo/two to test-agent",
        ]
    );

    // The refused grant is on record for both names, then each read that followed
    let log = bound.audit();
    for name in ["demo/one", "demo/two"] {
        assert!(decided(&log, name, "denied"), "{log}");
        assert!(decided(&log, name, "released"), "{log}");
    }
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn the_audit_log_shows_the_grant_the_token_reads_and_the_prompted_reads() {
    let bound = Bound::new();
    let token = bound
        .run(&["grant", "demo/one", "--for", "60"], None)
        .unwrap();
    let out = bound
        .cmd()
        .env("PASSBOX_TOKEN", token.trim())
        .args(["exec", "--env", "A=demo/one", "--", "true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    bound
        .run(&["exec", "--env", "B=demo/two", "--", "true"], None)
        .unwrap();
    bound.forget_prompts();

    let log = bound.run(&["audit", "--tail", "50"], None).unwrap();
    assert_eq!(bound.prompts(), ["read the audit log"]);
    assert!(decided(&log, "demo/one", "granted"), "{log}");
    assert!(decided(&log, "demo/one", "by token"), "{log}");
    assert!(decided(&log, "demo/two", "released"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_mock_build_aborts_outside_a_cargo_target_directory() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("passbox");
    std::fs::copy(env!("CARGO_BIN_EXE_passbox"), &copy).unwrap();
    let out = Command::new(&copy).arg("--version").output().unwrap();
    assert!(!out.status.success(), "a shipped mock build ran");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("outside a cargo target directory"),
        "{stderr}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn the_fake_enclave_refuses_a_store_outside_the_temp_directory() {
    let outside = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let cli = Cli::empty();
    let out = cli
        .cmd(PASSPHRASE)
        .env("PASSBOX_DIR", outside.path())
        .env_remove("PASSBOX_PASSPHRASE")
        .env("PASSBOX_SE_HELPER", fake_enclave())
        .arg("init")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "the fake ran against a store outside the temp directory"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("outside the temp directory"), "{stderr}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_refused_plugin_run_is_audited() {
    let bound = Bound::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"demo\"\ndescription = \"test\"\n\n[[tool]]\nname = \"say\"\nrun = [\"printf\", \"%s\", \"hi\"]\n",
    )
    .unwrap();
    bound
        .run(&["plugin", "add", src.path().to_str().unwrap()], None)
        .unwrap();
    bound.forget_prompts();

    bound.deny("1");
    let err = bound.run(&["plugin", "demo", "say"], None).unwrap_err();
    assert!(err.contains("denied"), "{err}");
    assert_eq!(bound.run(&["plugin", "demo", "say"], None).unwrap(), "hi");
    assert_eq!(bound.prompts(), ["run plugin:demo.say for test-agent"; 2]);

    let log = bound.audit();
    assert!(decided(&log, "plugin:demo.say", "denied"), "{log}");
    assert!(decided(&log, "plugin:demo.say", "approved"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_refused_project_grant_is_audited_and_an_approved_one_covers_reads() {
    let bound = Bound::new();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".passbox.toml"),
        "secrets = [\"demo/one\", \"demo/two\"]\n",
    )
    .unwrap();
    // The broker finds the manifest from the caller's working directory
    let read = |pair: &str| {
        bound
            .cmd()
            .current_dir(project.path())
            .args(["exec", "--env", pair, "--", "true"])
            .output()
            .unwrap()
    };

    bound.deny("1");
    assert!(
        !read("A=demo/one").status.success(),
        "a refused grant still read"
    );
    let out = read("A=demo/one");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Covered by the grant just approved, so no prompt
    let out = read("B=demo/two");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let prompts = bound.prompts();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        prompts
            .iter()
            .all(|p| p.starts_with("give test-agent access to 2 secrets declared by")),
        "{prompts:?}"
    );

    let log = bound.audit();
    for name in ["demo/one", "demo/two"] {
        assert!(decided(&log, name, "denied"), "{log}");
        assert!(decided(&log, name, "project grant"), "{log}");
    }
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn copy_reads_through_the_broker_and_never_prints_the_value() {
    let bound = Bound::new();
    let out = bound
        .cmd()
        .args(["copy", "demo/one", "--clear", "7"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(out.stdout.is_empty(), "copy printed to stdout");
    assert!(!stderr.contains("value-one"), "{stderr}");
    assert_eq!(
        bound.prompts(),
        ["release the password for demo/one to test-agent"]
    );

    let clipboard = bound.log.path().join("prompts.clipboard");
    assert_eq!(std::fs::read_to_string(&clipboard).unwrap(), "value-one");
    let clear = bound.log.path().join("prompts.clear");
    assert_eq!(std::fs::read_to_string(clear).unwrap(), "7");

    let log = bound.audit();
    assert!(decided(&log, "demo/one", "released"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_refused_copy_puts_nothing_on_the_clipboard() {
    let bound = Bound::new();
    bound.deny("1");
    let err = bound.run(&["copy", "demo/one"], None).unwrap_err();
    assert!(err.contains("denied"), "{err}");
    assert!(!bound.log.path().join("prompts.clipboard").exists());

    let log = bound.audit();
    assert!(decided(&log, "demo/one", "denied"), "{log}");
}
