//! Drives the built binary, so it covers what unit tests cannot: argument handling and exit codes.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
        // Nor the developer's git config, which may sign every commit through a password manager
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
        // A CI runner has no git identity, and the store commits after a write
        for (key, value) in [
            ("GIT_AUTHOR_NAME", "passbox test"),
            ("GIT_AUTHOR_EMAIL", "test@passbox.invalid"),
            ("GIT_COMMITTER_NAME", "passbox test"),
            ("GIT_COMMITTER_EMAIL", "test@passbox.invalid"),
        ] {
            cmd.env(key, value);
        }
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

    /// A value, read the way a program reads one, since `get` refuses a pipe
    fn read(&self, name: &str) -> Result<String, String> {
        self.read_as(PASSPHRASE, name)
    }

    fn read_as(&self, passphrase: &str, name: &str) -> Result<String, String> {
        let env = format!("V={name}");
        self.run_as(
            passphrase,
            &[&["exec", "--env", &env], &PRINT_V[..]].concat(),
            None,
        )
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

/// `exec` hands the value to a child that prints it, which is how a test sees what was stored
const PRINT_V: [&str; 4] = ["--", "sh", "-c", "printf %s \"$V\""];

#[test]
fn add_get_and_list() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();
    cli.run(&["add", "banking/login"], Some("swordfish"))
        .unwrap();

    assert_eq!(cli.read("github/token").unwrap(), "ghp_abc");
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "banking/login\ngithub/token\n"
    );
}

#[test]
fn get_refuses_a_capture() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    // stdout is a pipe in the harness, the same shape as an agent capturing the value
    let err = cli.run(&["get", "a/b"], None).unwrap_err();
    assert!(err.contains("not a terminal"), "{err}");
    assert!(err.contains("passbox copy"), "{err}");
    assert!(!err.contains("--reveal"), "{err}");
    // The override is gone, so it is an unknown argument
    let err = cli.run(&["get", "--reveal", "a/b"], None).unwrap_err();
    assert!(err.contains("unexpected argument '--reveal'"), "{err}");
}

/// The terminal path, reached through the pseudo-terminal `script` opens
#[test]
fn get_prints_at_a_terminal() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("at-a-terminal")).unwrap();
    let bin = env!("CARGO_BIN_EXE_passbox");
    let mut script = Command::new("script");
    script.envs(
        cli.cmd(PASSPHRASE)
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_owned(), v?.to_owned()))),
    );
    // BSD script takes the command as arguments, util-linux takes one string
    if cfg!(target_os = "macos") {
        script.args(["-q", "/dev/null", bin, "get", "a/b"]);
    } else {
        script.args(["-qec", &format!("'{bin}' get a/b"), "/dev/null"]);
    }

    let out = script.stdin(Stdio::null()).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("at-a-terminal"), "{stdout}");
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
    assert_eq!(cli.read("a/b").unwrap(), "v");
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

const IMAP_PW: &str = "hunter2-imap-pw";

/// An account on a port nothing listens on, so the script fails to connect and no mail server is used
fn imap_account() -> String {
    format!("{IMAP_PW}\nhost: 127.0.0.1\nport: 1\nuser: me@example.com\ntls: ssl\n")
}

/// A plugin of our own that asks for a secret on stdin and would print it
fn fed_plugin(add: impl Fn(&[&str])) -> tempfile::TempDir {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"demo\"\ndescription = \"test\"\nstdin = \"demo/one\"\n\n\
         [[tool]]\nname = \"leak\"\nrun = [\"cat\"]\n",
    )
    .unwrap();
    add(&["plugin", "add", src.path().to_str().unwrap()]);
    src
}

#[test]
fn the_headless_path_feeds_the_bundled_imap_script_and_prints_scrubbed_output() {
    let cli = Cli::new();
    cli.note(&["plugin", "add", "imap"], None);

    let err = cli.run(&["plugin", "imap", "recent"], None).unwrap_err();
    assert!(err.contains("needs the secret mail/imap"), "{err}");

    cli.run(&["add", "mail/imap"], Some(&imap_account()))
        .unwrap();
    let out = cli.run(&["plugin", "imap", "recent"], None).unwrap();
    // The script got the account on stdin, since it went on to connect
    assert!(out.contains("ConnectionRefusedError"), "{out}");
    assert!(out.contains("exit: 1"), "{out}");
    assert!(!out.contains(IMAP_PW), "{out}");
}

#[test]
fn a_stdin_plugin_that_is_not_the_bundled_copy_is_refused() {
    let cli = Cli::new();
    cli.run(&["add", "demo/one"], Some("value-one")).unwrap();
    let _src = fed_plugin(|args| {
        cli.note(args, None);
    });
    let err = cli.run(&["plugin", "demo", "leak"], None).unwrap_err();
    assert!(
        err.contains("reinstall it with `passbox plugin update demo`"),
        "{err}"
    );
    assert!(!err.contains("value-one"), "{err}");
}

#[test]
fn a_first_party_plugin_installs_by_name() {
    let cli = Cli::new();
    cli.note(&["plugin", "add", "things3"], None);
    let list = cli.run(&["plugin", "list"], None).unwrap();
    assert!(list.contains("things3 logbook"), "{list}");
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
        .replace("version = \"2.1.1\"", "version = \"0.1.0\"");
    std::fs::write(&toml, older).unwrap();
    let list = cli.run(&["plugin", "list"], None).unwrap();
    assert!(list.contains("update available: 0.1.0 -> 2.1.1"), "{list}");
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
    cli.read("a/one").unwrap();
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
    cli.read("github/token").unwrap();

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
fn add_refuses_an_existing_name() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("good")).unwrap();
    let err = cli.run(&["add", "github/token"], Some("bad")).unwrap_err();
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(cli.read("github/token").unwrap(), "good");
}

#[test]
fn a_replaced_value_is_recoverable() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("good")).unwrap();
    cli.run(&["rm", "github/token"], None).unwrap();
    cli.run(&["add", "github/token"], Some("bad")).unwrap();
    assert_eq!(cli.read("github/token").unwrap(), "bad");

    cli.run(&["restore", "github/token", "--index", "0"], None)
        .unwrap();
    assert_eq!(cli.read("github/token").unwrap(), "good");
}

#[test]
fn a_deleted_secret_is_still_recoverable() {
    let cli = Cli::new();
    cli.run(&["add", "banking/login"], Some("swordfish"))
        .unwrap();
    cli.run(&["rm", "banking/login"], None).unwrap();

    assert_eq!(cli.run(&["ls"], None).unwrap(), "");
    assert!(cli.read("banking/login").is_err());

    cli.run(&["restore", "banking/login", "--index", "0"], None)
        .unwrap();
    assert_eq!(cli.read("banking/login").unwrap(), "swordfish");
}

#[test]
fn a_wrong_passphrase_is_refused() {
    let cli = Cli::new();
    cli.run(&["add", "github/token"], Some("ghp_abc")).unwrap();

    let err = cli.read_as("wrong", "github/token").unwrap_err();
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
    assert_eq!(two.read("github/token").unwrap(), "ghp_abc");

    two.run(&["rm", "github/token"], None).unwrap();
    two.sync(remote.path());
    one.sync(remote.path());
    assert_eq!(one.run(&["ls"], None).unwrap(), "");

    one.run(&["restore", "github/token", "--index", "0"], None)
        .unwrap();
    assert_eq!(one.read("github/token").unwrap(), "ghp_abc");
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

/* pass entries carry `key: value` lines under the password, and `get --field` reads them, so
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

    let body = cli.read("bean/hl-mainnet-pk").unwrap();
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

/// A client run with a configured host and the given stdin, for `--token-stdin`
fn on_host_stdin(cli: &Cli, host: &str, stdin: &str, args: &[&str]) -> (bool, String, String) {
    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.env("PASSBOX_HOST", host).env_remove("PASSBOX_TOKEN");
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn a_token_on_stdin_asks_for_a_child_and_leaves_the_rest_to_the_exec_child() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["op"].as_str() {
        Some("grant") if r["token"] == "parent-tok" => Ok("child-tok\na/b".into()),
        Some("get") if r["token"] == "child-tok" => Ok("v".into()),
        _ => Err("a request without the token from stdin".into()),
    });

    let (ok, stdout, stderr) = on_host_stdin(
        &cli,
        &host,
        "parent-tok\n",
        &["grant", "--token-stdin", "a/b"],
    );
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "child-tok\n");
    assert!(
        !stderr.contains("parent-tok") && !stderr.contains("child-tok"),
        "a token leaked to stderr: {stderr}"
    );
    let seen = ops(&requests);
    // No --for asks for the parent's expiry
    assert_eq!(seen[0]["ttl"], 0);

    let args = [
        "exec",
        "--token-stdin",
        "--env",
        "A=a/b",
        "--",
        "sh",
        "-c",
        "printf %s, \"$A\"; cat",
    ];
    let (ok, stdout, stderr) = on_host_stdin(&cli, &host, "child-tok\nrest", &args);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v,rest");
    assert!(
        !stderr.contains("child-tok"),
        "the token leaked to stderr: {stderr}"
    );
    let kinds: Vec<String> = ops(&requests)
        .iter()
        .map(|r| r["op"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["get"]);
}

#[test]
fn a_token_on_stdin_needs_a_first_line_and_no_newline_after_it() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["token"].as_str() {
        Some("parent-tok") => Ok("child-tok\na/b".into()),
        _ => Err("a request without the token from stdin".into()),
    });
    let grant = ["grant", "--token-stdin", "a/b"];
    let exec = ["exec", "--token-stdin", "--env", "A=a/b", "--", "true"];

    // EOF, an empty first line or a blank one is refused before the host is asked
    for stdin in ["", "\n", "\nparent-tok\n", "  \n"] {
        for args in [&grant[..], &exec[..]] {
            let (ok, _, stderr) = on_host_stdin(&cli, &host, stdin, args);
            assert!(!ok, "{stdin:?} {args:?}");
            assert!(stderr.contains("--token-stdin read no token"), "{stderr}");
        }
    }
    assert!(ops(&requests).is_empty());

    let (ok, stdout, stderr) = on_host_stdin(&cli, &host, "parent-tok", &grant);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "child-tok\n");
    assert_eq!(ops(&requests)[0]["token"], "parent-tok");
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
        // Adding the second name needs the key to check it is new, so setup raises a prompt
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

    fn read(&self, name: &str) -> Result<String, String> {
        let env = format!("V={name}");
        self.run(&[&["exec", "--env", &env], &PRINT_V[..]].concat(), None)
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

    /// Every prompt from here on stays open until the guard drops, as when nobody is at the Mac
    fn hold(&self) -> Held<'_> {
        std::fs::write(self.log.path().join("prompts.hold"), "").unwrap();
        Held(self)
    }

    fn wait_for_prompts(&self, count: usize) {
        let until = Instant::now() + Duration::from_secs(10);
        while self.prompts().len() < count {
            assert!(
                Instant::now() < until,
                "no prompt arrived: {:?}",
                self.prompts()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
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

/// Closes the held prompt when dropped, so a failing assertion cannot leave a test hanging
struct Held<'a>(&'a Bound);

impl Held<'_> {
    fn release(&self) {
        let _ = std::fs::remove_file(self.0.log.path().join("prompts.hold"));
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/* A prompt left open stops nothing that needs no prompt. A token read is answered at once,
and a second read that does need a prompt waits for the open one instead of raising its own. */
#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_prompt_left_open_holds_up_no_token_read_and_raises_no_second_prompt() {
    let bound = Bound::new();
    let token = bound
        .run(&["grant", "demo/one", "--for", "60"], None)
        .unwrap();
    let token = token.trim();
    bound.forget_prompts();

    std::thread::scope(|scope| {
        let held = bound.hold();
        let first = scope.spawn(|| bound.read("demo/two"));
        bound.wait_for_prompts(1);
        let second = scope.spawn(|| bound.read("demo/two"));

        let mut read = bound
            .cmd()
            .env("PASSBOX_TOKEN", token)
            .args(["exec", "--env", "V=demo/one"])
            .args(PRINT_V)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while read.try_wait().unwrap().is_none() {
            if Instant::now() > until {
                let _ = read.kill();
                panic!("a token read waited behind the open prompt");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = read.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "value-one");

        // Long enough for the second read to reach the broker and queue
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            bound.prompts().len(),
            1,
            "a second dialog: {:?}",
            bound.prompts()
        );

        held.release();
        assert_eq!(first.join().unwrap().unwrap(), "value-two");
        assert_eq!(second.join().unwrap().unwrap(), "value-two");
    });
    assert_eq!(bound.prompts().len(), 2, "{:?}", bound.prompts());
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

/// One request line straight to the broker's socket, and its reply line
fn ask_socket(bound: &Bound, request: &str) -> String {
    let mut stream = std::os::unix::net::UnixStream::connect(bound.cli.path().join("broker.sock"))
        .expect("the broker is up");
    writeln!(stream, "{request}").unwrap();
    let mut reply = String::new();
    std::io::BufReader::new(stream)
        .read_line(&mut reply)
        .unwrap();
    reply
}

/// A store with the imap plugin and its account, and a running broker, with no prompt logged
fn bound_with_imap() -> Bound {
    let bound = Bound::new();
    bound.run(&["plugin", "add", "imap"], None).unwrap();
    bound
        .run(&["add", "mail/imap"], Some(&imap_account()))
        .unwrap();
    // A list goes through the broker, so this starts it for a test that talks to its socket
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();
    bound
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_stdin_plugin_runs_in_the_broker_and_names_and_audits_its_secret() {
    let bound = bound_with_imap();
    let out = bound.run(&["plugin", "imap", "recent"], None).unwrap();
    assert!(out.contains("ConnectionRefusedError"), "{out}");
    assert!(!out.contains(IMAP_PW), "{out}");
    assert_eq!(
        bound.prompts(),
        ["run plugin:imap.recent for test-agent, releasing mail/imap"]
    );
    let log = bound.audit();
    assert!(decided(&log, "plugin:imap.recent", "approved"), "{log}");
    assert!(decided(&log, "mail/imap", "released"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_approval_only_request_for_a_stdin_plugin_is_refused_and_no_reply_holds_the_secret() {
    let bound = bound_with_imap();
    let approve = r#"{"name":"imap","agent":"raw","op":"plugin","action":"recent","run":false}"#;
    let reply = ask_socket(&bound, approve);
    assert!(reply.contains("runs on the broker"), "{reply}");
    assert!(reply.contains("\"ok\":false"), "{reply}");
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());

    let run = r#"{"name":"imap","agent":"raw","op":"plugin","action":"recent","run":true}"#;
    let reply = ask_socket(&bound, run);
    assert!(reply.contains("ConnectionRefusedError"), "{reply}");
    for (piece, at) in [(IMAP_PW, "the password"), ("127.0.0.1\\nport", "the entry")] {
        assert!(!reply.contains(piece), "{at} in {reply}");
    }
    assert_eq!(bound.prompts().len(), 1, "{:?}", bound.prompts());
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_tampered_or_foreign_stdin_plugin_is_refused_before_the_prompt() {
    let bound = bound_with_imap();
    let dir = bound.cli.path().join("plugins/imap");
    let refused = |what: &str| {
        let err = bound.run(&["plugin", "imap", "recent"], None).unwrap_err();
        assert!(
            err.contains("reinstall it with `passbox plugin update imap`"),
            "{what}: {err}"
        );
        assert!(bound.prompts().is_empty(), "{what}: {:?}", bound.prompts());
    };

    let script = std::fs::read_to_string(dir.join("imap.py")).unwrap();
    std::fs::write(
        dir.join("imap.py"),
        format!("{script}\nprint(sys.stdin.read().encode().hex())\n"),
    )
    .unwrap();
    refused("an edited script");

    bound.run(&["plugin", "update", "imap"], None).unwrap();
    let manifest = std::fs::read_to_string(dir.join("plugin.toml")).unwrap();
    std::fs::write(
        dir.join("plugin.toml"),
        manifest.replace("\"mail/imap\"", "\"demo/one\""),
    )
    .unwrap();
    refused("a manifest mapping another secret");

    bound.run(&["plugin", "update", "imap"], None).unwrap();
    std::fs::remove_file(dir.join("imap.py")).unwrap();
    refused("a missing script");

    let _src = fed_plugin(|args| {
        bound.run(args, None).unwrap();
    });
    let err = bound.run(&["plugin", "demo", "leak"], None).unwrap_err();
    assert!(
        err.contains("reinstall it with `passbox plugin update demo`"),
        "{err}"
    );
    assert!(!err.contains("value-one"), "{err}");
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_plugin_without_stdin_still_runs_in_the_caller_after_an_approval() {
    let bound = Bound::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"demo\"\ndescription = \"test\"\n\n\
         [[tool]]\nname = \"where\"\nrun = [\"sh\", \"-c\", \"printf %s \\\"$ONLY_CALLER\\\"\"]\n",
    )
    .unwrap();
    bound
        .run(&["plugin", "add", src.path().to_str().unwrap()], None)
        .unwrap();
    // Start the broker first, so it cannot inherit the variable only the caller has
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();

    let out = bound
        .cmd()
        .env("ONLY_CALLER", "in-the-caller")
        .args(["plugin", "demo", "where"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "in-the-caller");
    assert_eq!(bound.prompts(), ["run plugin:demo.where for test-agent"]);

    let approve = r#"{"name":"demo","agent":"raw","op":"plugin","action":"where","run":false}"#;
    assert!(ask_socket(&bound, approve).contains("\"value\":\"ok\""));
}

/// A plugin of our own with two reads and one action, installed with the broker up and no prompt logged
fn bound_with_reads() -> (Bound, tempfile::TempDir) {
    let bound = Bound::new();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(
        src.path().join("plugin.toml"),
        "name = \"demo\"\ndescription = \"test\"\n\n\
         [[tool]]\nname = \"a\"\nrun = [\"printf\", \"read a\"]\n\n\
         [[tool]]\nname = \"b\"\nrun = [\"printf\", \"read b\"]\n\n\
         [[tool]]\nname = \"act\"\nrun = [\"printf\", \"acted\"]\n\n\
         [[tool]]\nname = \"search\"\nparams = [\"query\", \"mailbox?\"]\n\
         limits = { query = { max_len = 10 } }\n\
         run = [\"printf\", \"%s|%s\", \"{query}\", \"{mailbox}\"]\n\n\
         [[tool]]\nname = \"read\"\nparams = [\"id\"]\n\
         run = [\"printf\", \"%s\", \"{id}\"]\n",
    )
    .unwrap();
    bound
        .run(&["plugin", "add", src.path().to_str().unwrap()], None)
        .unwrap();
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();
    (bound, src)
}

fn set_windows(bound: &Bound, section: &str) {
    std::fs::write(
        bound.cli.path().join("config.toml"),
        format!("[plugins.windows]\n{section}\n"),
    )
    .unwrap();
}

fn count(log: &str, secret: &str, decision: &str) -> usize {
    log.lines()
        .filter(|l| {
            l.contains(&format!("\"secret\":\"{secret}\""))
                && l.contains(&format!("\"decision\":\"{decision}\""))
        })
        .count()
}

const RUN_A: &str = "run plugin:demo.a for test-agent";

/// Audit records for one slot and decision that carry these arguments
fn count_args(log: &str, secret: &str, decision: &str, args: &str) -> usize {
    let args = format!("\"args\":{}", serde_json::to_string(args).unwrap());
    log.lines()
        .filter(|l| {
            l.contains(&format!("\"secret\":\"{secret}\""))
                && l.contains(&format!("\"decision\":\"{decision}\""))
                && l.contains(&args)
        })
        .count()
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn local_cli_approval_sends_the_params_and_the_prompt_shows_them() {
    let (bound, _src) = bound_with_reads();
    let out = bound.run(
        &[
            "plugin",
            "demo",
            "search",
            "--query",
            "invoice",
            "--mailbox",
            "INBOX",
        ],
        None,
    );
    assert_eq!(out.unwrap(), "invoice|INBOX");
    assert_eq!(
        bound.prompts(),
        ["run plugin:demo.search query=\"invoice\" mailbox=\"INBOX\" for test-agent"]
    );

    // A missing required parameter is refused by the broker before any prompt
    bound.forget_prompts();
    let approve = r#"{"name":"demo","agent":"raw","op":"plugin","action":"search","run":false}"#;
    assert!(ask_socket(&bound, approve).contains("needs --query"));
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_argument_over_its_limit_is_refused_before_the_prompt_on_every_path() {
    let (bound, _src) = bound_with_reads();
    let err = bound
        .run(
            &["plugin", "demo", "search", "--query", "elevenchars"],
            None,
        )
        .unwrap_err();
    assert!(err.contains("query must be at most 10 characters"), "{err}");
    let raw = r#"{"name":"demo","agent":"raw","op":"plugin","action":"search","params":[["query","elevenchars"]],"run":true}"#;
    assert!(ask_socket(&bound, raw).contains("at most 10 characters"));
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());
    assert_eq!(
        bound
            .run(&["plugin", "demo", "search", "--query", "tenchars10"], None)
            .unwrap(),
        "tenchars10|"
    );

    let bound = bound_with_imap();
    for (args, why) in [
        (&["read", "--id", "1:*"][..], "id must be digits only"),
        (&["recent", "--count", "51"][..], "at most 50"),
    ] {
        let err = bound
            .run(&[&["plugin", "imap"], args].concat(), None)
            .unwrap_err();
        assert!(err.contains(why), "{args:?}: {err}");
    }
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_window_covers_the_exact_call_and_any_other_argument_prompts() {
    let (bound, _src) = bound_with_reads();
    set_windows(&bound, "\"demo.search\" = \"1h\"\n\"demo.read\" = \"1h\"");
    let search = |args: &[&str]| {
        bound
            .run(&[&["plugin", "demo", "search"], args].concat(), None)
            .unwrap()
    };
    let prompted = |what: &str, expected: usize| {
        assert_eq!(
            bound.prompts().len(),
            expected,
            "{what}: {:?}",
            bound.prompts()
        );
    };

    assert_eq!(search(&["--query", "invoice"]), "invoice|");
    assert_eq!(
        bound.prompts(),
        [
            "allow plugin windows demo.read 1h, demo.search 1h for test-agent, \
          then run plugin:demo.search query=\"invoice\" for test-agent"
        ]
    );
    search(&["--query", "invoice"]);
    prompted("the same call", 1);
    search(&["--query", "invoice", "--mailbox", ""]);
    prompted("an empty optional is the omitted one", 1);

    search(&["--query", "receipt"]);
    prompted("another query", 2);
    search(&["--query", "receipt"]);
    prompted("the second query has its own window", 2);
    search(&["--query", "invoice"]);
    prompted("the first window is still open", 2);
    search(&["--query", "invoice", "--mailbox", "Archive"]);
    prompted("another mailbox", 3);

    let read = |id: &str| {
        bound
            .run(&["plugin", "demo", "read", "--id", id], None)
            .unwrap()
    };
    assert_eq!(read("42"), "42");
    read("42");
    prompted("one message id", 4);
    read("43");
    prompted("another message id", 5);

    let log = bound.audit();
    let invoice = "query=\"invoice\"";
    assert_eq!(
        count_args(&log, "plugin:demo.search", "approved", invoice),
        1,
        "{log}"
    );
    assert_eq!(
        count_args(&log, "plugin:demo.search", "by window", invoice),
        3,
        "{log}"
    );
    assert_eq!(
        count_args(&log, "plugin:demo.read", "approved", "id=\"43\""),
        1,
        "{log}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_fed_plugin_window_is_bound_by_its_arguments_and_still_feeds_its_secret() {
    let bound = bound_with_imap();
    set_windows(&bound, "\"imap.search\" = \"1h\"\n\"imap.read\" = \"1h\"");
    let run = |args: &[&str]| {
        let out = bound
            .run(&[&["plugin", "imap"], args].concat(), None)
            .unwrap();
        // The script got the account on stdin, since it went on to connect
        assert!(out.contains("ConnectionRefusedError"), "{out}");
        assert!(!out.contains(IMAP_PW), "{out}");
    };
    let prompted = |what: &str, expected: usize| {
        assert_eq!(
            bound.prompts().len(),
            expected,
            "{what}: {:?}",
            bound.prompts()
        );
    };

    run(&["search", "--query", "invoice", "--mailbox", "INBOX"]);
    assert_eq!(
        bound.prompts(),
        [
            "allow plugin windows imap.read 1h, imap.search 1h for test-agent, then run \
          plugin:imap.search query=\"invoice\" mailbox=\"INBOX\" for test-agent, releasing mail/imap"
        ]
    );
    run(&["search", "--query", "invoice", "--mailbox", "INBOX"]);
    prompted("the same call", 1);
    run(&["search", "--query", "receipt", "--mailbox", "INBOX"]);
    prompted("another query", 2);
    run(&["search", "--query", "invoice", "--mailbox", "Archive"]);
    prompted("another mailbox", 3);
    run(&["read", "--id", "42"]);
    run(&["read", "--id", "42", "--mailbox", ""]);
    prompted("one message id", 4);
    run(&["read", "--id", "43"]);
    prompted("another message id", 5);

    let log = bound.audit();
    let call = "query=\"invoice\" mailbox=\"INBOX\"";
    assert_eq!(
        count_args(&log, "plugin:imap.search", "approved", call),
        1,
        "{log}"
    );
    assert_eq!(
        count_args(&log, "plugin:imap.search", "by window", call),
        1,
        "{log}"
    );
    assert_eq!(count_args(&log, "mail/imap", "released", call), 2, "{log}");
    assert_eq!(count(&log, "mail/imap", "released"), 7, "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn with_no_window_every_plugin_call_prompts() {
    let (bound, _src) = bound_with_reads();
    for _ in 0..3 {
        assert_eq!(bound.run(&["plugin", "demo", "a"], None).unwrap(), "read a");
    }
    assert_eq!(bound.prompts(), [RUN_A; 3]);
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_window_skips_the_prompt_until_it_ends_and_is_audited() {
    let (bound, _src) = bound_with_reads();
    set_windows(&bound, "\"demo.a\" = \"3s\"");
    for _ in 0..3 {
        assert_eq!(bound.run(&["plugin", "demo", "a"], None).unwrap(), "read a");
    }
    assert_eq!(
        bound.prompts(),
        [format!(
            "allow plugin windows demo.a 3s for test-agent, then {RUN_A}"
        )]
    );
    // A tool the section does not name still prompts
    bound.run(&["plugin", "demo", "b"], None).unwrap();
    assert_eq!(bound.prompts().len(), 2, "{:?}", bound.prompts());

    std::thread::sleep(Duration::from_millis(3_200));
    bound.forget_prompts();
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    assert_eq!(bound.prompts(), [RUN_A], "an ended window prompts");

    let log = bound.audit();
    assert_eq!(count(&log, "plugin:demo.a", "by window"), 2, "{log}");
    assert_eq!(count(&log, "plugin:demo.a", "approved"), 2, "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_bad_window_key_is_refused_before_any_prompt() {
    let (bound, _src) = bound_with_reads();
    for (section, why) in [
        ("demo = \"1h\"", "one plugin and one tool"),
        ("\"*\" = \"1h\"", "one plugin and one tool"),
        ("\"demo.*\" = \"1h\"", "one plugin and one tool"),
        ("\"other.a\" = \"1h\"", "not installed"),
    ] {
        set_windows(&bound, section);
        let err = bound.run(&["plugin", "demo", "a"], None).unwrap_err();
        assert!(err.contains(why), "{section}: {err}");
        assert!(err.contains("config.toml is not valid"), "{section}: {err}");
    }
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_edited_section_waits_for_its_prompt_and_a_refusal_keeps_the_old_one() {
    let (bound, _src) = bound_with_reads();
    let first = "\"demo.a\" = \"1h\"";
    set_windows(&bound, first);
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    assert_eq!(bound.prompts().len(), 1, "{:?}", bound.prompts());

    // The edit lists both windows, and until it is approved the open window does not apply
    bound.forget_prompts();
    set_windows(&bound, &format!("{first}\n\"demo.b\" = \"1h\""));
    bound.deny("1");
    assert!(bound.run(&["plugin", "demo", "a"], None).is_err());
    assert_eq!(
        bound.prompts(),
        [format!(
            "allow plugin windows demo.a 1h, demo.b 1h for test-agent, then {RUN_A}"
        )]
    );

    // Refused, so the old section still applies and its window is still open
    bound.forget_prompts();
    set_windows(&bound, first);
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());

    // Approved, so the edit applies
    set_windows(&bound, &format!("{first}\n\"demo.b\" = \"1h\""));
    bound.run(&["plugin", "demo", "b"], None).unwrap();
    bound.run(&["plugin", "demo", "b"], None).unwrap();
    assert_eq!(bound.prompts().len(), 1, "{:?}", bound.prompts());
    assert!(bound.prompts()[0].starts_with("allow plugin windows demo.a 1h, demo.b 1h"));
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn the_approved_section_survives_a_broker_restart_and_its_windows_do_not() {
    let (bound, _src) = bound_with_reads();
    set_windows(&bound, "\"demo.a\" = \"1h\"");
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    assert_eq!(bound.prompts().len(), 1, "{:?}", bound.prompts());

    // A request that finds no socket starts a new broker, with nothing of the old one in memory
    std::fs::remove_file(bound.cli.path().join("broker.sock")).unwrap();
    bound.forget_prompts();
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    bound.run(&["plugin", "demo", "a"], None).unwrap();
    assert_eq!(bound.prompts(), [RUN_A], "asked again for the section");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_fed_plugin_in_a_window_still_feeds_its_secret_and_returns_none() {
    let bound = bound_with_imap();
    set_windows(&bound, "\"imap.recent\" = \"1h\"");
    for _ in 0..2 {
        let out = bound.run(&["plugin", "imap", "recent"], None).unwrap();
        // The script got the account on stdin, since it went on to connect
        assert!(out.contains("ConnectionRefusedError"), "{out}");
        assert!(!out.contains(IMAP_PW), "{out}");
    }
    assert_eq!(bound.prompts().len(), 1, "{:?}", bound.prompts());

    let log = bound.audit();
    assert_eq!(count(&log, "plugin:imap.recent", "by window"), 1, "{log}");
    assert_eq!(count(&log, "mail/imap", "released"), 2, "{log}");

    // The bundled copy is still checked on every call in the window
    let script = bound.cli.path().join("plugins/imap/imap.py");
    let code = std::fs::read_to_string(&script).unwrap();
    std::fs::write(&script, format!("{code}\nprint(sys.stdin.read())\n")).unwrap();
    let err = bound.run(&["plugin", "imap", "recent"], None).unwrap_err();
    assert!(err.contains("reinstall it with"), "{err}");
    assert!(!err.contains(IMAP_PW), "{err}");
}

/// Runs an OpenSSH tool against the broker's agent socket, and never the developer's own agent
fn with_agent(bound: &Bound, program: &str, args: &[&str]) -> std::process::Output {
    Command::new(program)
        .args(args)
        .env("SSH_AUTH_SOCK", bound.cli.dir.path().join("ssh-agent.sock"))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn the_ssh_agent_offers_a_stored_key_and_every_signature_prompts() {
    for kind in ["ed25519", "ecdsa"] {
        agent_round_trip(kind);
    }
}

fn agent_round_trip(kind: &str) {
    let bound = Bound::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("id");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", kind, "-N", "", "-C", "test@passbox.dev", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let private = std::fs::read_to_string(&path).unwrap();
    bound.run(&["add", "ssh/test"], Some(&private)).unwrap();
    // Starts the broker, which serves the agent socket beside its own
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();

    let listed = with_agent(&bound, "ssh-add", &["-L"]);
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        public.trim()
    );
    assert!(bound.prompts().is_empty(), "{:?}", bound.prompts());

    let pubkey = path.with_extension("pub");
    let sign = |message: &Path| {
        std::fs::write(message, "signed through passbox").unwrap();
        with_agent(
            &bound,
            "ssh-keygen",
            &[
                "-Y",
                "sign",
                "-n",
                "test",
                "-f",
                pubkey.to_str().unwrap(),
                message.to_str().unwrap(),
            ],
        )
    };
    let message = keys.path().join("message");
    for target in [&message, &keys.path().join("again")] {
        let signed = sign(target);
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
    }
    let prompts = bound.prompts();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(
        prompts[0].starts_with("sign a test signature with SSH key test@passbox.dev for "),
        "{prompts:?}"
    );

    let checked = Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "test", "-s"])
        .arg(message.with_extension("sig"))
        .stdin(std::fs::File::open(&message).unwrap())
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );

    bound.deny("all");
    assert!(!sign(&keys.path().join("refused")).status.success());
    let log = bound.audit();
    assert!(decided(&log, "ssh/test", "signed"), "{log}");
    assert!(decided(&log, "ssh:test@passbox.dev", "denied"), "{log}");
}

#[test]
fn rm_and_restore_rebuild_the_offered_ssh_keys() {
    let cli = Cli::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("id");
    let made = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "rm@passbox.dev",
            "-f",
        ])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let private = std::fs::read_to_string(&path).unwrap();
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    let offered = || std::fs::read_to_string(cli.path().join("ssh-keys.pub")).unwrap_or_default();

    cli.run(&["add", "ssh/test"], Some(&private)).unwrap();
    cli.run(&["add", "plain"], Some("not a key")).unwrap();
    assert_eq!(offered().trim(), public.trim());

    cli.run(&["rm", "plain"], None).unwrap();
    assert_eq!(offered().trim(), public.trim());

    cli.run(&["rm", "ssh/test"], None).unwrap();
    assert_eq!(offered().trim(), "");

    cli.run(&["restore", "ssh/test", "--index", "0"], None)
        .unwrap();
    assert_eq!(offered().trim(), public.trim());
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

#[test]
fn copy_clears_within_a_minute_and_refuses_anything_longer() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();
    // Each fails on the argument, before anything is read or copied
    for bad in ["61", "3600", "0"] {
        let err = cli.run(&["copy", "a/b", "--clear", bad], None).unwrap_err();
        assert!(err.contains("1..=60"), "--clear {bad}: {err}");
    }
}

/* A fake age-plugin-yubikey on a PATH without the real one, ykman or brew, so no test reaches a
token. It logs its arguments, and every case here stops before the store key is unlocked */
fn yubikey_add(cli: &Cli, list: &str, exit: u8, args: &[&str]) -> (bool, String, String) {
    let fake = tempfile::tempdir().unwrap();
    let log = fake.path().join("calls");
    let shim = fake.path().join("age-plugin-yubikey");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\n[ \"$1\" = --list ] || exit 0\nprintf '%s' '{list}'\necho 'pcsc: no reader' >&2\nexit {exit}\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let out = cli
        .cmd(PASSPHRASE)
        .env("PATH", format!("{}:/usr/bin:/bin", fake.path().display()))
        .arg("yubikey-add")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let calls = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !calls.contains("--generate"),
        "a test generated on a token: {calls}"
    );
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        calls,
    )
}

#[test]
fn yubikey_add_without_a_token_offers_setup_and_stops_without_a_terminal() {
    let cli = Cli::new();
    for list in ["", "garbage\nage1yubi\n"] {
        let (ok, err, _) = yubikey_add(&cli, list, 0, &[]);
        assert!(!ok);
        assert!(err.contains("No age identity on the token yet"), "{err}");
        assert!(
            err.contains("age-plugin-yubikey --generate` when ready"),
            "{err}"
        );
    }
}

#[test]
fn yubikey_add_refuses_when_the_plugin_list_fails() {
    let cli = Cli::new();
    let (ok, err, _) = yubikey_add(&cli, "age1yubikey1aaa\n", 1, &[]);
    assert!(!ok);
    assert!(err.contains("--list failed: pcsc: no reader"), "{err}");
    assert!(!err.contains("No age identity"), "{err}");
}

#[test]
fn yubikey_add_with_several_new_tokens_needs_a_terminal() {
    let cli = Cli::new();
    let list = "#  Serial: 1, Slot: 1\nage1yubikey1aaa\n#  Serial: 2, Slot: 1\nage1yubikey1bbb\n";
    let (ok, err, _) = yubikey_add(&cli, list, 0, &[]);
    assert!(!ok);
    assert!(err.contains("several new tokens are plugged in"), "{err}");
}

#[test]
fn yubikey_add_with_only_stored_tokens_plugged_does_not_set_one_up() {
    let cli = Cli::new();
    let wraps = cli.path().join("wraps");
    std::fs::create_dir_all(&wraps).unwrap();
    std::fs::write(
        wraps.join("yubikey.recipients"),
        "age1yubikey1aaa\nage1yubikey1bbb\n",
    )
    .unwrap();

    let list = "age1yubikey1aaa\nage1yubikey1bbb\nage1yubikey1aaa\n";
    let (ok, err, _) = yubikey_add(&cli, list, 0, &[]);
    assert!(!ok);
    assert!(err.contains("the 2 plugged token(s) already open"), "{err}");
    assert!(!err.contains("No age identity"), "{err}");
}

#[test]
fn yubikey_add_with_a_recipient_never_lists_tokens() {
    let cli = Cli::new();
    let (ok, err, calls) = yubikey_add(&cli, "age1yubikey1aaa\n", 0, &["hello"]);
    assert!(!ok);
    assert!(!calls.contains("--list"), "{calls}");
    assert!(err.contains("hello is not an age recipient"), "{err}");
}

// A PEM's shape with a body that is no key, its marker split so secret scanners do not flag the fixture
const PEM: &str = concat!(
    "-----BEGIN RSA PRIV",
    "ATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCD\n\nbm90IGEga2V5\n-----END RSA PRIV",
    "ATE KEY-----"
);

#[test]
fn a_blob_keeps_every_line_and_injects_whole() {
    let cli = Cli::new();
    cli.run(&["add", "tls/key", "--blob"], Some(&format!("{PEM}\n")))
        .unwrap();

    assert_eq!(cli.read("tls/key").unwrap(), PEM);
}

#[test]
fn a_blob_is_read_from_a_file() {
    let cli = Cli::new();
    let source = cli.path().join("service.json");
    std::fs::write(
        &source,
        "{\n  \"type\": \"service_account\",\n  \"id\": 1\n}\n",
    )
    .unwrap();
    cli.run(
        &["add", "gcp/key", "--file", source.to_str().unwrap()],
        None,
    )
    .unwrap();

    assert_eq!(
        cli.read("gcp/key").unwrap(),
        "{\n  \"type\": \"service_account\",\n  \"id\": 1\n}"
    );
}

#[test]
fn a_blob_cannot_also_take_fields() {
    let cli = Cli::new();
    let err = cli
        .run(&["add", "tls/key", "--blob", "--field", "user"], Some("x"))
        .unwrap_err();
    assert!(err.contains("cannot be used with"), "{err}");
}

#[test]
fn exec_file_hands_the_child_a_path_and_removes_it_afterwards() {
    let cli = Cli::new();
    cli.run(&["add", "tls/key", "--blob"], Some(PEM)).unwrap();

    let marker = cli.path().join("path");
    let script = format!(
        "cat \"$KEY\" > {out}.copy; printf %s \"$KEY\" > {out}",
        out = marker.display()
    );
    cli.run(
        &["exec", "--file", "KEY=tls/key", "--", "sh", "-c", &script],
        None,
    )
    .unwrap();

    let copy = std::fs::read_to_string(format!("{}.copy", marker.display())).unwrap();
    assert_eq!(copy, format!("{PEM}\n"));
    let path = std::fs::read_to_string(&marker).unwrap();
    assert!(!Path::new(&path).exists(), "{path} outlived the child");
}

#[test]
fn replace_keeps_a_blob_whole() {
    let cli = Cli::new();
    cli.run(&["add", "tls/key", "--blob"], Some(PEM)).unwrap();
    cli.run(&["add", "tls/key", "--replace"], Some("new: 1\nline two\n"))
        .unwrap();

    let got = cli
        .run(
            &[
                "exec",
                "--env",
                "K=tls/key",
                "--",
                "sh",
                "-c",
                "printf %s \"$K\"",
            ],
            None,
        )
        .unwrap();
    assert!(got.contains("new: 1\nline two"), "{got}");
}

/// A fake `op` that serves two vaults: a login, a note, an SSH key the agent cannot use and a
/// binary document in Personal, and one login in Work
fn fake_op() -> tempfile::TempDir {
    let fake = tempfile::tempdir().unwrap();
    let shim = fake.path().join("op");
    std::fs::write(
        &shim,
        r#"#!/bin/sh
case "$1 $2 $3" in
"vault list "*) printf '%s\n' '[{"id":"v1","name":"Personal"},{"id":"v2","name":"Work"}]' ;;
"item list --vault")
  case "$4" in
  v1) printf '%s\n' '[{"id":"i1","title":"GitHub"},{"id":"i2","title":"Wi-Fi note"},{"id":"i3","title":"Old key"},{"id":"i4","title":"Scan"}]' ;;
  v2) printf '%s\n' '[{"id":"i5","title":"AWS: root"}]' ;;
  esac ;;
"item get i1") printf '%s\n' '{"id":"i1","category":"LOGIN","fields":[
  {"id":"username","purpose":"USERNAME","label":"username","value":"gb"},
  {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"hunter2"},
  {"id":"o","type":"OTP","label":"one-time password","value":"otpauth://totp/x"}],
  "urls":[{"href":"https://github.com","primary":true}]}' ;;
"item get i2") printf '%s\n' '{"id":"i2","category":"SECURE_NOTE","fields":[{"id":"notesPlain","purpose":"NOTES","value":"ssid home\npass abc"}]}' ;;
"item get i3") printf '%s\n' '{"id":"i3","category":"SSH_KEY","fields":[{"id":"private_key","type":"SSHKEY","value":"x"}]}' ;;
"item get i4") printf '%s\n' '{"id":"i4","category":"DOCUMENT","fields":[]}' ;;
"item get i5") printf '%s\n' '{"id":"i5","category":"API_CREDENTIAL","fields":[{"id":"credential","type":"CONCEALED","label":"credential","value":"AKIA"}]}' ;;
"read op://v1/i3/private key?ssh-format=openssh"*) printf -- '-----BEGIN RSA PRIVATE KEY-----\nabc\n' ;;
"document get i4") printf '\377\376\000' ;;
*) echo "unexpected: $*" >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    fake
}

fn import_1password(cli: &Cli, fake: &tempfile::TempDir, args: &[&str]) -> String {
    let out = cli
        .cmd(PASSPHRASE)
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .arg("import-1password")
        .args(args)
        .output()
        .unwrap();
    let note = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{note}");
    note
}

#[test]
fn importing_from_1password_maps_each_item_and_says_why_it_skipped() {
    let cli = Cli::new();
    let fake = fake_op();

    let dry = import_1password(&cli, &fake, &["--dry-run", "--prefix", "1p"]);
    assert!(
        dry.contains("Personal/GitHub -> 1p/personal/github"),
        "{dry}"
    );
    assert!(dry.contains("Work/AWS: root -> 1p/work/aws-root"), "{dry}");
    assert!(
        dry.contains("skipped Personal/Old key, the SSH agent signs"),
        "{dry}"
    );
    assert!(
        dry.contains("skipped Personal/Scan, the document is binary"),
        "{dry}"
    );
    assert!(dry.contains("would import 3, skipped 2"), "{dry}");
    assert!(!dry.contains("hunter2"), "a dry run printed a value: {dry}");
    assert_eq!(cli.run(&["ls"], None).unwrap(), "");

    let out = import_1password(&cli, &fake, &["--vault", "personal"]);
    assert!(
        out.contains("TOTP seed, passbox has no TOTP support"),
        "{out}"
    );
    assert!(out.contains("imported 2, skipped 2, refused 0"), "{out}");
    assert!(!out.contains("hunter2"), "{out}");
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "personal/github\npersonal/wi-fi-note\n"
    );
    assert_eq!(
        cli.read("personal/github").unwrap(),
        "hunter2\nusername: gb\nurl: https://github.com"
    );
    assert_eq!(
        cli.read("personal/wi-fi-note").unwrap(),
        "ssid home\npass abc"
    );

    // A second run refuses every name already there and overwrites nothing
    let again = import_1password(&cli, &fake, &[]);
    assert!(
        again.contains("refused personal/github, already in the store"),
        "{again}"
    );
    assert!(
        again.contains("imported 1, skipped 2, refused 2"),
        "{again}"
    );
    assert_eq!(cli.read("work/aws-root").unwrap(), "AKIA");
}

#[test]
fn two_1password_items_with_one_name_import_the_first_and_skip_the_second() {
    let cli = Cli::new();
    let fake = tempfile::tempdir().unwrap();
    let shim = fake.path().join("op");
    std::fs::write(
        &shim,
        r#"#!/bin/sh
case "$1 $2 $3" in
"vault list "*) printf '%s\n' '[{"id":"v1","name":"Dev"}]' ;;
"item list --vault") printf '%s\n' '[{"id":"i1","title":"GitHub"},{"id":"i2","title":"github!"}]' ;;
"item get i1") printf '%s\n' '{"id":"i1","category":"API_CREDENTIAL","fields":[{"id":"credential","type":"CONCEALED","value":"one"}]}' ;;
"item get i2") printf '%s\n' '{"id":"i2","category":"API_CREDENTIAL","fields":[{"id":"credential","type":"CONCEALED","value":"two"}]}' ;;
*) echo "unexpected: $*" >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let out = import_1password(&cli, &fake, &[]);
    assert!(
        out.contains("skipped Dev/github!, dev/github is already taken by Dev/GitHub"),
        "{out}"
    );
    assert!(!out.contains("already in the store"), "{out}");
    assert!(out.contains("imported 1, skipped 1, refused 0"), "{out}");
    assert_eq!(cli.read("dev/github").unwrap(), "one");
}
