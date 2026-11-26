//! Adding, reading, copying and running with secrets, blobs included.

use super::*;

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

/* A 1Password note with fields and no password imports with an empty first line. Asking for its
password fails, rather than copying nothing over what was on the clipboard */
#[test]
fn an_entry_with_no_password_says_so() {
    let cli = Cli::new();
    cli.run(&["add", "bank/main"], Some("\nbank: itau\npix: me@x"))
        .unwrap();
    let err = cli
        .run(&["copy", "bank/main", "--field", "password"], None)
        .unwrap_err();
    assert!(err.contains("bank/main has no password"), "{err}");
}

/// What Alfred lists to copy one field: the labels, in order, and never a value
#[test]
fn fields_lists_the_labels_and_no_value() {
    let cli = Cli::new();
    cli.run(
        &["add", "bank/main"],
        Some("hunter2\nusername: gb\npix: me@x"),
    )
    .unwrap();
    let out = cli.run(&["fields", "bank/main"], None).unwrap();
    assert_eq!(out, "password\nusername\npix\n");
    assert!(!out.contains("hunter2") && !out.contains("me@x"), "{out}");

    // A note is one text, so it names no field even when a line holds a colon
    cli.run(&["add", "notes/wifi", "--blob"], Some("home\npass: abc\n"))
        .unwrap();
    assert_eq!(cli.run(&["fields", "notes/wifi"], None).unwrap(), "");

    // An entry with nothing to list is not a note, so it fails rather than copying whole
    cli.run(&["add", "misc/pin"], Some("\nmy pin is 4821: bank"))
        .unwrap();
    let err = cli.run(&["fields", "misc/pin"], None).unwrap_err();
    assert!(err.contains("misc/pin has no field to copy"), "{err}");
}

/* Alfred's ⌘⏎ asks every entry for its password. A note has none, so asking it for a field fails
rather than handing out its first line */
#[test]
fn a_note_has_no_field_to_read() {
    let cli = Cli::new();
    cli.run(
        &["add", "notes/wifi", "--blob"],
        Some("home network\npass: abc\n"),
    )
    .unwrap();
    let err = cli
        .run(&["copy", "notes/wifi", "--field", "password"], None)
        .unwrap_err();
    assert!(err.contains("notes/wifi is a note"), "{err}");
    assert!(!err.contains("home network"), "{err}");

    cli.run(&["add", "bank/main"], Some("pw\npix: me@x"))
        .unwrap();
    let err = cli
        .run(&["copy", "bank/main", "--field", "agency"], None)
        .unwrap_err();
    assert!(err.contains("bank/main has no field agency"), "{err}");
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
