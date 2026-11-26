//! Importing from pass and from 1Password.

use super::*;

/* pass entries carry `key: value` lines under the password, and `get --field` reads them, so
the import has to keep the whole body rather than the first line. */
#[test]
fn importing_from_pass_keeps_the_whole_entry() {
    let cli = Cli::new();
    let pass = FakePass::new(
        &["bean/hl-mainnet-pk", "bean/fred-api-key", "beanstalk/other"],
        "topsecret\\nlogin: gb\\nurl: https://example.com",
    );

    let note = pass.import(&cli, &["bean"]);
    assert!(
        note.contains("imported 2, skipped 0, refused 0 already there"),
        "{note}"
    );

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
    let pass = FakePass::new(&["solo"], "value");

    let first = pass.import(&cli, &[]);
    assert!(
        first.contains("imported 1, skipped 0, refused 0 already there"),
        "{first}"
    );
    let second = pass.import(&cli, &[]);
    assert!(
        second.contains("refused solo, already in the store"),
        "{second}"
    );
    assert!(
        second.contains("imported 0, skipped 0, refused 1 already there"),
        "{second}"
    );
}

/// A dry run names what each entry would become and writes nothing, and a prefix moves every name
#[test]
fn importing_from_pass_takes_a_prefix_and_a_dry_run() {
    let cli = Cli::new();
    let pass = FakePass::new(&["bean/key", "other"], "v");

    let dry = pass.import(&cli, &["bean", "--prefix", "old/", "--dry-run"]);
    assert!(dry.contains("bean/key -> old/bean/key"), "{dry}");
    assert!(
        dry.contains("would import 1, skipped 0, refused 0 already there"),
        "{dry}"
    );
    assert_eq!(cli.run(&["ls"], None).unwrap(), "");

    pass.import(&cli, &["--prefix", "old"]);
    assert_eq!(cli.run(&["ls"], None).unwrap(), "old/bean/key\nold/other\n");
}

/// A pass store with these entries, and a `pass` on PATH that shows `body` for any of them
struct FakePass {
    store: tempfile::TempDir,
    bin: tempfile::TempDir,
}

impl FakePass {
    fn new(names: &[&str], body: &str) -> Self {
        let pass = FakePass {
            store: tempfile::tempdir().unwrap(),
            bin: tempfile::tempdir().unwrap(),
        };
        for name in names {
            let path = pass.store.path().join(format!("{name}.gpg"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
        }
        let shim = pass.bin.path().join("pass");
        std::fs::write(&shim, format!("#!/bin/sh\nprintf '{body}'\n")).unwrap();
        std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        pass
    }

    /// `passbox import pass` with these arguments, which must succeed, and what it printed
    fn import(&self, cli: &Cli, args: &[&str]) -> String {
        let out = cli
            .cmd(PASSPHRASE)
            .env("PASSWORD_STORE_DIR", self.store.path())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.bin.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .args(["import", "pass"])
            .args(args)
            .output()
            .unwrap();
        let note = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(out.status.success(), "{note}");
        note
    }
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
        .args(["import", "1password"])
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
    // A key the agent cannot sign with is still imported
    assert!(
        dry.contains("Personal/Old key -> 1p/personal/old-key"),
        "{dry}"
    );
    assert!(
        dry.contains("skipped Personal/Scan, the document is binary"),
        "{dry}"
    );
    assert!(dry.contains("would import 4, skipped 1"), "{dry}");
    assert!(!dry.contains("hunter2"), "a dry run printed a value: {dry}");
    assert_eq!(cli.run(&["ls"], None).unwrap(), "");

    let out = import_1password(&cli, &fake, &["personal"]);
    assert!(out.contains("TOTP seed, kept as a field"), "{out}");
    assert!(out.contains("imported 3, skipped 1, refused 0"), "{out}");
    assert!(!out.contains("hunter2"), "{out}");
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "personal/github\npersonal/old-key\npersonal/wi-fi-note\n"
    );
    assert_eq!(
        cli.read("personal/github").unwrap(),
        "hunter2\nusername: gb\nurl: https://github.com\none-time password: otpauth://totp/x"
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
        again.contains("imported 1, skipped 1, refused 3"),
        "{again}"
    );
    assert_eq!(cli.read("work/aws-root").unwrap(), "AKIA");
}

#[test]
fn two_1password_items_with_one_name_both_import_the_later_numbered() {
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
        out.contains("dev/github-2: named dev/github-2, since Dev/GitHub took dev/github"),
        "{out}"
    );
    assert!(!out.contains("already in the store"), "{out}");
    assert!(out.contains("imported 2, skipped 0, refused 0"), "{out}");
    assert_eq!(cli.read("dev/github").unwrap(), "one");
    assert_eq!(cli.read("dev/github-2").unwrap(), "two");

    // A second run refuses both, and numbers nothing new
    let again = import_1password(&cli, &fake, &[]);
    assert!(
        again.contains("imported 0, skipped 0, refused 2"),
        "{again}"
    );
    assert_eq!(
        cli.run(&["ls"], None).unwrap(),
        "dev/github\ndev/github-2\n"
    );
}
