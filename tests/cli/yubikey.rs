//! Adding a YubiKey wrap against a fake age-plugin-yubikey.

use super::*;

fn yubikey_add(cli: &Cli, list: &str, exit: u8, args: &[&str]) -> (bool, String, String) {
    let fake = fake_yubikey(list, exit);
    let log = fake.path().join("calls");
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
