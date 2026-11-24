//! Installing, updating and running plugins without the broker.

use super::*;

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
