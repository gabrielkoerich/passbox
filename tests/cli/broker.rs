//! Prompts, plugin windows and the audit log, through a broker on a fake Enclave.

use super::*;

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
    let detach = || {
        // SAFETY: setsid only moves the child into a session of its own
        unsafe { libc::setsid() };
        Ok(())
    };
    // SAFETY: the hook only calls setsid, which is async-signal-safe and touches nothing in this process
    unsafe { cmd.pre_exec(detach) };
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disabled by PASSBOX_NO_ENCLAVE"),
        "{stderr}"
    );
    assert!(!stderr.contains("bound to this Mac"), "{stderr}");
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

const SHOW_AB: &str = "printf %s,%s \"$A\" \"$B\"";

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn fields_through_the_broker_prompts_once_and_is_audited_without_a_value() {
    let bound = Bound::new();
    let out = bound.run(&["fields", "demo/one"], None).unwrap();
    assert_eq!(out, "password\n");
    assert_eq!(
        bound.prompts(),
        ["list the fields of demo/one for test-agent"]
    );
    let log = bound.audit();
    assert!(decided(&log, "demo/one", "fields listed"), "{log}");
    assert!(!log.contains("value-one"), "{log}");
}

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
