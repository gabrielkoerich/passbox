//! The SSH agent: offered keys, signatures and signing windows.

use super::*;

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
    assert!(made.success(), "ssh-keygen could not make a {kind} key");
    let private = std::fs::read_to_string(&path).unwrap();
    bound.run(&["add", "ssh/test"], Some(&private)).unwrap();
    // Starts the broker, which serves the agent socket beside its own
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();

    let listed = with_agent(&bound, "ssh-add", &["-L"]);
    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        public.trim(),
        "ssh-add -L does not list the stored key"
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
    // A signature names no host, so the prompt names the folder it was made in and who asked
    assert!(
        prompts[0].starts_with("sign a test signature in "),
        "{prompts:?}"
    );
    assert!(
        prompts[0].contains(" with SSH key test@passbox.dev for "),
        "{prompts:?}"
    );
    assert!(prompts[0].contains("(ssh-keygen < "), "{prompts:?}");

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
    assert!(
        !sign(&keys.path().join("refused")).status.success(),
        "a refused prompt still signed"
    );
    let log = bound.audit();
    assert!(decided(&log, "ssh/test", "signed"), "{log}");
    assert!(decided(&log, "ssh:test@passbox.dev", "denied"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_ssh_key_never_leaves_bare() {
    let bound = Bound::new();
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
            "test@passbox.dev",
            "-f",
        ])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let private = std::fs::read_to_string(&path).unwrap();
    bound.run(&["add", "ssh/test"], Some(&private)).unwrap();

    let err = bound
        .run(&["exec", "--env", "K=ssh/test", "--", "true"], None)
        .unwrap_err();
    assert!(err.contains("only the SSH agent signs with"), "{err}");
    let err = bound.run(&["grant", "ssh/test"], None).unwrap_err();
    assert!(err.contains("no token holds it"), "{err}");
    let err = bound.run(&["copy", "ssh/test"], None).unwrap_err();
    assert!(err.contains("passbox get --encrypt ssh/test"), "{err}");
    assert!(decided(&bound.audit(), "ssh/test", "withheld"));
}

#[test]
fn a_passphrase_store_refuses_an_ssh_key_too() {
    let cli = Cli::new();
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("id");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success());
    let private = std::fs::read_to_string(&path).unwrap();
    cli.run(&["add", "ssh/test"], Some(&private)).unwrap();
    let err = cli
        .run(&["exec", "--env", "K=ssh/test", "--", "true"], None)
        .unwrap_err();
    assert!(err.contains("only the SSH agent signs with"), "{err}");
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

/// Whether ssh says an agent connection was forwarded, the last byte of a session bind
#[derive(Clone, Copy)]
enum Hop {
    Direct,
    Forwarded,
}

/// One length-prefixed field of the SSH agent protocol
fn wire(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend(bytes);
}

/// Sends one agent message and returns the type byte of the reply
fn agent_send(stream: &mut std::os::unix::net::UnixStream, body: &[u8]) -> u8 {
    let mut message = Vec::new();
    wire(&mut message, body);
    stream.write_all(&message).unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let mut reply = vec![0; usize::try_from(u32::from_be_bytes(len)).unwrap()];
    stream.read_exact(&mut reply).unwrap();
    reply[0]
}

/// A login as OpenSSH 8.9 makes one: bind the agent connection to the host key that signed the
/// session id, then ask for a signature over a publickey login for that same session
fn agent_login(
    bound: &Bound,
    host: &ssh_key::PrivateKey,
    user: &[u8],
    session: &[u8],
    hop: Hop,
) -> u8 {
    let mut stream =
        std::os::unix::net::UnixStream::connect(bound.cli.path().join("ssh-agent.sock")).unwrap();
    let signature: ssh_key::Signature = signature::Signer::try_sign(host, session).unwrap();
    let mut bind = vec![27];
    wire(&mut bind, b"session-bind@openssh.com");
    wire(&mut bind, &host.public_key().to_bytes().unwrap());
    wire(&mut bind, session);
    wire(&mut bind, &Vec::<u8>::try_from(signature).unwrap());
    bind.push(u8::from(matches!(hop, Hop::Forwarded)));
    assert_eq!(
        agent_send(&mut stream, &bind),
        6,
        "the agent refused the bind"
    );

    let mut login = Vec::new();
    wire(&mut login, session);
    login.push(50);
    for field in [&b"git"[..], b"ssh-connection", b"publickey"] {
        wire(&mut login, field);
    }
    login.push(1);
    wire(&mut login, b"ssh-ed25519");
    wire(&mut login, user);
    let mut sign = vec![13];
    wire(&mut sign, user);
    wire(&mut sign, &login);
    sign.extend(0u32.to_be_bytes());
    agent_send(&mut stream, &sign)
}

/// One prompt covers later logins with the same key to the same host key. The window is pinned to
/// the host key the connection proved, so a forwarded agent or another host still prompts
/* A git signature names no host, so its window is keyed by the namespace. The first one prompts and
opens it, later git signatures from this Mac go through, and any other namespace still prompts */
#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_git_signing_window_covers_later_git_signatures_and_nothing_else() {
    let bound = Bound::new();
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
            "test@passbox.dev",
            "-f",
        ])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success(), "ssh-keygen could not make a key");
    let private = std::fs::read_to_string(&path).unwrap();
    bound.run(&["add", "ssh/test"], Some(&private)).unwrap();
    std::fs::write(
        bound.cli.path().join("config.toml"),
        "[ssh.signing]\ngit = \"1h\"\n",
    )
    .unwrap();
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();

    let pubkey = path.with_extension("pub");
    let sign = |namespace: &str, file: &str| {
        let message = keys.path().join(file);
        std::fs::write(&message, "signed through passbox").unwrap();
        let out = with_agent(
            &bound,
            "ssh-keygen",
            &[
                "-Y",
                "sign",
                "-n",
                namespace,
                "-f",
                pubkey.to_str().unwrap(),
                message.to_str().unwrap(),
            ],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    sign("git", "one");
    sign("git", "two");
    sign("git", "three");
    let prompts = bound.prompts();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(
        prompts[0].starts_with("allow SSH windows git signatures 1h for "),
        "{prompts:?}"
    );
    assert!(
        prompts[0].contains("and its git signatures for 1h without asking"),
        "{prompts:?}"
    );

    sign("file", "four");
    let prompts = bound.prompts();
    assert_eq!(
        prompts.len(),
        2,
        "another namespace went through the git window: {prompts:?}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_signing_window_covers_later_logins_to_the_same_host_key_and_nothing_else() {
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    use ssh_key::{HashAlg, PrivateKey, PublicKey};

    const SIGNED: u8 = 14;
    let bound = Bound::new();
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
            "test@passbox.dev",
            "-f",
        ])
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success(), "ssh-keygen could not make a key");
    let private = std::fs::read_to_string(&path).unwrap();
    bound.run(&["add", "ssh/test"], Some(&private)).unwrap();
    bound.run(&["ls"], None).unwrap();
    bound.forget_prompts();

    let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    let user = PublicKey::from_openssh(&public)
        .unwrap()
        .to_bytes()
        .unwrap();
    let host = |seed: u8| {
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        PrivateKey::new(KeypairData::from(pair), "host").unwrap()
    };
    let (legion, other) = (host(7), host(8));
    let listed = legion.public_key().fingerprint(HashAlg::Sha256).to_string();
    std::fs::write(
        bound.cli.path().join("config.toml"),
        format!("[ssh.windows]\n\"{listed}\" = \"1h\"\n"),
    )
    .unwrap();

    assert_eq!(
        agent_login(&bound, &legion, &user, b"session-1", Hop::Direct),
        SIGNED
    );
    let prompts = bound.prompts();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(prompts[0].starts_with("allow SSH windows"), "{prompts:?}");
    assert!(
        prompts[0].contains(&format!("an SSH login as git to {listed}")),
        "{prompts:?}"
    );
    assert!(
        prompts[0].ends_with(&format!("and its logins to {listed} for 1h without asking")),
        "{prompts:?}"
    );

    assert_eq!(
        agent_login(&bound, &legion, &user, b"session-2", Hop::Direct),
        SIGNED
    );
    assert_eq!(
        bound.prompts().len(),
        1,
        "a login inside the window prompted: {:?}",
        bound.prompts()
    );

    assert_eq!(
        agent_login(&bound, &legion, &user, b"session-3", Hop::Forwarded),
        SIGNED
    );
    assert_eq!(
        bound.prompts().len(),
        2,
        "a forwarded agent used the window"
    );
    assert_eq!(
        agent_login(&bound, &other, &user, b"session-4", Hop::Direct),
        SIGNED
    );
    assert_eq!(bound.prompts().len(), 3, "another host key used the window");

    let log = bound.audit();
    assert_eq!(count(&log, "ssh/test", "by window"), 1, "{log}");
    assert!(log.contains(", window 1h"), "{log}");
}
