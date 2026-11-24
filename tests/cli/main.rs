//! Drives the built binary, so it covers what unit tests cannot: argument handling and exit codes.
use age::x25519::Identity;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod broker;
mod client;
mod import;
mod phone;
mod plugins;
mod secrets;
mod ssh;
mod sync;
mod terminal;
mod yubikey;

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

/// A TOML basic string holding `text`, so a shell script with quotes survives the manifest
fn toml_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
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
    /// Set on every command, the one that starts the broker included
    env: Vec<(String, String)>,
}

impl Bound {
    fn new() -> Self {
        Bound::with_env(Vec::new())
    }

    fn with_env(env: Vec<(String, String)>) -> Self {
        let bound = Bound {
            cli: Cli::empty(),
            log: tempfile::tempdir().unwrap(),
            env,
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
            .env("PASSBOX_AGENT", "test-agent")
            .envs(self.env.iter().map(|(key, value)| (key, value)));
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

/// Whether the audit log holds a record of `decision` for `secret`
fn decided(log: &str, secret: &str, decision: &str) -> bool {
    log.lines().any(|l| {
        l.contains(&format!("\"secret\":\"{secret}\""))
            && l.contains(&format!("\"decision\":\"{decision}\""))
    })
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

fn count(log: &str, secret: &str, decision: &str) -> usize {
    log.lines()
        .filter(|l| {
            l.contains(&format!("\"secret\":\"{secret}\""))
                && l.contains(&format!("\"decision\":\"{decision}\""))
        })
        .count()
}

/* A fake age-plugin-yubikey on a PATH without the real one, ykman or brew, so no test reaches a
token. It logs its arguments, and every case here stops before the store key is unlocked */
/// A stand-in `age-plugin-yubikey` that lists `list`, logs every call, and exits `exit` for --list
fn fake_yubikey(list: &str, exit: u8) -> tempfile::TempDir {
    let fake = tempfile::tempdir().unwrap();
    let shim = fake.path().join("age-plugin-yubikey");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\n[ \"$1\" = --list ] || exit 0\nprintf '%s' '{list}'\necho 'pcsc: no reader' >&2\nexit {exit}\n",
            fake.path().join("calls").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    fake
}
