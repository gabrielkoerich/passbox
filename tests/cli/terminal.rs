//! Commands that ask at a terminal, driven through a pseudo terminal.

use super::*;

/// One passbox command on a pseudo-terminal, so it prompts as it does for a person at a keyboard
struct Term {
    master: std::fs::File,
    child: std::process::Child,
    seen: std::sync::Arc<std::sync::Mutex<String>>,
    // Where the last expected prompt ended, so a prompt asked twice is waited for twice
    cursor: usize,
}

impl Term {
    fn spawn(mut cmd: Command) -> Self {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;

        let (mut master, mut slave) = (0, 0);
        // SAFETY: openpty writes two descriptors and reads only the null name, termios and size
        let opened = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0, "no pseudo-terminal");
        // SAFETY: openpty just opened this descriptor and nothing else owns it
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        // SAFETY: as above
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };

        cmd.stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        // rpassword reads /dev/tty, which is the terminal of the child's own session
        let controlling = || {
            // SAFETY: stdin is the slave, which login_tty makes the terminal of a new session
            unsafe { libc::login_tty(0) };
            Ok(())
        };
        // SAFETY: the hook only calls login_tty, which touches nothing but this child's session
        unsafe { cmd.pre_exec(controlling) };
        let child = cmd.spawn().unwrap();
        drop(cmd);

        let master = std::fs::File::from(master);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut reader = master.try_clone().unwrap();
        let sink = std::sync::Arc::clone(&seen);
        // Linux answers EIO once the child closes the terminal, so any error ends the output
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = reader.read(&mut buf) {
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        Term {
            master,
            child,
            seen,
            cursor: 0,
        }
    }

    /// Waits for `prompt`, then types `line` and Enter
    fn answer(&mut self, prompt: &str, line: &str) {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let seen = self.seen.lock().unwrap().clone();
            if let Some(at) = seen[self.cursor..].find(prompt) {
                self.cursor += at + prompt.len();
                break;
            }
            assert!(
                Instant::now() < until,
                "no {prompt:?} on the terminal: {seen}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        writeln!(self.master, "{line}").unwrap();
    }

    /// Whether the command succeeded, and everything it wrote to the terminal
    fn wait(mut self) -> (bool, String) {
        let until = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > until {
                let _ = self.child.kill();
                panic!("the command never finished: {}", self.seen.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // The reader drains what the child wrote just before it exited
        std::thread::sleep(Duration::from_millis(200));
        let seen = self.seen.lock().unwrap().clone();
        (status.success(), seen)
    }
}

#[test]
fn add_at_a_terminal_asks_twice_then_for_each_field_and_the_notes() {
    let cli = Cli::new();
    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.args(["add", "db/pass", "--multiline", "--field", "username"]);
    let mut term = Term::spawn(cmd);
    term.answer("value: ", "s3cret");
    term.answer("again: ", "s3cret");
    term.answer("username: ", "admin");
    term.answer("empty line to finish", "rotated quarterly");
    term.answer("rotated quarterly", "");
    let (ok, out) = term.wait();

    assert!(ok, "{out}");
    assert!(
        !out.contains("s3cret"),
        "the value echoed on the terminal: {out}"
    );
    assert_eq!(
        cli.read("db/pass").unwrap(),
        "s3cret\nusername: admin\nrotated quarterly"
    );
}

#[test]
fn add_at_a_terminal_refuses_two_values_that_differ() {
    let cli = Cli::new();
    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.args(["add", "db/pass"]);
    let mut term = Term::spawn(cmd);
    term.answer("value: ", "one");
    term.answer("again: ", "two");
    let (ok, out) = term.wait();

    assert!(!ok, "two different values were stored");
    assert!(out.contains("values do not match"), "{out}");
    assert!(cli.read("db/pass").is_err(), "something was stored");
}

/// A pick of 2 reaches the wrap with the second token, whose fake recipient then fails to parse
#[test]
fn yubikey_add_at_a_terminal_picks_one_of_several_new_tokens() {
    let cli = Cli::new();
    let fake = fake_yubikey(
        "#  Serial: 1, Slot: 1\nage1yubikey1aaa\n#  Serial: 2, Slot: 1\nage1yubikey1bbb\n",
        0,
    );
    for (pick, expected) in [
        ("2", "age1yubikey1bbb is not an age recipient"),
        ("7", "expected 1 to 2, got 7"),
    ] {
        let mut cmd = cli.cmd(PASSPHRASE);
        cmd.env("PATH", format!("{}:/usr/bin:/bin", fake.path().display()))
            .arg("yubikey-add");
        let mut term = Term::spawn(cmd);
        term.answer("Which? [1-2] ", pick);
        let (ok, out) = term.wait();

        assert!(!ok, "{out}");
        assert!(
            out.contains("2) Serial: 2, Slot: 1  age1yubikey1bbb"),
            "{out}"
        );
        assert!(out.contains(expected), "{out}");
    }
    let calls = std::fs::read_to_string(fake.path().join("calls")).unwrap();
    assert!(
        !calls.contains("--generate"),
        "a test generated on a token: {calls}"
    );
}

/// A store bound to this Mac has no way in elsewhere, so `--enable` offers a passphrase. It is
/// typed twice at the terminal and must then open the store on its own
#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn sync_enable_at_a_terminal_sets_a_recovery_passphrase_and_a_directory() {
    let bound = Bound::new();
    let remote = tempfile::tempdir().unwrap();
    let phrase = "a long recovery phrase";

    let mut cmd = bound.cmd();
    cmd.args(["sync", "--enable"]);
    let mut term = Term::spawn(cmd);
    term.answer("Which? [1/2] ", "2");
    term.answer("recovery passphrase: ", "short");
    let (ok, out) = term.wait();
    assert!(!ok, "a short passphrase was accepted");
    assert!(out.contains("use at least 12 characters"), "{out}");
    assert!(!bound.cli.path().join("wraps/recovery.age").exists());

    let mut cmd = bound.cmd();
    cmd.args(["sync", "--enable"]);
    let mut term = Term::spawn(cmd);
    term.answer("Which? [1/2] ", "2");
    term.answer("recovery passphrase: ", phrase);
    term.answer("again: ", phrase);
    term.answer("Which? [1/2/3/4] ", "2");
    term.answer("directory: ", &remote.path().display().to_string());
    let (ok, out) = term.wait();

    assert!(ok, "{out}");
    assert!(!out.contains(phrase), "the passphrase echoed: {out}");
    assert!(bound.cli.path().join("wraps/recovery.age").exists());
    assert!(
        std::fs::read_dir(remote.path()).unwrap().count() > 0,
        "nothing was copied: {out}"
    );
    assert_eq!(bound.cli.read_as(phrase, "demo/one").unwrap(), "value-one");
}
