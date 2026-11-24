//! A phone as a second approver: enrolling it, its answers and the relay.

use super::*;

const PHONE: &str = "iphone (me@example.com, 100.64.0.9)";
const PHONE_ADDRESS: &str = "100.64.0.9";

/// A `tailscale` that says this Mac is on a tailnet and names the nodes on it. Written once, since
/// a script still open for writing in one thread cannot be run from another
fn fake_tailscale() -> &'static Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("tailscale");
        std::fs::write(
            &script,
            "#!/bin/sh\ncase \"$1\" in\n  ip) echo 100.64.0.1 ;;\n  whois)\n    case \"$2\" in\n      100.64.0.9) name=iphone ;;\n      100.64.0.1) name=mac ;;\n      *) name=server ;;\n    esac\n    printf 'Machine:\\n  Name:          %s.example.ts.net\\n  ID:            nExampleCNTRL\\nUser:\\n  Name:     me@example.com\\n' \"$name\" ;;\nesac\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        dir
    })
    .path()
}

/// A bound store whose broker listens for tailnet peers on a port of its own, and the app's half
/// of the protocol, written here independently of the broker's
struct Paired {
    bound: Bound,
    port: u16,
    token: String,
}

impl Paired {
    /// `timing` is the body of `[phone]` in the config, such as `delay = 0`
    fn unenrolled(timing: &str) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let path = format!(
            "{}:{}",
            fake_tailscale().display(),
            std::env::var("PATH").unwrap()
        );
        let bound = Bound::with_env(vec![
            ("PATH".to_string(), path),
            ("PASSBOX_TEST_TAILNET_PORT".to_string(), port.to_string()),
        ]);
        std::fs::write(
            bound.cli.path().join("config.toml"),
            format!("[phone]\n{timing}\n"),
        )
        .unwrap();
        Paired {
            bound,
            port,
            token: String::new(),
        }
    }

    fn new(timing: &str) -> Self {
        let mut paired = Paired::unenrolled(timing);
        let (ok, stderr) = paired.add(Proof::Give);
        assert!(ok, "phone add failed: {stderr}");
        paired.bound.forget_prompts();
        paired
    }

    /// One line to the tailnet listener as `tailscale serve` delivers it, from the node at `from`
    fn call_from(&self, from: &str, request: &serde_json::Value) -> Result<String, String> {
        let mut stream = self.dial();
        write!(
            stream,
            "PROXY TCP4 {from} 100.64.0.1 50000 8787\r\n{request}\n"
        )
        .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut line)
            .unwrap();
        let reply: serde_json::Value = serde_json::from_str(&line).unwrap();
        if reply["ok"] == true {
            Ok(reply["value"].as_str().unwrap().to_string())
        } else {
            Err(reply["error"].as_str().unwrap().to_string())
        }
    }

    /// The broker opens its tailnet port a moment after its socket, so a first call may be early
    fn dial(&self) -> std::net::TcpStream {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            match std::net::TcpStream::connect(("127.0.0.1", self.port)) {
                Ok(stream) => return stream,
                Err(e) => assert!(Instant::now() < until, "the broker is not listening: {e}"),
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn call(&self, action: &str, name: &str, params: &[(&str, &str)]) -> Result<String, String> {
        self.call_from(
            PHONE_ADDRESS,
            &serde_json::json!({
                "op": "phone", "agent": "", "action": action, "name": name,
                "token": self.token, "params": params,
            }),
        )
    }

    /// The request on the phone's screen, once there is one
    fn pending(&self) -> serde_json::Value {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let shown = self.call("pending", "", &[]).unwrap();
            if !shown.is_empty() {
                return serde_json::from_str(&shown).unwrap();
            }
            assert!(Instant::now() < until, "nothing reached the phone");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Face ID, as the app does it: open the wrap, then seal the store key to the request's key.
    /// The fake enclave seals nothing, so its ciphertext is the plaintext
    fn approve(&self, shown: &serde_json::Value) -> Result<String, String> {
        let key = unbase64(shown["ciphertext"].as_str().unwrap());
        let id = shown["id"].as_str().unwrap();
        let (ephemeral, sealed) = seal_answer(shown["key"].as_str().unwrap(), id, &key);
        self.call(
            "answer",
            id,
            &[("ephemeral", &ephemeral), ("sealed", &sealed)],
        )
    }

    /// `passbox phone add` with the phone doing its part, and whether the phone then proves itself
    fn add(&mut self, proof: Proof) -> (bool, String) {
        let mut child = self
            .bound
            .cmd()
            .args(["phone", "add"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
        let mut said = String::new();
        let code = loop {
            let mut line = String::new();
            if stderr.read_line(&mut line).unwrap() == 0 {
                child.wait().unwrap();
                return (false, said);
            }
            said.push_str(&line);
            if let Some(code) = line.trim().strip_prefix("Code") {
                break code.trim().to_string();
            }
        };

        // An uncompressed P-256 point by shape, which is all the fake enclave looks at
        let public = base64(&[&[4u8][..], &[7u8; 64][..]].concat());
        let enrolled: serde_json::Value = serde_json::from_str(
            &self
                .call("enroll", "", &[("code", &code), ("public_key", &public)])
                .expect("enroll"),
        )
        .unwrap();
        // What the app shows on its info screen: the Mac it paired with and its own tailnet name
        assert_eq!(enrolled["phone"], PHONE, "the phone was told another name");
        assert!(
            !enrolled["mac"].as_str().unwrap().is_empty(),
            "the Mac did not name itself"
        );
        self.token = enrolled["token"].as_str().unwrap().to_string();
        if proof == Proof::Abandon {
            child.kill().unwrap();
            child.wait().unwrap();
            return (false, said);
        }
        if proof == Proof::Give {
            let shown = self.pending();
            assert_eq!(
                shown["reason"], "confirm this phone can approve reads",
                "the proof is not what the phone was shown"
            );
            self.approve(&shown).expect("the proof");
        }
        stderr.read_to_string(&mut said).unwrap();
        (child.wait().unwrap().success(), said)
    }

    /// The mask in the phone's wrap, which the phone itself never sees
    fn mask(&self) -> Vec<u8> {
        let wraps = self.bound.cli.path().join("wraps");
        let wrap = std::fs::read_dir(&wraps)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("phone-")
            })
            .expect("a phone wrap");
        let wrap: serde_json::Value =
            serde_json::from_slice(&std::fs::read(wrap).unwrap()).unwrap();
        hex::decode(wrap["mask"].as_str().unwrap()).unwrap()
    }

    /// A read left running, since it waits on an approval the test then gives or withholds
    fn read_later(&self, name: &str) -> std::thread::JoinHandle<Result<String, String>> {
        let env = format!("V={name}");
        let mut cmd = self.bound.cmd();
        cmd.args(["exec", "--env", &env]).args(PRINT_V);
        std::thread::spawn(move || {
            let out = cmd.output().unwrap();
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).to_string())
            }
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Proof {
    Give,
    Withhold,
    /// Ctrl-C on `passbox phone add` once the phone has enrolled, before the proof
    Abandon,
}

fn base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unbase64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).unwrap()
}

/* The box the app seals its answer in: X25519 with a one-time key, HKDF-SHA256 salted with both
public keys and bound to the request id, ChaCha20-Poly1305 with the id as associated data and a
zero nonce. A second implementation agreeing with the broker's is the evidence the format is what
the design says it is. */
fn seal_answer(to: &str, id: &str, plaintext: &[u8]) -> (String, String) {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let to: [u8; 32] = unbase64(to).try_into().unwrap();
    let to = x25519_dalek::PublicKey::from(to);
    let ephemeral = x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>());
    let public = x25519_dalek::PublicKey::from(&ephemeral);

    let salt = [public.as_bytes().as_slice(), to.as_bytes().as_slice()].concat();
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), ephemeral.diffie_hellman(&to).as_bytes())
        .expand(format!("passbox-phone-v1 {id}").as_bytes(), &mut key)
        .unwrap();
    let sealed = chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key))
        .encrypt(
            &chacha20poly1305::Nonce::default(),
            Payload {
                msg: plaintext,
                aad: id.as_bytes(),
            },
        )
        .unwrap();
    (base64(public.as_bytes()), base64(&sealed))
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_phone_enrolls_with_the_code_a_fingerprint_and_a_proof() {
    let mut paired = Paired::unenrolled("");
    assert_eq!(paired.bound.run(&["phone", "ls"], None).unwrap(), "");
    // A read starts the broker, which is what a phone dials
    paired.bound.read("demo/one").unwrap();
    paired.bound.forget_prompts();

    // Nothing enrolls without the window `phone add` opens, or with the wrong code
    let public = base64(&[&[4u8][..], &[7u8; 64][..]].concat());
    let refused = paired
        .call("enroll", "", &[("code", "000000"), ("public_key", &public)])
        .unwrap_err();
    assert!(refused.contains("no enrollment is open"), "{refused}");

    let (ok, said) = paired.add(Proof::Give);
    assert!(ok, "{said}");
    assert!(
        said.contains("Mac   100.64.0.1   mac (me@example.com, 100.64.0.1)"),
        "{said}"
    );
    assert!(said.contains(&format!("{PHONE} can approve")), "{said}");
    assert_eq!(
        paired.bound.prompts(),
        [format!(
            "let {PHONE} with key EE 5C 83 approve reads from now on"
        )]
    );
    assert_eq!(
        paired.bound.run(&["phone", "ls"], None).unwrap().trim(),
        PHONE
    );

    // The code opened one enrollment, and a second phone is refused while the first stands
    let again = paired
        .call("enroll", "", &[("code", "000000"), ("public_key", &public)])
        .unwrap_err();
    assert!(again.contains("no enrollment is open"), "{again}");
    let second = paired.bound.run(&["phone", "add"], None).unwrap_err();
    assert!(second.contains("is already enrolled"), "{second}");

    let wrap = std::fs::read_to_string(
        std::fs::read_dir(paired.bound.cli.path().join("wraps"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("phone-")
            })
            .expect("a phone wrap"),
    )
    .unwrap();
    assert!(!wrap.contains(&paired.token), "the wrap holds the bearer");

    let log = paired.bound.audit();
    assert!(decided(&log, "<phone>", "enrolled"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_phone_that_cannot_prove_itself_is_removed() {
    let mut paired = Paired::unenrolled("timeout = 1");
    let (ok, said) = paired.add(Proof::Withhold);
    assert!(!ok, "{said}");
    assert!(said.contains("did not answer within 1s"), "{said}");
    assert!(said.contains("so it was removed"), "{said}");
    assert_eq!(paired.bound.run(&["phone", "ls"], None).unwrap(), "");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_unanswered_prompt_reaches_the_phone_and_its_answer_releases_the_secret() {
    let paired = Paired::new("delay = 0");
    let held = paired.bound.hold();
    let read = paired.read_later("demo/one");

    let shown = paired.pending();
    assert_eq!(
        shown["reason"],
        "release the password for demo/one to test-agent"
    );
    paired.bound.wait_for_prompts(1);
    assert_eq!(paired.approve(&shown).unwrap(), "ok");
    assert_eq!(read.join().unwrap().unwrap(), "value-one");

    // Answered once, and gone from the phone
    assert_eq!(paired.call("pending", "", &[]).unwrap(), "");
    let stale = paired.approve(&shown).unwrap_err();
    assert!(stale.contains("no longer waiting"), "{stale}");

    // The Mac still answers on its own, and a fingerprint there is not a phone approval
    held.release();
    assert_eq!(paired.bound.read("demo/two").unwrap(), "value-two");

    let log = paired.bound.audit();
    assert_eq!(count(&log, "<phone>", "approved on phone"), 1, "{log}");
    assert!(
        log.contains("\"args\":\"release the password for demo/one to test-agent\""),
        "{log}"
    );
    assert_eq!(count(&log, "demo/one", "released"), 1, "{log}");
    assert_eq!(count(&log, "demo/two", "released"), 1, "{log}");
}

/* An open app holds one `pending` call open and hears of a request the moment it is shown, and a
call with nothing to wait for comes back empty when its time is up. */
#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_held_pending_call_returns_when_a_request_appears() {
    let paired = Paired::new("delay = 0");
    let started = Instant::now();
    assert_eq!(paired.call("pending", "", &[("wait", "1")]).unwrap(), "");
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "an empty call returned early"
    );

    let _held = paired.bound.hold();
    let asked = std::thread::scope(|scope| {
        let waiting = scope.spawn(|| {
            let started = Instant::now();
            let shown = paired.call("pending", "", &[("wait", "30")]).unwrap();
            (shown, started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(300));
        let read = paired.read_later("demo/one");
        let (shown, took) = waiting.join().unwrap();
        assert!(took < Duration::from_secs(20), "the call sat out its wait");
        let shown: serde_json::Value = serde_json::from_str(&shown).unwrap();
        paired.approve(&shown).unwrap();
        read.join().unwrap()
    });
    assert_eq!(asked.unwrap(), "value-one");

    let bad = paired.call("pending", "", &[("wait", "soon")]).unwrap_err();
    assert!(bad.contains("not a number of seconds"), "{bad}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn the_phone_is_not_asked_while_touch_id_is_still_within_its_delay() {
    let paired = Paired::new("delay = 600");
    let held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    paired.bound.wait_for_prompts(1);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(paired.call("pending", "", &[]).unwrap(), "");

    held.release();
    assert_eq!(read.join().unwrap().unwrap(), "value-one");
    let log = paired.bound.audit();
    assert_eq!(count(&log, "<phone>", "approved on phone"), 0, "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_closed_lid_asks_the_phone_at_once_and_gives_up_when_it_stays_silent() {
    let paired = Paired::new("delay = 600\ntimeout = 2");
    paired.bound.deny("unavailable");

    let read = paired.read_later("demo/one");
    let shown = paired.pending();
    paired.approve(&shown).unwrap();
    assert_eq!(read.join().unwrap().unwrap(), "value-one");

    let silent = paired.bound.read("demo/two").unwrap_err();
    assert!(silent.contains("Touch ID is unavailable"), "{silent}");
    assert!(
        silent.contains(&format!("{PHONE} did not answer within 2s either")),
        "{silent}"
    );
    assert_eq!(paired.call("pending", "", &[]).unwrap(), "");

    let log = paired.bound.audit();
    assert!(decided(&log, "demo/two", "prompt failed"), "{log}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_lid_closed_on_an_open_prompt_hands_the_request_to_the_phone() {
    let paired = Paired::new("delay = 600\ntimeout = 5");
    let held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    paired.bound.wait_for_prompts(1);
    assert_eq!(paired.call("pending", "", &[]).unwrap(), "");

    // The helper gives up on a prompt the system keeps dismissing with the closed lid's words
    paired.bound.deny("unavailable");
    held.release();
    let shown = paired.pending();
    paired.approve(&shown).unwrap();
    assert_eq!(read.join().unwrap().unwrap(), "value-one");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_typo_under_phone_in_the_config_leaves_touch_id_working() {
    let paired = Paired::new("delay = 600");
    std::fs::write(
        paired.bound.cli.path().join("config.toml"),
        "[phone]\nsoon = 1\n",
    )
    .unwrap();
    assert_eq!(paired.bound.read("demo/one").unwrap(), "value-one");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_refusal_on_the_phone_is_a_denial_and_takes_the_prompt_down() {
    let paired = Paired::new("delay = 0");
    let _held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    let shown = paired.pending();
    paired.bound.wait_for_prompts(1);
    paired
        .call("answer", shown["id"].as_str().unwrap(), &[("deny", "1")])
        .unwrap();

    // The prompt is still held open, so the read can only have ended because it was taken down
    let refused = read.join().unwrap().unwrap_err();
    assert!(
        refused.contains(&format!("denied: refused on {PHONE}")),
        "{refused}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn only_the_enrolled_phone_sees_or_answers_a_request() {
    let mut paired = Paired::new("delay = 0");
    let _held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    let shown = paired.pending();
    let id = shown["id"].as_str().unwrap();

    // The bearer from another node, as a copied one would arrive
    let elsewhere = paired
        .call_from(
            "100.64.0.7",
            &serde_json::json!({
                "op": "phone", "agent": "", "action": "pending", "token": paired.token,
            }),
        )
        .unwrap_err();
    assert!(elsewhere.contains("now dials in as server"), "{elsewhere}");

    // The local socket, which every process on the Mac can reach
    let local = ask_socket(
        &paired.bound,
        &serde_json::json!({
            "op": "phone", "agent": "", "action": "pending", "token": paired.token,
        })
        .to_string(),
    );
    assert!(
        local.contains("over the tailnet, not this socket"),
        "{local}"
    );

    // A box that opens to something other than this store's key, masked as the phone's would be
    let other: Vec<u8> = age_key()
        .bytes()
        .zip(paired.mask())
        .map(|(a, b)| a ^ b)
        .collect();
    let (ephemeral, sealed) = seal_answer(shown["key"].as_str().unwrap(), id, &other);
    let wrong = paired
        .call(
            "answer",
            id,
            &[("ephemeral", &ephemeral), ("sealed", &sealed)],
        )
        .unwrap_err();
    assert!(wrong.contains("a different key"), "{wrong}");

    // The right key sealed for another request
    let key = unbase64(shown["ciphertext"].as_str().unwrap());
    let (ephemeral, sealed) = seal_answer(shown["key"].as_str().unwrap(), "another", &key);
    let moved = paired
        .call(
            "answer",
            id,
            &[("ephemeral", &ephemeral), ("sealed", &sealed)],
        )
        .unwrap_err();
    assert!(moved.contains("does not open"), "{moved}");

    // And the phone without its bearer
    let token = std::mem::take(&mut paired.token);
    let bare = paired.call("pending", "", &[]).unwrap_err();
    assert!(bare.contains("not the phone enrolled"), "{bare}");
    paired.token = token;

    // None of that used the request up
    paired.approve(&shown).unwrap();
    assert_eq!(read.join().unwrap().unwrap(), "value-one");
}

/// A store key that is not this store's, in the form a wrap holds one
fn age_key() -> String {
    let key = Identity::generate().to_string();
    secrecy::ExposeSecret::expose_secret(&key).to_string()
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn five_wrong_codes_close_the_enrollment() {
    let paired = Paired::unenrolled("");
    let mut child = paired
        .bound
        .cmd()
        .args(["phone", "add"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while !line.trim().starts_with("Code") {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "no code was shown"
        );
    }
    let code = line.trim().trim_start_matches("Code").trim().to_string();
    let wrong = if code == "000000" { "000001" } else { "000000" };

    let public = base64(&[&[4u8][..], &[7u8; 64][..]].concat());
    for _ in 0..5 {
        let refused = paired
            .call("enroll", "", &[("code", wrong), ("public_key", &public)])
            .unwrap_err();
        assert!(refused.contains("not the code"), "{refused}");
    }
    let closed = paired
        .call("enroll", "", &[("code", &code), ("public_key", &public)])
        .unwrap_err();
    assert!(closed.contains("too many wrong codes"), "{closed}");
    assert!(
        paired.bound.prompts().is_empty(),
        "a wrong code raised a prompt"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn removing_the_phone_leaves_touch_id_alone() {
    let paired = Paired::new("delay = 0");
    let removed = paired.bound.cmd().args(["phone", "rm"]).output().unwrap();
    assert!(removed.status.success());
    assert_eq!(paired.bound.run(&["phone", "ls"], None).unwrap(), "");

    let held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    paired.bound.wait_for_prompts(1);
    let gone = paired.call("pending", "", &[]).unwrap_err();
    assert!(gone.contains("no phone is enrolled"), "{gone}");
    held.release();
    assert_eq!(read.join().unwrap().unwrap(), "value-one");

    let log = paired.bound.audit();
    assert!(decided(&log, "<phone>", "removed"), "{log}");
}

/// A relay on loopback that records what the broker sends it, one request per connection
fn fake_relay() -> (String, std::sync::mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let (sender, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }

                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            request.push_str(&String::from_utf8_lossy(&body));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n{{\"ok\":true}}"
            )
            .unwrap();
            let _ = sender.send(request);
        }
    });
    (address, received)
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_unanswered_prompt_asks_the_relay_to_wake_the_phone_and_says_nothing_else() {
    let paired = Paired::new("delay = 0");
    let (relay, received) = fake_relay();
    let id = "1".repeat(32);
    let secret = "2".repeat(64);

    // Only the enrolled phone registers, and only with what the relay hands out
    let stranger = paired
        .call_from(
            "100.64.0.7",
            &serde_json::json!({
                "op": "phone", "agent": "", "action": "notify", "token": paired.token,
                "params": [["relay", relay], ["id", id], ["secret", secret]],
            }),
        )
        .unwrap_err();
    assert!(stranger.contains("now dials in as"), "{stranger}");
    let plain = paired
        .call(
            "notify",
            "",
            &[
                ("relay", "http://relay.example"),
                ("id", &id),
                ("secret", &secret),
            ],
        )
        .unwrap_err();
    assert!(plain.contains("https"), "{plain}");
    paired
        .call(
            "notify",
            "",
            &[("relay", &relay), ("id", &id), ("secret", &secret)],
        )
        .unwrap();

    let _held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    let sent = received
        .recv_timeout(Duration::from_secs(10))
        .expect("the relay was never asked");
    assert!(sent.starts_with("POST /push "), "{sent}");
    let body: serde_json::Value =
        serde_json::from_str(sent.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body, serde_json::json!({ "id": id, "secret": secret }));
    assert!(
        !sent.contains("demo/one"),
        "the secret's name reached the relay: {sent}"
    );

    let shown = paired.pending();
    paired.approve(&shown).unwrap();
    assert_eq!(read.join().unwrap().unwrap(), "value-one");

    // Turned off, the next prompt asks no relay
    paired.call("notify", "", &[("off", "1")]).unwrap();
    let _held = paired.bound.hold();
    let read = paired.read_later("demo/two");
    let shown = paired.pending();
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a relay was asked after off"
    );
    paired.approve(&shown).unwrap();
    assert_eq!(read.join().unwrap().unwrap(), "value-two");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_removed_phone_that_kept_its_wrap_opens_nothing() {
    let mut paired = Paired::new("delay = 0");
    let kept = {
        let held = paired.bound.hold();
        let read = paired.read_later("demo/one");
        let shown = paired.pending();
        // The fake enclave seals nothing, so this is exactly what the phone's Enclave would open
        let copy = shown["ciphertext"].as_str().unwrap().to_string();
        assert!(
            !String::from_utf8_lossy(&unbase64(&copy)).starts_with("AGE-SECRET-KEY"),
            "the phone was handed the bare store key"
        );
        held.release();
        assert_eq!(read.join().unwrap().unwrap(), "value-one");
        copy
    };

    assert!(
        paired
            .bound
            .cmd()
            .args(["phone", "rm"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let (ok, said) = paired.add(Proof::Give);
    assert!(ok, "{said}");
    let _held = paired.bound.hold();
    let _read = paired.read_later("demo/one");
    let mut shown = paired.pending();
    shown["ciphertext"] = serde_json::Value::String(kept);
    let refused = paired.approve(&shown).unwrap_err();
    assert!(refused.contains("a different key"), "{refused}");
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn an_interrupted_phone_add_leaves_no_phone_that_is_asked() {
    let mut paired = Paired::unenrolled("timeout = 1");
    let (ok, said) = paired.add(Proof::Abandon);
    assert!(!ok, "{said}");
    // The CLI may have started the proof before it died, and then the broker settles it within `wait`
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(paired.bound.run(&["phone", "ls"], None).unwrap(), "");

    paired.bound.deny("unavailable");
    let refused = paired.bound.read("demo/one").unwrap_err();
    assert!(
        !refused.contains("did not answer"),
        "an unproven phone was asked: {refused}"
    );
    assert_eq!(paired.call("pending", "", &[]).unwrap_or_default(), "");

    paired.bound.deny("0");
    let (ok, said) = paired.add(Proof::Give);
    assert!(
        ok,
        "a new phone add did not replace the unproven one: {said}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "mock-enclave"),
    ignore = "needs --features mock-enclave"
)]
fn a_held_pending_call_ends_when_the_request_it_saw_is_answered() {
    let paired = Paired::new("delay = 0");
    let held = paired.bound.hold();
    let read = paired.read_later("demo/one");
    let shown = paired.pending();
    let id = shown["id"].as_str().unwrap().to_string();
    let started = Instant::now();
    let watcher = {
        let paired = &paired;
        std::thread::scope(|scope| {
            let watching =
                scope.spawn(|| paired.call("pending", "", &[("wait", "25"), ("seen", &id)]));
            std::thread::sleep(Duration::from_millis(300));
            held.release();
            watching.join().unwrap()
        })
    };
    assert_eq!(watcher.unwrap(), "");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the held call waited out its hold"
    );
    assert_eq!(read.join().unwrap().unwrap(), "value-one");
}
