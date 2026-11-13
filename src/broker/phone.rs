//! A phone as a second approver: enrolling it, the request it is shown, and its race with Touch ID.

use super::audit::{Entry, append_audit_to};
use super::server::{Origin, Shared, UNNAMED, clock};
use super::{Broker, Request};
use crate::store::{self, Store, write_private};
use crate::{project, se, sync};
use age::x25519;
use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// How long `passbox phone add` waits for the phone to dial in with the code
pub(crate) const ENROLL_SECS: u64 = 120;
/// Wrong codes before the window closes, so six digits cannot be walked
const ENROLL_TRIES: u8 = 5;
/// Seconds Touch ID goes unanswered before the phone is asked as well
const DEFAULT_AFTER_SECS: u64 = 15;
/// Seconds the phone has when it is the only approver, as with the lid closed
const DEFAULT_WAIT_SECS: u64 = 60;
/// The helper's opening words when no prompt can be shown, as `swift/passbox-se.swift` writes them
const NO_SENSOR: &str = "Touch ID is unavailable";
/// The longest a phone may hold one `pending` call open, so an idle app is one connection in a while
const MAX_HOLD_SECS: u64 = 30;
/// What the audit log names in place of a secret for a line about the phone itself
const SUBJECT: &str = "<phone>";

/**
 * The store key under a key in the phone's Secure Enclave, sealed the way the Mac's own wrap is.
 * Only that phone opens it, after Face ID, so the file is inert here and anywhere it is copied.
 * Deleting it is the whole of removing the phone
 **/
#[derive(Serialize, Deserialize)]
pub(crate) struct PhoneWrap {
    /// The tailnet node as `tailscale whois` named it at enrollment, which every later call must match
    pub(crate) node: String,
    public_key: String,
    ephemeral: String,
    ciphertext: String,
    /// SHA-256 of the bearer the phone presents, so this file cannot be replayed as the phone
    token: String,
    added: u64,
}

impl PhoneWrap {
    /// None when no phone is enrolled, which leaves every prompt exactly as it was
    pub(crate) fn load(store: &Store) -> Option<Self> {
        let raw = std::fs::read(store.phone_wrap_path()).ok()?;
        match serde_json::from_slice(&raw) {
            Ok(wrap) => Some(wrap),
            Err(e) => {
                eprintln!("{} ignoring an unreadable phone wrap: {e}", clock());
                None
            }
        }
    }
}

/// `[phone]` in `config.toml`: when the phone is asked, and how long it has when it is alone
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Timing {
    pub(crate) after: Duration,
    wait: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            after: Duration::from_secs(DEFAULT_AFTER_SECS),
            wait: Duration::from_secs(DEFAULT_WAIT_SECS),
        }
    }
}

impl Timing {
    pub(crate) fn read(store: &Store) -> Result<Self> {
        let path = sync::config_path(store);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(Timing::default());
        };
        Timing::parse(&text).with_context(|| format!("{} is not valid", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let config: toml::Table = toml::from_str(text)?;
        let mut timing = Timing::default();
        let Some(phone) = config.get("phone") else {
            return Ok(timing);
        };
        for (key, value) in phone.as_table().context("phone must be a table")? {
            let secs = value
                .as_integer()
                .and_then(|n| u64::try_from(n).ok())
                .with_context(|| format!("phone.{key} must be a number of seconds"))?;
            match key.as_str() {
                "after" => timing.after = Duration::from_secs(secs),
                "wait" if secs > 0 => timing.wait = Duration::from_secs(secs),
                "wait" => bail!("phone.wait must be at least a second"),
                other => bail!("unknown key phone.{other}, the keys are after and wait"),
            }
        }
        Ok(timing)
    }
}

/// What ends a wait: the Mac's own prompt, or the phone
enum Event {
    Mac(Result<x25519::Identity>),
    Phone(Result<x25519::Identity>),
}

/// The one request a phone can see. A prompt holds the broker's lock, so there is never a second
struct Pending {
    id: String,
    reason: String,
    since: u64,
    /// Made for this request alone. The phone seals the store key to its public half
    secret: StaticSecret,
    answer: Sender<Event>,
}

/// An open `passbox phone add`
struct Enrolling {
    code: String,
    until: u64,
    tries: u8,
}

/// Reachable without the broker's lock, which a waiting prompt holds, so the phone is never stuck
/// behind the request it is answering
#[derive(Default)]
pub(super) struct Phones {
    pending: Mutex<Option<Pending>>,
    /// Signalled when a request appears, for a phone holding a `pending` call open
    arrived: Condvar,
    enrolling: Mutex<Option<Enrolling>>,
}

/**
 * The answer travels in a box only this request's key opens: X25519 with a key the phone makes
 * for the one message, HKDF-SHA256 salted with both public keys and bound to the request id, then
 * ChaCha20-Poly1305 with the id as associated data. The nonce is zero because the key is used once.
 * The tailnet already encrypts the hop. This holds when the answer travels some other way
 **/
fn open_box(
    secret: &StaticSecret,
    id: &str,
    ephemeral: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let theirs: [u8; 32] = ephemeral
        .try_into()
        .map_err(|_| anyhow!("the answer's key is not 32 bytes"))?;
    let shared = secret.diffie_hellman(&PublicKey::from(theirs));
    if !shared.was_contributory() {
        bail!("the answer's key is not a usable point");
    }
    let mut salt = theirs.to_vec();
    salt.extend_from_slice(PublicKey::from(secret).as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(format!("passbox-phone-v1 {id}").as_bytes(), &mut *key)
        .map_err(|_| anyhow!("could not derive the answer's key"))?;
    ChaCha20Poly1305::new(Key::from_slice(&*key))
        .decrypt(
            &Nonce::default(),
            Payload {
                msg: sealed,
                aad: id.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("the answer does not open, it was sealed for another request"))
}

fn param<'a>(request: &'a Request, key: &str) -> Result<&'a str> {
    request
        .params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .with_context(|| format!("the request has no {key}"))
}

/// The enrolled phone, when the call comes from its node and carries its bearer. The node is
/// the half the control plane vouches for, and the bearer is the half a forged header lacks
fn enrolled(store: &Store, request: &Request, caller: &str) -> Result<PhoneWrap> {
    let wrap = PhoneWrap::load(store).context("no phone is enrolled on this Mac")?;
    if wrap.token != project::hash(request.token.as_bytes()) {
        bail!("this is not the phone enrolled on this Mac");
    }
    // A failed whois says nothing about the pairing, so it must not read as a changed phone
    if caller.starts_with(UNNAMED) {
        bail!("tailscale could not name the caller just now, try again");
    }

    if wrap.node != caller {
        bail!(
            "the phone enrolled as {} and now dials in as {caller}, enroll it again",
            wrap.node
        );
    }
    Ok(wrap)
}

/// Every phone step, none of which waits on the broker's lock except enrolling, which prompts
pub(super) fn handle(
    shared: &Shared,
    request: &Request,
    caller: &str,
    origin: Origin,
) -> Result<String> {
    match (request.action.as_str(), origin) {
        ("open", Origin::Local) => open(shared),
        ("test", Origin::Local) => shared.broker.lock().expect("broker").test_phone(),
        ("enroll", Origin::Tailnet) => enroll(shared, request, caller),
        ("pending", Origin::Tailnet) => pending(shared, request, caller),
        ("answer", Origin::Tailnet) => answer(shared, request, caller),
        ("open" | "test", Origin::Tailnet) => bail!("only the Mac itself starts an enrollment"),
        ("enroll" | "pending" | "answer", Origin::Local) => {
            bail!("a phone reaches the broker over the tailnet, not this socket")
        }
        (other, _) => bail!("no phone step named {other}"),
    }
}

/// `passbox phone add` opens the window and shows the code this returns
fn open(shared: &Shared) -> Result<String> {
    if let Some(wrap) = PhoneWrap::load(&shared.store) {
        bail!(
            "{} is already enrolled, remove it first with `passbox phone rm`",
            wrap.node
        );
    }
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    *shared.phones.enrolling.lock().expect("enrolling") = Some(Enrolling {
        code: code.clone(),
        until: store::now() + ENROLL_SECS,
        tries: 0,
    });
    Ok(code)
}

/// The phone's first call: the code from the Mac's terminal and the public half of its new key
fn enroll(shared: &Shared, request: &Request, caller: &str) -> Result<String> {
    // The wrap pins the node's name, so a phone whois cannot name has nothing to be pinned to
    if caller.starts_with(UNNAMED) {
        bail!("tailscale could not name this phone just now, try again");
    }

    let until = {
        let mut slot = shared.phones.enrolling.lock().expect("enrolling");
        let Some(window) = slot.as_mut().filter(|w| store::now() < w.until) else {
            *slot = None;
            bail!("no enrollment is open, run `passbox phone add` on the Mac");
        };
        window.tries += 1;
        if window.tries > ENROLL_TRIES {
            *slot = None;
            bail!("too many wrong codes, run `passbox phone add` again");
        }
        if window.code != param(request, "code")? {
            bail!("that is not the code the Mac is showing");
        }
        let until = window.until;
        // One code enrolls one phone, whether or not the fingerprint that follows is given
        *slot = None;
        until
    };

    let public_key = param(request, "public_key")?;
    // An uncompressed P-256 point, the form the Enclave hands out and the helper seals to
    if !se::unbase64(public_key).is_some_and(|raw| raw.len() == 65 && raw[0] == 4) {
        bail!("the public key is not an uncompressed P-256 point");
    }
    shared
        .broker
        .lock()
        .expect("broker")
        .enroll_phone(caller, public_key, until)
}

/**
 * What the phone shows and what it needs to answer, or nothing when no prompt is waiting. With
 * `wait` the call stays open that many seconds for a request to appear, so an open app hears of
 * one at once without asking every second, which would also fill the broker's log
 **/
fn pending(shared: &Shared, request: &Request, caller: &str) -> Result<String> {
    let wrap = enrolled(&shared.store, request, caller)?;
    let hold = match param(request, "wait") {
        Ok(secs) => secs
            .parse::<u64>()
            .context("wait is not a number of seconds")?,
        Err(_) => 0,
    };
    let (slot, _) = shared
        .phones
        .arrived
        .wait_timeout_while(
            shared.phones.pending.lock().expect("pending"),
            Duration::from_secs(hold.min(MAX_HOLD_SECS)),
            |slot| slot.is_none(),
        )
        .expect("pending");
    let Some(waiting) = slot.as_ref() else {
        return Ok(String::new());
    };
    Ok(serde_json::json!({
        "id": waiting.id,
        "reason": waiting.reason,
        "since": waiting.since,
        "key": se::base64(PublicKey::from(&waiting.secret).as_bytes()),
        "ephemeral": wrap.ephemeral,
        "ciphertext": wrap.ciphertext,
    })
    .to_string())
}

/// The phone's decision. A release carries the store key, which is checked before anything waits on it
fn answer(shared: &Shared, request: &Request, caller: &str) -> Result<String> {
    let wrap = enrolled(&shared.store, request, caller)?;
    let mut slot = shared.phones.pending.lock().expect("pending");
    let gone = || anyhow!("that request is no longer waiting");
    let waiting = slot
        .as_ref()
        .filter(|w| w.id == request.name)
        .ok_or_else(gone)?;

    let event = if request.params.iter().any(|(k, _)| k == "deny") {
        Event::Phone(Err(anyhow!("denied: refused on {}", wrap.node)))
    } else {
        let ephemeral =
            se::unbase64(param(request, "ephemeral")?).context("ephemeral is not base64")?;
        let sealed = se::unbase64(param(request, "sealed")?).context("sealed is not base64")?;
        let plain = open_box(&waiting.secret, &waiting.id, &ephemeral, &sealed)?;
        Event::Phone(Ok(shared.store.key_from_phone(&plain)?))
    };
    // Taken only now, so an answer that does not open leaves the request up for a real one
    let waiting = slot.take().ok_or_else(gone)?;
    waiting.answer.send(event).map_err(|_| gone())?;
    Ok("ok".to_string())
}

// Where step 3 sends the push. Until then the phone learns of a request by being opened, and
// this is the line in the broker's log that says one is waiting
fn wake(phone: &PhoneWrap) {
    eprintln!(
        "{} waiting for {} to answer in passbox",
        clock(),
        phone.node
    );
}

fn show(phones: &Phones, phone: &PhoneWrap, reason: &str, answer: Sender<Event>) {
    *phones.pending.lock().expect("pending") = Some(Pending {
        id: store::new_id(),
        reason: reason.to_string(),
        since: store::now(),
        secret: StaticSecret::from(rand::random::<[u8; 32]>()),
        answer,
    });
    phones.arrived.notify_all();
    wake(phone);
}

/**
 * Whoever answers first decides. With a prompt on the Mac the phone is asked after `after` and
 * both then stay open for as long as the prompt would have, which is until someone answers. With
 * no prompt possible the phone is asked at once and has `wait`, since nothing on screen says a
 * request is hanging. `asked_after` of None is the phone alone, for the round that proves an
 * enrollment
 **/
fn wait(
    phones: &Phones,
    phone: &PhoneWrap,
    reason: &str,
    (answers, sender): (&Receiver<Event>, Sender<Event>),
    timing: Timing,
    asked_after: Option<Duration>,
) -> Result<(x25519::Identity, Option<String>)> {
    let mut sender = Some(sender);
    let mut ask = |phones: &Phones| {
        if let Some(sender) = sender.take() {
            show(phones, phone, reason, sender);
        }
    };
    let mut no_sensor = None;
    let mut asked = false;
    let mut deadline = Some(Instant::now() + asked_after.unwrap_or(timing.wait));
    if asked_after.is_none() {
        ask(phones);
        asked = true;
    }

    loop {
        let event = match deadline {
            Some(at) => answers.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => answers.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::Mac(Ok(key))) => return Ok((key, None)),
            Ok(Event::Phone(Ok(key))) => return Ok((key, Some(phone.node.clone()))),
            Ok(Event::Mac(Err(e))) if e.to_string().starts_with(NO_SENSOR) => {
                ask(phones);
                asked = true;
                no_sensor = Some(e);
                deadline = Some(Instant::now() + timing.wait);
            }
            Ok(Event::Mac(Err(e)) | Event::Phone(Err(e))) => return Err(e),
            Err(RecvTimeoutError::Timeout) if !asked => {
                ask(phones);
                asked = true;
                deadline = None;
            }
            Err(RecvTimeoutError::Timeout) => {
                let secs = timing.wait.as_secs();
                return Err(match no_sensor {
                    Some(e) => anyhow!("{e:#} {} did not answer within {secs}s either", phone.node),
                    None => anyhow!("{} did not answer within {secs}s", phone.node),
                });
            }
            Err(RecvTimeoutError::Disconnected) => bail!("the prompt ended with no answer"),
        }
    }
}

/// The store key and, when it was the phone that released it, the phone's name. With no phone
/// enrolled this is `unlock_with_se` and nothing else
pub(super) fn unlock(
    store: &Store,
    phones: &Phones,
    reason: &str,
) -> Result<(x25519::Identity, Option<String>)> {
    let Some(phone) = PhoneWrap::load(store) else {
        return Ok((store.unlock_with_se(reason)?, None));
    };
    // A typo in config.toml must not take Touch ID down with it, so the defaults stand in
    let timing = Timing::read(store).unwrap_or_else(|e| {
        eprintln!("{} using the default phone timing: {e:#}", clock());
        Timing::default()
    });
    let (sender, answers) = channel();
    let mac = sender.clone();
    let prompt = store.unlock_with_se_in_background(reason, move |outcome| {
        let _ = mac.send(Event::Mac(outcome));
    })?;
    let outcome = wait(
        phones,
        &phone,
        reason,
        (&answers, sender),
        timing,
        Some(timing.after),
    );
    // Whichever lost is taken down, so neither a dialog nor a request outlives the decision
    prompt.cancel();
    *phones.pending.lock().expect("pending") = None;
    outcome
}

impl Broker {
    /// Touch ID on the Mac and never the phone, since this is what makes a phone an approver
    fn enroll_phone(&mut self, caller: &str, public_key: &str, until: u64) -> Result<String> {
        let key = self
            .store
            .unlock_with_se(&format!("let {caller} approve reads from now on"))
            .map_err(|e| self.refused(caller, &[SUBJECT], e, caller))?;
        // `passbox phone add` has given up by now, so nothing would run the proof or remove a failure
        if store::now() >= until {
            let late = anyhow!("the enrollment window closed before the fingerprint");
            return Err(self.refused(caller, &[SUBJECT], late, caller));
        }

        let mut text = secrecy::ExposeSecret::expose_secret(&key.to_string()).to_string();
        let sealed = se::seal_to(public_key, text.as_bytes());
        text.zeroize();
        let sealed = sealed?;

        let token = hex::encode(rand::random::<[u8; 32]>());
        let wrap = PhoneWrap {
            node: caller.to_string(),
            public_key: public_key.to_string(),
            ephemeral: sealed.ephemeral,
            ciphertext: sealed.ciphertext,
            token: project::hash(token.as_bytes()),
            added: store::now(),
        };
        write_private(&self.store.phone_wrap_path(), &serde_json::to_vec(&wrap)?)?;
        self.audit(&key, caller, SUBJECT, "enrolled", caller)?;
        // The names are for the phone to show its owner. Only the bearer is ever sent back
        Ok(serde_json::json!({
            "token": token,
            "mac": store::hostname(),
            "phone": caller,
        })
        .to_string())
    }

    /// One round with the phone alone, so a pairing that cannot approve fails while the owner is
    /// still at the Mac. The key it returns is checked and dropped, it opens nothing here
    fn test_phone(&mut self) -> Result<String> {
        let phone = PhoneWrap::load(&self.store).context("no phone is enrolled on this Mac")?;
        let timing = Timing::read(&self.store)?;
        let (sender, answers) = channel();
        let outcome = wait(
            &self.phones,
            &phone,
            "confirm this phone can approve reads",
            (&answers, sender),
            timing,
            None,
        );
        *self.phones.pending.lock().expect("pending") = None;
        outcome.map(|_| phone.node)
    }

    /// The line that says a prompt was answered on the phone, ahead of whatever it released
    pub(super) fn approved_on_phone(
        &self,
        key: &x25519::Identity,
        node: &str,
        reason: &str,
    ) -> Result<()> {
        append_audit_to(
            &self.store,
            &key.to_public(),
            &Entry {
                agent: node,
                secret: SUBJECT,
                decision: "approved on phone",
                caller: node,
                args: reason,
                ..Entry::default()
            },
        )
    }
}

pub(super) type PhoneState = Arc<Phones>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The phone's half of the box, written out here the way the app has to write it
    fn seal(to: &PublicKey, id: &str, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ephemeral = StaticSecret::from(rand::random::<[u8; 32]>());
        let public = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(to);
        let mut salt = public.as_bytes().to_vec();
        salt.extend_from_slice(to.as_bytes());
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
            .expand(format!("passbox-phone-v1 {id}").as_bytes(), &mut key)
            .unwrap();
        let sealed = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: plaintext,
                    aad: id.as_bytes(),
                },
            )
            .unwrap();
        (public.as_bytes().to_vec(), sealed)
    }

    #[test]
    fn an_answer_opens_only_for_the_request_it_was_sealed_for() {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        let (ephemeral, sealed) = seal(&PublicKey::from(&secret), "request-1", b"the store key");
        assert_eq!(
            &open_box(&secret, "request-1", &ephemeral, &sealed).unwrap()[..],
            b"the store key"
        );
        assert!(open_box(&secret, "request-2", &ephemeral, &sealed).is_err());

        let other = StaticSecret::from(rand::random::<[u8; 32]>());
        assert!(open_box(&other, "request-1", &ephemeral, &sealed).is_err());
        assert!(open_box(&secret, "request-1", &ephemeral[..31], &sealed).is_err());
        assert!(open_box(&secret, "request-1", &[0u8; 32], &sealed).is_err());
    }

    /**
     * The bytes the iOS app produces from these fixed keys, pinned in its own tests as well, in
     * `ios/Core/Tests`. They came from a third implementation, Python's `cryptography`, so the app
     * and the broker are each checked against something neither of them wrote
     **/
    #[test]
    fn the_apps_answer_opens() {
        let request = StaticSecret::from([0x11; 32]);
        let ephemeral =
            hex::decode("0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20")
                .unwrap();
        let sealed = hex::decode(
            "81bfa93789e621bd66606d5110cb79bffa48ebcbdeec9e69278b8b7cffdcf951ff41f600f798d7",
        )
        .unwrap();
        assert_eq!(
            &open_box(&request, "request-1", &ephemeral, &sealed).unwrap()[..],
            b"AGE-SECRET-KEY-1EXAMPLE"
        );
    }

    #[test]
    fn the_timing_defaults_and_reads_its_two_keys() {
        assert_eq!(Timing::parse("").unwrap(), Timing::default());
        assert_eq!(Timing::default().after, Duration::from_secs(15));
        let set = Timing::parse("[phone]\nafter = 0\nwait = 5\n").unwrap();
        assert_eq!(set.after, Duration::ZERO);
        assert_eq!(set.wait, Duration::from_secs(5));
        assert!(Timing::parse("[phone]\nwait = 0\n").is_err());
        assert!(Timing::parse("[phone]\nafter = \"soon\"\n").is_err());
        assert!(Timing::parse("[phone]\nsoon = 1\n").is_err());
    }
}
