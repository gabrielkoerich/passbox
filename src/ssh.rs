//! The SSH agent protocol, and which secrets it offers. The broker owns the socket and the prompt

use crate::store::{self, Store};
use crate::{broker, plugin, project, sync};
use age::x25519;
use anyhow::{Context, Result, bail};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey, Signature};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
const USERAUTH_REQUEST: u8 = 50;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// A forwarded agent rarely chains more than a few hops, so this bounds what one connection holds
const MAX_BINDS: usize = 16;
/// Far above any real request, so a bad length cannot make the broker allocate gigabytes
const MAX_MESSAGE: usize = 256 * 1024;
const HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// A secret is an SSH key when its value is an unencrypted Ed25519 or P-256 OpenSSH key
pub(crate) fn parse(value: &str) -> Option<PrivateKey> {
    if !value.trim_start().starts_with(HEADER) {
        return None;
    }
    let key = PrivateKey::from_openssh(value).ok()?;
    let usable = matches!(
        key.algorithm(),
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
    );
    (usable && !key.is_encrypted()).then_some(key)
}

/// Every SSH key in the store, with the name it is stored under
pub(crate) fn keys(store: &Store, key: &x25519::Identity) -> Result<Vec<(String, PrivateKey)>> {
    let mut out = Vec::new();
    for id in store.ids()? {
        let secret = store.load(&id, key)?;
        if let Some(private) = parse(&secret.value) {
            out.push((secret.name.clone(), private));
        }
    }
    Ok(out)
}

/**
 * ssh lists keys before every connection, so listing cannot prompt and the public halves sit in
 * the clear. Each carries the key's own comment and never the secret's name, which stays inside
 * the ciphertext. Rebuilt whenever the store key is open, which also drops a removed key
 **/
pub(crate) fn refresh(store: &Store, keys: &[(String, PrivateKey)]) -> Result<()> {
    write(store, keys.iter().map(|(_, k)| k.public_key().clone()))
}

pub(crate) fn rebuild(store: &Store, key: &x25519::Identity) -> Result<()> {
    refresh(store, &keys(store, key)?)
}

fn write(store: &Store, keys: impl Iterator<Item = PublicKey>) -> Result<()> {
    let mut text = String::new();
    for key in keys {
        text.push_str(&key.to_openssh()?);
        text.push('\n');
    }
    store::write_private(&store.ssh_keys_path(), text.as_bytes())
}

pub(crate) fn offered(store: &Store) -> Vec<PublicKey> {
    std::fs::read_to_string(store.ssh_keys_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| PublicKey::from_openssh(l).ok())
        .collect()
}

/// Called by `add`, which has the value in hand, so a new key is offered before the next unlock
pub(crate) fn remember(store: &Store, value: &str) -> Result<()> {
    if !value.trim_start().starts_with(HEADER) {
        return Ok(());
    }
    let Some(private) = parse(value) else {
        eprintln!(
            "the SSH agent offers only unencrypted Ed25519 and P-256 keys, so it will not offer this one"
        );
        return Ok(());
    };
    let mut all = offered(store);
    if !all
        .iter()
        .any(|k| k.key_data() == private.public_key().key_data())
    {
        all.push(private.public_key().clone());
    }
    write(store, all.into_iter())
}

/// How a prompt names a key: its comment, or its fingerprint when it has none
pub(crate) fn label(key: &PublicKey) -> String {
    if key.comment().is_empty() {
        key.fingerprint(HashAlg::Sha256).to_string()
    } else {
        key.comment().to_string()
    }
}

/**
 * What the data being signed is, read from its shape. An `SSHSIG` blob carries the namespace, `git`
 * for a commit, and a login carries the user after the session id. The caller writes both strings,
 * so anything that is not short printable text reads as unrecognised
 **/
pub(crate) fn purpose(data: &[u8]) -> String {
    if let Some(mut rest) = data.strip_prefix(b"SSHSIG") {
        return match take(&mut rest).ok().and_then(printable) {
            Some(namespace) => format!("a {namespace} signature"),
            None => "a signature".to_string(),
        };
    }
    let mut rest = data;
    let login = take(&mut rest).is_ok()
        && rest
            .split_first()
            .is_some_and(|(&b, _)| b == USERAUTH_REQUEST);
    if login {
        rest = &rest[1..];
        return match take(&mut rest).ok().and_then(printable) {
            Some(user) => format!("an SSH login as {user}"),
            None => "an SSH login".to_string(),
        };
    }
    "unrecognised data".to_string()
}

fn printable(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let fits = !text.is_empty() && text.len() <= 64 && text.bytes().all(|b| b.is_ascii_graphic());
    fits.then(|| text.to_string())
}

/// The `[ssh.windows]` section of config.toml: hosts a key may sign logins to without a prompt
#[derive(Default, Debug)]
pub(crate) struct Windows {
    /// Seconds a key stays open for one host key after an approved login to it
    pub hosts: BTreeMap<String, u64>,
    /// Covers every host and length, so editing either one asks again
    pub hash: String,
}

impl Windows {
    /// As the approval prompt lists them, such as `legion 12h, m1 12h`
    pub(crate) fn shown(&self) -> String {
        self.hosts
            .iter()
            .map(|(host, secs)| format!("{host} {}", plugin::span(*secs)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The listed name a host key goes by, read from `known_hosts` or given as its own fingerprint
    pub(crate) fn listed(&self, host: &PublicKey, known_hosts: &str) -> Option<(String, u64)> {
        std::iter::once(host.fingerprint(HashAlg::Sha256).to_string())
            .chain(known_names(known_hosts, host))
            .find_map(|name| self.hosts.get(&name).map(|secs| (name, *secs)))
    }
}

pub(crate) fn windows(store: &Store) -> Result<Windows> {
    let path = sync::config_path(store);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Windows::default());
    };
    parse_windows(&text).with_context(|| format!("{} is not valid", path.display()))
}

pub(crate) fn parse_windows(text: &str) -> Result<Windows> {
    let config: toml::Table = toml::from_str(text)?;
    let Some(ssh) = config.get("ssh") else {
        return Ok(Windows::default());
    };
    let ssh = ssh.as_table().context("ssh must be a table")?;
    if let Some(other) = ssh.keys().find(|k| *k != "windows") {
        bail!("unknown key ssh.{other}, the only one is ssh.windows");
    }
    let Some(section) = ssh.get("windows") else {
        return Ok(Windows::default());
    };
    let section = section.as_table().context("ssh.windows must be a table")?;

    let mut out = Windows::default();
    let mut hashed = String::new();
    for (host, value) in section {
        // A pattern is an "any host" window, refused for the reason a namespace grant is
        let pattern = host.is_empty()
            || host
                .chars()
                .any(|c| matches!(c, '*' | '?' | '!' | ',') || c.is_whitespace() || c.is_control());
        if pattern {
            bail!("{host:?} must name one host as known_hosts lists it, or its SHA256 fingerprint");
        }

        let span = value
            .as_str()
            .with_context(|| format!("{host} must be a duration such as \"12h\""))?;
        let secs = plugin::duration(span)
            .with_context(|| host.clone())?
            .min(broker::MAX_GRANT_SECS);
        let _ = writeln!(hashed, "{host}={secs}");
        out.hosts.insert(host.clone(), secs);
    }
    out.hash = project::hash(hashed.as_bytes());
    Ok(out)
}

/// Plain text like the section, signed under the store key as the plugin record is
pub(crate) fn approval_path(store: &Store) -> std::path::PathBuf {
    store
        .dir
        .join(format!("windows-ssh-{}.json", store::hostname()))
}

pub(crate) fn approved(store: &Store) -> Option<plugin::Approval> {
    plugin::approved_at(&approval_path(store))
}

pub(crate) fn approve(store: &Store, key: &x25519::Identity, hash: &str) -> Result<()> {
    plugin::approve_at(&approval_path(store), "ssh", key, hash)
}

pub(crate) fn known_hosts() -> String {
    std::env::var_os("HOME")
        .map(|home| std::path::Path::new(&home).join(".ssh/known_hosts"))
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default()
}

/// The names `known_hosts` gives a host key. A hashed name cannot be read back, so it is skipped
pub(crate) fn known_names(known_hosts: &str, host: &PublicKey) -> Vec<String> {
    let mut out = Vec::new();
    for line in known_hosts.lines().map(str::trim) {
        // `@cert-authority` and `@revoked` lines vouch for other keys, they name no host
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }

        let mut fields = line.split_whitespace();
        let (Some(names), Some(kind), Some(blob)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let matches = PublicKey::from_openssh(&format!("{kind} {blob}"))
            .is_ok_and(|k| k.key_data() == host.key_data());
        if !matches {
            continue;
        }

        for name in names.split(',') {
            if name.starts_with('|') || name.starts_with('!') {
                continue;
            }

            // `[host]:2222` is the same host on another port
            let bare = name
                .strip_prefix('[')
                .and_then(|n| n.split_once("]:"))
                .map_or(name, |(n, _)| n);
            out.push(bare.to_string());
        }
    }
    out
}

/// One length-prefixed message, or None once the client hangs up
pub(crate) fn read_message(stream: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }
    let len = usize::try_from(u32::from_be_bytes(len))?;
    if len > MAX_MESSAGE {
        bail!("a {len} byte message is too long");
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

pub(crate) fn write_message(stream: &mut impl Write, body: &[u8]) -> Result<()> {
    put(stream, body)?;
    Ok(stream.flush()?)
}

/// A host one connection proved it reached, from `session-bind@openssh.com`
struct Binding {
    host: PublicKey,
    session: Vec<u8>,
    forwarding: bool,
}

/// What one agent connection has proved so far. ssh binds it before it asks for a signature
#[derive(Default)]
pub(crate) struct Connection {
    binds: Vec<Binding>,
}

impl Connection {
    /**
     * The host key a login signature goes to, when the connection proves it. ssh binds the
     * connection to the host key that signed the session id, and a login signs that same id, so the
     * signature is no use to any other server. A forwarded agent or a second bind proves nothing
     * about the last hop, so neither names a host
     **/
    pub(crate) fn destination(&self, data: &[u8]) -> Option<&PublicKey> {
        let [bind] = self.binds.as_slice() else {
            return None;
        };
        if bind.forwarding {
            return None;
        }

        let mut rest = data;
        let session = take(&mut rest).ok()?;
        let login = session == bind.session.as_slice() && rest.first() == Some(&USERAUTH_REQUEST);
        login.then_some(&bind.host)
    }

    fn bind(&mut self, mut rest: &[u8]) -> Result<()> {
        let host = PublicKey::from_bytes(take(&mut rest)?)?;
        let session = take(&mut rest)?;
        let signature = Signature::try_from(take(&mut rest)?)?;
        let forwarding = *rest.first().context("a truncated request")? != 0;
        signature::Verifier::verify(&host, session, &signature)
            .map_err(|_| anyhow::anyhow!("the host key did not sign this session"))?;
        if self.binds.len() >= MAX_BINDS || self.binds.iter().any(|b| b.session == session) {
            bail!("a session bound twice, or too many binds on one connection");
        }

        self.binds.push(Binding {
            host,
            session: session.to_vec(),
            forwarding,
        });
        Ok(())
    }
}

/**
 * The reply to one request. `sign` raises the prompt, and runs only for a key on offer. It gets the
 * host key the signature goes to when the connection proves one, see `Connection::destination`
 **/
pub(crate) fn answer(
    request: &[u8],
    offered: &[PublicKey],
    connection: &mut Connection,
    sign: impl FnOnce(&PublicKey, &[u8], Option<&PublicKey>) -> Result<Signature>,
) -> Vec<u8> {
    reply(request, offered, connection, sign).unwrap_or_else(|e| {
        eprintln!("ssh agent: {e:#}");
        vec![FAILURE]
    })
}

// Adding, removing and locking keys all fail, since keys come from the store and not the socket
fn reply(
    request: &[u8],
    offered: &[PublicKey],
    connection: &mut Connection,
    sign: impl FnOnce(&PublicKey, &[u8], Option<&PublicKey>) -> Result<Signature>,
) -> Result<Vec<u8>> {
    let (&kind, mut rest) = request.split_first().context("an empty request")?;
    let mut out = Vec::new();
    match kind {
        REQUEST_IDENTITIES => {
            out.push(IDENTITIES_ANSWER);
            out.extend(u32::try_from(offered.len())?.to_be_bytes());
            for key in offered {
                put(&mut out, &key.to_bytes()?)?;
                put(&mut out, key.comment().as_bytes())?;
            }
        }
        SIGN_REQUEST => {
            let blob = take(&mut rest)?;
            let data = take(&mut rest)?;
            let wanted = offered
                .iter()
                .find(|k| k.to_bytes().is_ok_and(|b| b == blob))
                .context("a sign request for a key this agent does not offer")?;
            let signature = sign(wanted, data, connection.destination(data))?;
            out.push(SIGN_RESPONSE);
            put(&mut out, &Vec::<u8>::try_from(signature)?)?;
        }
        EXTENSION if take(&mut rest)? == SESSION_BIND => {
            connection.bind(rest)?;
            out.push(SUCCESS);
        }
        _ => out.push(FAILURE),
    }
    Ok(out)
}

fn put(out: &mut impl Write, bytes: &[u8]) -> Result<()> {
    out.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    Ok(out.write_all(bytes)?)
}

fn take<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (len, tail) = rest
        .split_first_chunk::<4>()
        .context("a truncated request")?;
    let len = usize::try_from(u32::from_be_bytes(*len))?;
    let (field, tail) = tail.split_at_checked(len).context("a truncated request")?;
    *rest = tail;
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Verifier;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    /// A fixed seed, so the key is the same on every run and never touches disk
    fn key() -> PrivateKey {
        seeded(7, "test@passbox.dev")
    }

    fn seeded(seed: u8, comment: &str) -> PrivateKey {
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        PrivateKey::new(KeypairData::from(pair), comment).unwrap()
    }

    /// Whether ssh says the agent connection was forwarded, the last byte of a bind
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Hop {
        Direct,
        Forwarded,
    }

    /// A `session-bind@openssh.com` request as ssh sends it, signed by `signer`
    fn bind(host: &PrivateKey, signer: &PrivateKey, session: &[u8], hop: Hop) -> Vec<u8> {
        let signature: Signature = signature::Signer::try_sign(signer, session).unwrap();
        let mut out = vec![EXTENSION];
        put(&mut out, SESSION_BIND).unwrap();
        put(&mut out, &host.public_key().to_bytes().unwrap()).unwrap();
        put(&mut out, session).unwrap();
        put(&mut out, &Vec::<u8>::try_from(signature).unwrap()).unwrap();
        out.push(u8::from(hop == Hop::Forwarded));
        out
    }

    fn login(session: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, session).unwrap();
        out.push(USERAUTH_REQUEST);
        put(&mut out, b"gb").unwrap();
        out
    }

    /// The host key `sign` was handed for one request on this connection
    fn destination(connection: &mut Connection, data: &[u8]) -> Option<PublicKey> {
        let private = key();
        let blob = private.public_key().to_bytes().unwrap();
        let mut seen = None;
        answer(
            &request(SIGN_REQUEST, &[&blob, data], 0),
            &[private.public_key().clone()],
            connection,
            |_, data, host| {
                seen = host.cloned();
                Ok(signature::Signer::try_sign(&private, data)?)
            },
        );
        seen
    }

    fn request(kind: u8, fields: &[&[u8]], flags: u32) -> Vec<u8> {
        let mut out = vec![kind];
        for f in fields {
            put(&mut out, f).unwrap();
        }
        out.extend(flags.to_be_bytes());
        out
    }

    #[test]
    fn a_key_value_is_recognised_and_anything_else_is_not() {
        let text = key().to_openssh(ssh_key::LineEnding::LF).unwrap();
        let parsed = parse(&text).expect("an ed25519 key");
        assert_eq!(parsed.comment(), "test@passbox.dev");
        // `add` trims the trailing newline off a piped value
        assert!(parse(text.trim_end()).is_some());
        assert!(parse("hunter2").is_none());
        assert!(parse(&format!("{HEADER}\nnot a key")).is_none());
    }

    #[test]
    fn identities_list_every_offered_key_with_its_comment() {
        let public = key().public_key().clone();
        let out = answer(
            &[REQUEST_IDENTITIES],
            std::slice::from_ref(&public),
            &mut Connection::default(),
            |_, _, _| unreachable!(),
        );
        let (&kind, rest) = out.split_first().unwrap();
        assert_eq!(kind, IDENTITIES_ANSWER);
        let (count, mut rest) = rest.split_first_chunk::<4>().unwrap();
        assert_eq!(u32::from_be_bytes(*count), 1);
        assert_eq!(take(&mut rest).unwrap(), public.to_bytes().unwrap());
        assert_eq!(take(&mut rest).unwrap(), b"test@passbox.dev");
        assert_eq!(rest.len(), 0, "bytes left after the last key");
    }

    #[test]
    fn a_signature_verifies_against_the_offered_key() {
        let private = key();
        let public = private.public_key().clone();
        let blob = public.to_bytes().unwrap();
        let out = answer(
            &request(SIGN_REQUEST, &[&blob, b"challenge"], 0),
            std::slice::from_ref(&public),
            &mut Connection::default(),
            |wanted, data, host| {
                assert_eq!(wanted, &public);
                assert!(host.is_none(), "an unbound connection names no host");
                Ok(signature::Signer::try_sign(&private, data)?)
            },
        );
        let (&kind, mut rest) = out.split_first().unwrap();
        assert_eq!(kind, SIGN_RESPONSE);
        let signature = Signature::try_from(take(&mut rest).unwrap()).unwrap();
        Verifier::verify(&public, b"challenge", &signature).unwrap();
    }

    #[test]
    fn a_key_not_on_offer_or_a_refused_prompt_fails_without_signing() {
        let public = key().public_key().clone();
        let blob = public.to_bytes().unwrap();
        let unknown = answer(
            &request(SIGN_REQUEST, &[&blob, b"x"], 0),
            &[],
            &mut Connection::default(),
            |_, _, _| unreachable!(),
        );
        assert_eq!(unknown, [FAILURE]);
        let refused = answer(
            &request(SIGN_REQUEST, &[&blob, b"x"], 0),
            &[public],
            &mut Connection::default(),
            |_, _, _| bail!("denied"),
        );
        assert_eq!(refused, [FAILURE]);
    }

    #[test]
    fn the_purpose_is_read_from_the_shape_of_the_data() {
        let mut sshsig = b"SSHSIG".to_vec();
        put(&mut sshsig, b"git").unwrap();
        assert_eq!(purpose(&sshsig), "a git signature");

        let mut login = Vec::new();
        put(&mut login, &[9; 32]).unwrap();
        login.push(50);
        put(&mut login, b"git").unwrap();
        put(&mut login, b"ssh-connection").unwrap();
        assert_eq!(purpose(&login), "an SSH login as git");

        // A caller's string with spaces or control characters cannot reword the prompt
        let mut forged = b"SSHSIG".to_vec();
        put(&mut forged, b"git signature, approve\n").unwrap();
        assert_eq!(purpose(&forged), "a signature");
        assert_eq!(purpose(b"anything"), "unrecognised data");
    }

    #[test]
    fn unsupported_and_malformed_requests_fail() {
        let mut c = Connection::default();
        assert_eq!(
            answer(&[17], &[], &mut c, |_, _, _| unreachable!()),
            [FAILURE]
        );
        assert_eq!(
            answer(&[], &[], &mut c, |_, _, _| unreachable!()),
            [FAILURE]
        );
        assert_eq!(
            answer(
                &[SIGN_REQUEST, 0, 0, 0, 9, 1],
                &[],
                &mut c,
                |_, _, _| unreachable!()
            ),
            [FAILURE]
        );
        let mut other = vec![EXTENSION];
        put(&mut other, b"query").unwrap();
        assert_eq!(
            answer(&other, &[], &mut c, |_, _, _| unreachable!()),
            [FAILURE]
        );
    }

    #[test]
    fn a_bound_connection_names_the_host_only_for_a_login_to_that_session() {
        let host = seeded(1, "legion");
        let mut c = Connection::default();
        assert_eq!(
            answer(
                &bind(&host, &host, b"sid", Hop::Direct),
                &[],
                &mut c,
                |_, _, _| unreachable!()
            ),
            [SUCCESS]
        );
        assert_eq!(
            destination(&mut c, &login(b"sid")).map(|k| k.key_data().clone()),
            Some(host.public_key().key_data().clone())
        );
        // Another session's login, or a commit signature, goes to no host this connection proved
        assert!(destination(&mut c, &login(b"other")).is_none());
        let mut sshsig = b"SSHSIG".to_vec();
        put(&mut sshsig, b"git").unwrap();
        assert!(destination(&mut c, &sshsig).is_none());
    }

    #[test]
    fn a_forged_forwarded_or_second_bind_names_no_host() {
        let host = seeded(1, "legion");
        let liar = seeded(2, "evil");
        let mut forged = Connection::default();
        let out = answer(
            &bind(&host, &liar, b"sid", Hop::Direct),
            &[],
            &mut forged,
            |_, _, _| unreachable!(),
        );
        assert_eq!(out, [FAILURE]);
        assert!(destination(&mut forged, &login(b"sid")).is_none());

        let mut forwarded = Connection::default();
        answer(
            &bind(&host, &host, b"sid", Hop::Forwarded),
            &[],
            &mut forwarded,
            |_, _, _| unreachable!(),
        );
        assert!(destination(&mut forwarded, &login(b"sid")).is_none());

        let mut chained = Connection::default();
        answer(
            &bind(&host, &host, b"sid", Hop::Direct),
            &[],
            &mut chained,
            |_, _, _| unreachable!(),
        );
        answer(
            &bind(&liar, &liar, b"sid2", Hop::Direct),
            &[],
            &mut chained,
            |_, _, _| unreachable!(),
        );
        assert!(destination(&mut chained, &login(b"sid")).is_none());
    }

    #[test]
    fn a_window_names_one_host_and_lasts_at_most_a_day() {
        let parsed = parse_windows("[ssh.windows]\nlegion = \"12h\"\nm1 = \"48h\"\n").unwrap();
        assert_eq!(parsed.hosts["legion"], 12 * 3600);
        assert_eq!(parsed.hosts["m1"], broker::MAX_GRANT_SECS);
        assert_eq!(parsed.shown(), "legion 12h, m1 24h");
        for host in ["\"*\"", "\"*.ts.net\"", "\"a,b\"", "\"!legion\"", "\"\""] {
            let err = parse_windows(&format!("[ssh.windows]\n{host} = \"1h\"\n")).unwrap_err();
            assert!(
                err.to_string().contains("must name one host"),
                "{host}: {err}"
            );
        }
        let err = parse_windows("[ssh]\nany = true\n").unwrap_err();
        assert!(err.to_string().contains("unknown key ssh.any"), "{err}");
        assert!(parse_windows("[ssh.windows]\nlegion = \"soon\"\n").is_err());
    }

    #[test]
    fn no_section_opens_no_window_and_an_edit_changes_the_hash() {
        assert!(parse_windows("").unwrap().hosts.is_empty());
        assert!(
            parse_windows("[plugins.windows]\n\"a.b\" = \"1h\"\n")
                .unwrap()
                .hosts
                .is_empty()
        );
        let a = parse_windows("[ssh.windows]\nlegion = \"1h\"\n")
            .unwrap()
            .hash;
        assert_eq!(
            a,
            parse_windows("[ssh.windows]\nlegion = \"60m\"\n")
                .unwrap()
                .hash
        );
        assert_ne!(
            a,
            parse_windows("[ssh.windows]\nlegion = \"2h\"\n")
                .unwrap()
                .hash
        );
        assert_ne!(
            a,
            parse_windows("[ssh.windows]\nm1 = \"1h\"\n").unwrap().hash
        );
    }

    #[test]
    fn known_hosts_names_a_host_key_and_a_window_lists_it_by_name_or_fingerprint() {
        let legion = seeded(1, "");
        let other = seeded(2, "");
        let line = |names: &str, k: &PrivateKey| {
            format!("{names} {}\n", k.public_key().to_openssh().unwrap())
        };
        let text = [
            "# a comment\n".to_string(),
            line("legion,100.64.0.2", &legion),
            line("[legion.ts.net]:2222", &legion),
            line("|1|c2FsdA==|aGFzaA==", &legion),
            line("@cert-authority *", &legion),
            line("m1", &other),
        ]
        .concat();
        assert_eq!(
            known_names(&text, legion.public_key()),
            ["legion", "100.64.0.2", "legion.ts.net"]
        );

        let windows = parse_windows("[ssh.windows]\nlegion = \"1h\"\n").unwrap();
        assert_eq!(
            windows.listed(legion.public_key(), &text),
            Some(("legion".into(), 3600))
        );
        assert!(windows.listed(other.public_key(), &text).is_none());
        // Without a known_hosts line, a fingerprint names the host key itself
        let print = other.public_key().fingerprint(HashAlg::Sha256).to_string();
        let windows = parse_windows(&format!("[ssh.windows]\n\"{print}\" = \"1h\"\n")).unwrap();
        assert_eq!(windows.listed(other.public_key(), ""), Some((print, 3600)));
    }

    #[test]
    fn a_plugin_record_does_not_pass_as_an_ssh_record() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let key = x25519::Identity::generate();
        plugin::approve(&store, &key, "h").unwrap();
        std::fs::copy(plugin::approval_path(&store), approval_path(&store)).unwrap();
        let copied = approved(&store).unwrap();
        assert!(!copied.verify_for("ssh", &key));
        approve(&store, &key, "h").unwrap();
        assert!(approved(&store).unwrap().verify_for("ssh", &key));
    }

    #[test]
    fn a_message_round_trips_and_an_oversized_one_is_refused() {
        let mut wire = Vec::new();
        write_message(&mut wire, &[REQUEST_IDENTITIES]).unwrap();
        let mut reader = wire.as_slice();
        assert_eq!(
            read_message(&mut reader).unwrap().unwrap(),
            [REQUEST_IDENTITIES]
        );
        assert!(read_message(&mut reader).unwrap().is_none());
        let huge = (u32::try_from(MAX_MESSAGE).unwrap() + 1).to_be_bytes();
        assert!(read_message(&mut huge.as_slice()).is_err());
    }
}
