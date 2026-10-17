//! The SSH agent protocol, and which secrets it offers. The broker owns the socket and the prompt

use crate::store::{self, Store};
use age::x25519;
use anyhow::{Context, Result, bail};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey, Signature};
use std::io::{Read, Write};

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// Far above any real request, so a bad length cannot make the broker allocate gigabytes
const MAX_MESSAGE: usize = 256 * 1024;
const HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// A secret is an SSH key when its value is an unencrypted Ed25519 or P-256 OpenSSH key
pub fn parse(value: &str) -> Option<PrivateKey> {
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
pub fn keys(store: &Store, key: &x25519::Identity) -> Result<Vec<(String, PrivateKey)>> {
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
pub fn refresh(store: &Store, keys: &[(String, PrivateKey)]) -> Result<()> {
    write(store, keys.iter().map(|(_, k)| k.public_key().clone()))
}

fn write(store: &Store, keys: impl Iterator<Item = PublicKey>) -> Result<()> {
    let mut text = String::new();
    for key in keys {
        text.push_str(&key.to_openssh()?);
        text.push('\n');
    }
    store::write_private(&store.ssh_keys_path(), text.as_bytes())
}

pub fn offered(store: &Store) -> Vec<PublicKey> {
    std::fs::read_to_string(store.ssh_keys_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| PublicKey::from_openssh(l).ok())
        .collect()
}

/// Called by `add`, which has the value in hand, so a new key is offered before the next unlock
pub fn remember(store: &Store, value: &str) -> Result<()> {
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
pub fn label(key: &PublicKey) -> String {
    if key.comment().is_empty() {
        key.fingerprint(HashAlg::Sha256).to_string()
    } else {
        key.comment().to_string()
    }
}

/// One length-prefixed message, or None once the client hangs up
pub fn read_message(stream: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        bail!("a {len} byte message is too long");
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_message(stream: &mut impl Write, body: &[u8]) -> Result<()> {
    put(stream, body)?;
    Ok(stream.flush()?)
}

/// The reply to one request. `sign` raises the prompt, and runs only for a key on offer
pub fn answer(
    request: &[u8],
    offered: &[PublicKey],
    sign: impl FnOnce(&PublicKey, &[u8]) -> Result<Signature>,
) -> Vec<u8> {
    reply(request, offered, sign).unwrap_or_else(|e| {
        eprintln!("ssh agent: {e:#}");
        vec![FAILURE]
    })
}

// Adding, removing and locking keys all fail, since keys come from the store and not the socket
fn reply(
    request: &[u8],
    offered: &[PublicKey],
    sign: impl FnOnce(&PublicKey, &[u8]) -> Result<Signature>,
) -> Result<Vec<u8>> {
    let (&kind, mut rest) = request.split_first().context("an empty request")?;
    let mut out = Vec::new();
    match kind {
        REQUEST_IDENTITIES => {
            out.push(IDENTITIES_ANSWER);
            out.extend((offered.len() as u32).to_be_bytes());
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
            let signature = sign(wanted, data)?;
            out.push(SIGN_RESPONSE);
            put(&mut out, &Vec::<u8>::try_from(signature)?)?;
        }
        _ => out.push(FAILURE),
    }
    Ok(out)
}

fn put(out: &mut impl Write, bytes: &[u8]) -> Result<()> {
    out.write_all(&(bytes.len() as u32).to_be_bytes())?;
    Ok(out.write_all(bytes)?)
}

fn take<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (len, tail) = rest
        .split_first_chunk::<4>()
        .context("a truncated request")?;
    let len = u32::from_be_bytes(*len) as usize;
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
        let pair = Ed25519Keypair::from_seed(&[7; 32]);
        PrivateKey::new(KeypairData::from(pair), "test@passbox.dev").unwrap()
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
            |_, _| unreachable!(),
        );
        let (&kind, rest) = out.split_first().unwrap();
        assert_eq!(kind, IDENTITIES_ANSWER);
        let (count, mut rest) = rest.split_first_chunk::<4>().unwrap();
        assert_eq!(u32::from_be_bytes(*count), 1);
        assert_eq!(take(&mut rest).unwrap(), public.to_bytes().unwrap());
        assert_eq!(take(&mut rest).unwrap(), b"test@passbox.dev");
        assert!(rest.is_empty());
    }

    #[test]
    fn a_signature_verifies_against_the_offered_key() {
        let private = key();
        let public = private.public_key().clone();
        let blob = public.to_bytes().unwrap();
        let out = answer(
            &request(SIGN_REQUEST, &[&blob, b"challenge"], 0),
            std::slice::from_ref(&public),
            |wanted, data| {
                assert_eq!(wanted, &public);
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
            |_, _| unreachable!(),
        );
        assert_eq!(unknown, [FAILURE]);
        let refused = answer(
            &request(SIGN_REQUEST, &[&blob, b"x"], 0),
            &[public],
            |_, _| bail!("denied"),
        );
        assert_eq!(refused, [FAILURE]);
    }

    #[test]
    fn unsupported_and_malformed_requests_fail() {
        assert_eq!(answer(&[17], &[], |_, _| unreachable!()), [FAILURE]);
        assert_eq!(answer(&[], &[], |_, _| unreachable!()), [FAILURE]);
        assert_eq!(
            answer(&[SIGN_REQUEST, 0, 0, 0, 9, 1], &[], |_, _| unreachable!()),
            [FAILURE]
        );
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
        let huge = (MAX_MESSAGE as u32 + 1).to_be_bytes();
        assert!(read_message(&mut huge.as_slice()).is_err());
    }
}
