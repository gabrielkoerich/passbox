+++
title = "About"
weight = 7
+++


### Using it from a program

[`examples/`](https://github.com/gabrielkoerich/passbox/tree/main/examples) holds a [Python](https://github.com/gabrielkoerich/passbox/tree/main/examples/python) and a [Rust](https://github.com/gabrielkoerich/passbox/tree/main/examples/rust) client,
each with a runnable self-check. The same shape works in any language: shell out to
`passbox exec` to hand a secret to a child process, and mint one grant per process rather than
one per read.

For agents specifically, see [AGENTS.md](/agents), and the skill in
[`skills/passbox`](https://github.com/gabrielkoerich/passbox/tree/main/skills/passbox) that teaches a coding agent to use passbox correctly.

### Compared with pass

passbox exists because of the first two rows. It is not a replacement for
[pass](https://www.passwordstore.org) in the rows below them.

| | `pass` | passbox |
|---|---|---|
| Private key at rest | a portable file under a passphrase, attackable offline | sealed to the Secure Enclave, inert on any other machine |
| Entry names | plaintext filenames, and in git commit subjects | inside the ciphertext |
| Authorisation | one GPG passphrase, then the agent caches it | per agent and per secret, with modes and windows |
| Who asked for it | unknowable | named in the prompt and in the audit log |
| Giving one to an agent | prints to stdout | injected into one child, and scrubbed from its output |
| Maturity | a decade old, packaged everywhere | young, unreviewed |
| Platforms | anywhere GPG runs | macOS, with a passphrase-only client on Linux |
| Ecosystem | browser, mobile, dmenu, otp, import | none |
| Losing the machine | keys are portable and backed up by design | the store is gone unless sync is on, then a passphrase or a YubiKey opens it |
| Reading the source | 721 lines of shell | 3,079 lines of Rust and Swift, plus a daemon |

Use passbox for the secrets your agents touch. Keep pass for the ones you cannot
afford to lose, until this has had outside eyes on it.

### What this has and has not been checked against

The parts that came from elsewhere carry other people's review. age and scrypt
come from the `age` crate. The Secure Enclave, HKDF and AES-GCM come from
CryptoKit. The hardware guarantee is Apple's.

What is ours is the composition, and these are the checks on it:

- A second implementation, Python's `cryptography`, opens what CryptoKit sealed.
  Two libraries agreeing is the evidence the construction is standard rather than
  something invented here. It also checks that a stranger's key, a flipped tag
  byte and a swapped ephemeral key are all refused, and that no ephemeral key
  repeats. Run it with `tests/ecies.py`.
- The reference `age` CLI opens the secret files, so the store is standard age
  and stays readable with off the shelf tools if passbox goes away.
- Tampered and truncated files are refused: secrets, the recovery wrap, audit
  records, and grants, which fail closed to no grants at all.
- The base64 the helper is fed matches the RFC 4648 vectors.

### Disclaimer

This is not proven and it is not fault proof.

It is young, and no independent security review has happened yet.
Cross-implementation tests raise confidence. They do not replace an audit, and
nothing above is a proof of security.

Use it for the secrets your agents reach for. Keep another copy of anything you
cannot afford to lose. Findings are welcome.

### Licence

MIT
