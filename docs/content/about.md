+++
title = "About"
weight = 7
+++


### Compared with pass

It is not a replacement for [pass](https://www.passwordstore.org).

| | `pass` | passbox |
|---|---|---|
| Private key at rest | a portable file under a passphrase, attackable offline | sealed to the Secure Enclave, inert on any other machine |
| Entry names | plaintext filenames, and in git commit subjects | inside the ciphertext |
| Authorisation | one GPG passphrase, then the agent caches it | per agent and per secret, with modes and windows |
| Who asked for it | unknowable | named in the prompt and in the audit log |
| Giving one to an agent | prints to stdout | injected into one child, and scrubbed from its output |
| Asking from an agent | a shell command it composes | MCP tools that cannot return a value |
| A job at 3am | the agent holds the passphrase | injected at launch, or a token scoped to named secrets |
| Another machine | copy the key there | it asks the Mac, and the fingerprint happens there |
| Maturity | a decade old, packaged everywhere | young, unreviewed |
| Platforms | anywhere GPG runs | macOS holds the store, Linux asks it |
| Ecosystem | browser, mobile, dmenu, otp, import | Python, Rust and TypeScript clients, and an MCP server |
| Losing the machine | keys are portable and backed up by design | the store is gone unless sync is on, then a passphrase or a YubiKey opens it |
| Reading the source | 721 lines of shell | 3,798 lines of Rust and Swift, plus a daemon |

The first six rows are why passbox exists. The rest is where `pass` is the better tool, and
that is most of them: it is older, it runs everywhere, and losing your only machine is
survivable by design rather than by remembering to turn sync on.

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
