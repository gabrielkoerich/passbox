+++
title = "Comparisons"
weight = 7
+++


### pass

passbox was built next to [pass](https://www.passwordstore.org), and both can stay installed. The table shows where each one is the better tool.

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

The first six rows are why passbox exists. In the rest, `pass` is the better tool: it is older, it runs everywhere, and you can lose your only machine without losing your secrets.

