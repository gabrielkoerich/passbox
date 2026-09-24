# Ideas for later

None of this is built, and none of it is committed to. It is written down so the
reasoning survives, and so a later session starts from the argument rather than
from scratch.

Two threads: where a plugin seam is worth opening, and asking another machine
for something only that machine can do.

## The measurement first

| Module | Lines | Non-test |
|---|---|---|
| `store.rs` | 664 | the file format and versions |
| `main.rs` | 627 | the CLI |
| `broker.rs` | 542 | approvals, windows, audit |
| `sync.rs` | 346 | **152** |
| `project.rs` | 250 | manifests and grants |
| `mcp.rs` | 222 | the MCP server |
| `se.rs` | 150 | the Enclave helper |

## Two different things are called plugins

They have different costs and different timelines.

**Subcommand extensions** add verbs. `pass` grew a community on these: `pass otp`,
`pass-import`, `pass-update`, and the browser and mobile clients around them. They
do not replace any mechanism, they use the store.

**Backend plugins** replace a mechanism, such as how the key is unwrapped or who
is asked for approval.

The first is cheap here and worth doing early. The second is the rest of this
document.

## Subcommand extensions, and why passbox starts ahead

`pass` sources an extension into its own shell process, so the extension inherits
everything pass can do. That is why user extensions are gated behind
`PASSWORD_STORE_ENABLE_EXTENSIONS=true`.

passbox does not need that trade, because the broker already is the extension
API. A `passbox-otp` asks the broker over the socket exactly as any agent does,
and gets the same prompt, the same window and the same audit line. It never holds
the store key, so it is not in the trust base the way a backend plugin is.

What is missing is only dispatch: `passbox foo` should exec `passbox-foo` from
`PATH` when `foo` is not a built-in verb. That is roughly twenty lines, and it
buys the ecosystem shape that grew `pass`.

Cost: any `passbox-*` binary on `PATH` can then be launched by typing a passbox
command, and can name itself whatever it likes when it calls the broker. The
prompt still names the secret, which is the part that cannot be faked, and the
audit log still records the real process ancestry. Gate it behind an opt-in the
way `pass` does.

## What the core should keep

One question decides it: **does this need the store key in plaintext?**

Everything that does is the product and stays. Everything that does not can be a
separate binary, and then "this program can never see a secret" is a property
someone can check by reading the dependency list rather than the code.

| Keeps the key | Why |
|---|---|
| `crypto.rs`, `store.rs` | the file format |
| `se.rs` | the Enclave and the prompt |
| `broker.rs` | approvals, windows, audit |
| `project.rs` | grants, which the broker reads |
| `init`, `add`, `get`, `ls`, `rm`, `exec` | the idea itself |

| Never needs the key | Size |
|---|---|
| `sync.rs` | 346 |
| `mcp.rs`, which asks the broker like any agent | 222 |
| the `git` passthrough | about 20 |

That is roughly 590 of 2,883 lines, and none of it ever holds a secret.

## Sync moves out whole, rather than behind an interface

An earlier draft of this document argued against extracting sync, on the grounds
that only about 15 of its 152 non-test lines are backend specific and the union
copy with tombstones would stay in core anyway.

That argument holds against making sync a **backend interface** with pluggable
drivers. It does not hold against moving the whole thing out, because `sync.rs`
never decrypts anything. It walks two directories, compares modification times,
copies files and writes tombstones. A `passbox-sync` binary needs no key, no
broker and no prompt.

So the union copy leaves with it, and core loses 346 lines rather than 15.

Rejected: a pluggable sync backend inside core. Every target so far reduces to a
directory, and rclone already covers the rest in fifteen lines.

## The wrap and the approver are the right seam

Two implementations exist and two more are planned:

| | Unwraps the store key | Proves a human agreed |
|---|---|---|
| macOS | Secure Enclave blob | Touch ID |
| any | scrypt passphrase | typing it |
| planned, Linux | YubiKey | a touch on the key |
| planned, servers | asks another machine | Touch ID over there |

This is already an interface in everything but name. `Store::unlock_with_se` and
`Store::unlock_with_passphrase` return the same type and `unlock` in `main.rs`
picks between them. The broker calls `unlock_with_se` directly, which is the
line that stops passbox running anywhere else.

Four implementations of one operation is where an interface earns its place.

## Build the third one first

Do not design the plugin interface before writing the YubiKey path as concrete
code. An interface drawn from two cases tends to fit neither the third nor the
fourth, and remote approval is the one most likely to break assumptions, since
it is the only approver that is not a local function call.

Order: YubiKey concretely, then remote approval concretely, then extract
whatever the three actually share.

## When it is time, use executables

An external binary, `passbox-<name>` on `PATH`, speaking newline delimited JSON
on stdio. The same shape as age plugins and git remote helpers, and the same
shape `se.rs` already uses to talk to the Swift helper.

Rejected: dynamic libraries. Rust has no stable ABI, so every plugin would need
rebuilding against every release.

Rejected: in-process traits. They keep the code smaller, and they also mean a
plugin shares address space with the process holding the store key.

## What an executable plugin costs

Anything named `passbox-*` on `PATH` becomes part of the trust base, and `PATH`
is writable by anything running as the user. A plugin therefore has to be
recorded in the store, by name and by hash of its binary, with the same rule the
project manifests use: a changed hash means it asks again.

Without that rule this feature hands an attacker a way to be asked for the store
key. It should not ship before the allowlist does.

## Not plugins

- **Secret types**, such as TOTP or SSH keys. These change the payload schema
  rather than the mechanism, so they belong in `store.rs`.
- **The MCP server.** One implementation, and the protocol is the interface.
- **Output formats.** JSON on a flag is smaller than any plugin.

## Remote capabilities, a later idea

Gabriel's examples: Things and Mail run on the Mac, a Linux box cannot have
them, and an agent there needs the data. Generalised, a machine asks another
machine for something only that machine can provide.

Mail is the sharper case. The alternative is giving the Linux box an IMAP
credential, which hands it standing access to the whole mailbox. Asking the Mac
for `mail.search` returns the messages that matched and nothing else, and the
credential never leaves the Mac. The same argument covers Messages, Calendar,
Photos and anything else holding an account rather than a file.

This is the broker with the word "secret" removed. The requester never receives
the underlying access, only the result, which is what `run_with_secret` already
does locally.

Transport, in order of preference:

- **SSH.** No new infrastructure and the trust already exists.
- **Tailscale.** Stable per node identity, which is a better caller identity
  than the self declared agent name, and no ports to manage.
- Rejected: **Cloudflare Tunnel.** Built for public exposure, which is the wrong
  shape for a personal broker, and it puts a third party in the path.

Never a remote shell. The Mac declares named capabilities such as `things.today`
and `things.add`, each carrying the same mode a secret carries, and each raising
the same prompt naming the caller and the capability.

A capability provider never needs the store key, so it is a subcommand extension
rather than a backend plugin, and it inherits the broker's policy unchanged.
