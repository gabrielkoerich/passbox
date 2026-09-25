# passbox

A password store for machines that run agents. An agent asks for a secret, macOS
raises a Touch ID prompt naming the agent and the secret, and the value goes into
one child process rather than into the agent.

<p align="center">
  <img src="docs/prompt.png" alt="Touch ID prompt naming the secret and the agent" width="340">
</p>

Secrets are ordinary [age](https://age-encryption.org) files. The broker decides
who may open them. See [docs/DESIGN.md](docs/DESIGN.md) for why it is built this
way and what it costs.

Runs with no Apple Developer Program membership.

## Install

```bash
brew install gabrielkoerich/tap/passbox
passbox init
```

Recent Homebrew asks you to trust a third party tap before it will build from
one. If the install stops and says so, run `brew trust --formula
gabrielkoerich/tap/passbox` and try again.

That downloads a prebuilt binary. Nothing is compiled, so Rust is not needed.
Building from source, with `--build-from-source` or `--HEAD`, needs Rust and the
Command Line Tools for `swiftc`. A full Xcode is not needed either way.

On Linux `brew install` gives the client build: no Secure Enclave, no broker and
no `sync`, so it opens the store with a passphrase. See [Known
limits](docs/DESIGN.md#known-limits).

`init` binds the store to this Mac's Secure Enclave and asks for nothing else.
There is no passphrase, so there is no file anyone can carry off and grind at.

The cost is plain: the store opens on this Mac only. Lose it and the secrets are
gone. Turning on sync is what adds a way back, and it is off until you ask.

## Use

```bash
printf 'ghp_xxx' | passbox add github/token
passbox ls
passbox get github/token
```

### Coming from pass

```bash
passbox import-pass              # everything
passbox import-pass bean         # one namespace
passbox import-pass bean/token   # one entry
```

Each entry is decrypted through GPG and re-encrypted to the store key. The whole
body is kept, so the `key: value` lines many pass entries carry under the
password survive. Entries already in the store are skipped unless you pass
`--force`, and nothing in `pass` is changed or removed.

### Giving a secret to an agent

The value goes into one child process and never into the agent.

```bash
passbox exec --env GITHUB_TOKEN=github/token -- gh api /user
passbox exec --stdin db/password -- psql
```

Prefer `--stdin` where the tool accepts it. Any process running as you can read a
child's environment with `ps eww`.

Set `PASSBOX_AGENT` so the prompt names the caller.

```bash
PASSBOX_AGENT=claude-code passbox exec --env GH_TOKEN=github/token -- gh pr list
```

The prompt then reads `passbox is trying to release the password for
github/token to claude-code.` macOS writes the opening clause from the binary
name, and passbox writes the rest.

### Through MCP

```bash
claude mcp add passbox -- passbox mcp
```

The server exposes two tools, and neither returns a secret.

| Tool | Returns |
|---|---|
| `list_secrets` | names only |
| `run_with_secret` | the command's output, with the value scrubbed out of it |

There is deliberately no `get_secret`. A tool result lands in the model's context,
where it is logged and sent onward, so the tools run the command for the agent
instead of handing it the value. If the command prints the secret anyway,
passbox replaces it in the output before returning.

The agent name in the prompt comes from the MCP handshake, so it is the client's
own `clientInfo.name` rather than a guess up the process tree.

### Approving a project once

A project declares what it needs in `.passbox.toml`:

```toml
secrets = ["github/token", "npm/token"]
window_secs = 3600
```

The first time an agent working in that directory asks for one of them, passbox
shows a single prompt covering the whole list, and does not ask again for the
window. The default is an hour and the cap is twelve.

**The file is a request, not a grant.** An agent can write one itself, so nothing
is approved until you put your finger on the sensor. The approval is bound to the
file's SHA-256: add a secret to the list and the hash changes, so it asks again.
A secret set to `never` is refused no matter what the manifest says.

The project is the caller's working directory, read from the kernel rather than
taken from the request, so a caller cannot point at a manifest somewhere else.
Grants live in `grants-<host>.age`, encrypted, and never sync.

### Permission modes

Every secret carries one.

| Mode | Behaviour |
|---|---|
| `open` | No prompt, for a token an agent reads all day |
| `window` | One prompt per agent and secret per window, the default |
| `always` | A prompt on every read |
| `never` | Never released to an agent, interactive `get` only |

```bash
passbox mode banking/login never
passbox add github/token --mode window --window 600
```

A new value never widens access. Adding over an existing secret keeps the mode it
already had unless you pass `--mode`.

### Seeing what was released

```bash
passbox audit --tail 50
```

Every decision is logged, encrypted, one record per line.

## Backup, with no key anywhere

git carries the encrypted secrets and nothing that opens them.

```bash
passbox git init
passbox git remote add origin git@github.com:you/passbox-store.git
passbox git add -A && passbox git commit -m backup && passbox git push
```

The Secure Enclave wraps are excluded, so the remote holds opaque age files that
only this Mac can read. That protects you from deleting a secret by accident. It
does **not** protect you from losing the Mac, because nothing in the backup can
open it. For that, turn on sync.

## Sync

Sync is off, and nothing leaves the Mac until you run `passbox sync` yourself.
There is no timer and no syncing on write.

```bash
passbox sync --enable
passbox sync
```

`--enable` asks two questions.

The first is how a second machine gets in, a YubiKey or a passphrase. See [If you
lose the Mac](#if-you-lose-the-mac).

The second is where the copy goes:

```
Where should the copy go?

  1) iCloud Drive, a folder on this Mac that Apple replicates
  2) A directory you name, such as a USB stick or Dropbox
  3) A git remote, which also gives you history
  4) An rclone remote, for S3, B2, Drive and the rest
```

The answer is written to `~/.passbox/remote`, so later runs of bare `passbox sync`
go to the same place. Running `--enable` again shows the current destination and
offers to change it. `PASSBOX_REMOTE` overrides one run without changing the file.

| Answer | Goes to | Needs |
|---|---|---|
| iCloud Drive | `~/Library/Mobile Documents/com~apple~CloudDocs/passbox` | nothing |
| a directory | wherever you say | nothing |
| a git remote | `~/.passbox` made a repo, pushed on each sync | `git` |
| an rclone remote | any of rclone's backends | `rclone` |

iCloud Drive is an ordinary directory on macOS, so the default path is a directory
to directory copy. No account, no rclone, no network code.

passbox tells them apart by shape. A remote starting `git@`, `ssh://` or `https://`,
or ending `.git`, is git. One starting `/`, `~` or `.` is a directory. Anything else
holding a colon goes to `rclone bisync`. The rest is a directory.

Git commits after the copy, which gives you history and an off-site remote. Commit
subjects are generic, since a subject naming an entry would undo the encrypted
names.

On a second Mac, `passbox sync` then `passbox machine add`, the same steps as
recovering onto a replacement.

## If you lose the Mac

By default there is no way back. `init` binds the store to this Mac's Secure
Enclave and writes no other wrap, so the key exists in one place and cannot
leave it.

**Time Machine does not help.** It copies `wraps/se-<host>.json` faithfully, and
the file is inert anywhere else. The private half never leaves the Enclave.
Erasing the Mac destroys the Enclave keys, so a restore onto a wiped machine
finds files it cannot open. Only a restore to the same Mac, not erased, still
works.

To have a way back, turn on sync. It asks how the copy should be opened, writes
that wrap, then asks where the copy goes.

```bash
passbox sync --enable
```

```
That copy needs a way in. Two choices:

  1) A YubiKey. Nothing in the copy can be attacked, and you keep the token.
  2) A passphrase. Works anywhere, and anyone holding the copy can grind it.
```

Choosing the token handles the rest: it offers to install `age-plugin-yubikey`,
and asks before provisioning a slot, because that changes the hardware.

Pick the passphrase knowing the cost. Anyone holding the copy can attack that wrap
offline at their own pace. passbox refuses a passphrase under 12 characters. Use
five or six diceware words.

A wrap only helps where the copy reaches. A USB stick in the same bag as the Mac
survives neither a fire nor a theft.

### A YubiKey instead of a passphrase

A passphrase wrap is the one file in a synced copy worth attacking. A YubiKey
wrap has nothing to grind, because the private half stays in the token.

`passbox sync --enable` does the whole setup, so the commands below are only for
adding a token to a store that already syncs.

```bash
passbox yubikey-add age1yubikey1...    # the recipient from --list
```

#### A YubiKey on firmware 5.7 needs one command first

Firmware 5.7 sets the PIV management key algorithm to **AES192**, and
`age-plugin-yubikey` supports TDES only, so a brand new token fails. A factory
reset does not help, because the reset sets AES192 too.

```bash
ykman piv info | grep "Management key algorithm"   # AES192 means read on
ykman piv access change-management-key -a tdes \
  -n 010203040506070801020304050607080102030405060708
```

passbox checks this before it asks the plugin for anything, so it says which
algorithm is set and what to run rather than failing inside the plugin. The
symptom without the check is an error naming neither the cause nor the fix, and
on a half-finished attempt a private key is left in a PIV slot with no
certificate. `ykman piv keys delete <slot>` clears that.

This touches the PIV applet only. OpenPGP is a separate applet on the same chip,
so PGP keys and their PIN are unaffected.

The copy in iCloud is then inert without the token in your hand. Touch ID stays
the daily path on this Mac; the token is only for recovery. `machine add` uses it
when the wrap is there, and falls back to the passphrase otherwise.

| | passphrase wrap | YubiKey wrap |
|---|---|---|
| A stolen copy | can be ground offline | is useless |
| You must keep | the phrase | the token |
| Recovery needs | the phrase | the token and `age-plugin-yubikey` |

Enrol a second token. age takes any number of recipients, so `yubikey-add` adds
to the same wrap rather than replacing it, and either token then opens the store.

```bash
passbox yubikey-add age1yubikey1...   # the second one
```

Recipients are public keys, so they sit in the clear in `wraps/yubikey.recipients`.

passbox uses the **PIV** applet. OpenPGP keys live in a separate applet on the
same chip and are never touched. Before provisioning a slot it reads what PIV
already holds and shows you, using `ykman` when it is installed.

### Recovering on a replacement Mac

```bash
brew install gabrielkoerich/tap/passbox
cp -R ~/Library/Mobile\ Documents/com~apple~CloudDocs/passbox ~/.passbox
passbox machine add
```

`machine add` asks the recovery passphrase, then binds the new Mac's Enclave, so
reads go back to asking for a fingerprint.

Rejected: backing up the Enclave key itself. It cannot be exported, which is the
property that makes a stolen copy of the store useless.

## Undoing a change

Every write keeps the last 5 versions, and `rm` keeps the file too.

```bash
passbox restore github/token            # list versions
passbox restore github/token --index 0  # put the newest one back
```

## What is on disk

```text
~/.passbox/
  store/<random-id>.age     one self describing secret per file
  store/<random-id>.tomb    deletion marker
  store/.versions/<id>/     earlier versions, kept local
  wraps/recipient           the store public key, no secret in it
  wraps/recovery.age        the store key under your passphrase, only once sync is on
  wraps/se-<host>.json      the store key under that Mac's Secure Enclave
  audit-<host>.log          one encrypted record per line
  broker.sock               the approval socket
```

The filename is a random id. Names live inside the ciphertext, so nothing on disk
says what a secret is called. What still leaks: how many secrets exist, their
sizes, and their modification times.

## Environment

| Variable | Effect |
|---|---|
| `PASSBOX_DIR` | Where the store lives, default `~/.passbox` |
| `PASSBOX_REMOTE` | Overrides the destination for one run, ahead of the one `sync --enable` recorded |
| `PASSBOX_AGENT` | Name shown in the prompt beside the secret |
| `PASSBOX_PASSPHRASE` | Supplies the passphrase for CI and headless use, and turns off the Enclave path |

## Building

```bash
cargo test
cargo test -- --ignored   # the Secure Enclave round trip, needs a finger
```

`build.rs` compiles the Swift helper with `swiftc` from the Command Line Tools.

## Listing names without unlocking

`ls` used to decrypt every entry to learn the names, which meant a prompt and a store key warm
in the broker afterwards. That is the largest privilege there is for the smallest question.

A plaintext list of names now lives at `~/.passbox/names`, written as the store changes, so `ls`
answers with no key and no prompt. `get` is unaffected and still needs one.

The cost, stated plainly: that one file names what you hold. It never leaves the machine. Sync
skips it, a store that is a git repo ignores it, and it is `0600`, so a copy elsewhere still says
nothing about you. Someone with this disk but not the Enclave learns what you have, not what it
is.

A sync that pulls deletes the list, because a pull can bring names this machine has never
decrypted. The next `ls` rebuilds it with one prompt.

## Fields in one entry

An entry can hold more than a password. The first line is the secret, later `key: value` lines
are fields, which is the layout `pass` uses and `import-pass` keeps.

```bash
passbox get db/prod                  # the whole thing
passbox get db/prod --field username # just that one
```

Reading one field hands a caller the password without the note beside it.

## A job that runs unattended

A window asks for a fingerprint when it lapses, which nothing running at 3am can answer. A
**lease** is the answer to that: one approval, then the broker keeps that one value for as long
as you set, and asking for anything else still needs a fingerprint.

```bash
passbox mode trade/signing-key window --lease 86400
```

### A token, for a job that should not get everything

A lease is keyed on the secret, so for its life anything that reaches the socket gets that
value. A token is narrower: one approval mints a bearer token that opens **only the secrets it
was granted**, for whoever holds it, until it lapses.

```bash
export PASSBOX_TOKEN=$(passbox grant bean/hl-mainnet-pk --for 3600)
```

**Name the secrets, not the namespace.** A token is only worth minting if it is narrower than
the store, and `grant bean` on a project with twenty entries hands over all twenty to save one
prompt. List what the job reads:

```bash
passbox grant bean/hl-mainnet-pk bean/coinmarketcap-api-key --for 3600
```

A namespace is accepted, for the case where a job genuinely reads all of it:

```bash
passbox grant r2/storage --for 3600
```

Names and namespaces mix in one grant, so a job asks for what it needs across the store and
gets nothing else.

One fingerprint. The token goes to stdout and the covered names to stderr, so the command above
captures the token alone. Every read that presents it is audited as `by token`.

| | Lease | Token |
|---|---|---|
| Who gets it | anything on the socket | whoever holds the token |
| Covers | one secret | the names granted, and no others |
| Ends | when it lapses | when it lapses, or the broker restarts |
| Ceiling | none | 24 hours |

Prefer a token. The lease is the blunter instrument, and it is kept because it needs nothing
passed along to a child.

Both need the broker, so a passphrase-only store has neither: it reads without a prompt anyway.

A namespace works too, and costs one fingerprint rather than one per secret:

```bash
passbox mode bean window --lease 86400      # everything under bean/
```

A lease is keyed on the secret, not on the agent that asked, so one approval covers every
program that reads it. Without a lease, two agents reading the same secret prompt twice.

The lease holds the value, not the store key. That is the whole difference. The store key opens
every secret, so the broker drops it after five minutes; a lease covers the secret it was
approved for and nothing else. A broker holding a day-long lease on one key cannot be talked
into handing over a second one.

| | Window | Lease |
|---|---|---|
| Covers | one agent and one secret | one secret |
| When it lapses | prompts again | prompts again |
| Survives the store key expiring | no | yes |
| Good for | you, at the keyboard | a daemon, unattended |

Leased reads are still audited, and `passbox audit` shows them as `within lease`.

The honest limit: for the lease's duration that value sits in broker memory, and anything able
to reach the socket as you can read it without a prompt. That is the cost of unattended access,
and it is why the lease is per secret rather than per store.

## Using it from a program

[`examples/python`](examples/python) is a small client over the CLI, with a runnable
self-check. The same shape works in any language: shell out to `passbox exec` to hand
a secret to a child process, or `passbox get` when a library needs the value itself.

## Compared with pass

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

## What this has and has not been checked against

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

## Disclaimer

This is not proven and it is not fault proof.

It is young, and no independent security review has happened yet.
Cross-implementation tests raise confidence. They do not replace an audit, and
nothing above is a proof of security.

Use it for the secrets your agents reach for. Keep another copy of anything you
cannot afford to lose. Findings are welcome.

## Licence

MIT
