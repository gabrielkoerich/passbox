# Design

Why passbox is built this way, and what each decision costs.

## The constraint that shaped it

It must build and run with no Apple Developer Program membership.

An earlier attempt at a Touch ID helper created a `kSecClassGenericPassword` item
with biometric `SecAccessControl`. Unsigned it returned `-34018`. Ad-hoc signed
with `keychain-access-groups` the process was SIGKILLed at launch. That
entitlement needs a provisioning profile, which needs a paid identity.

Changing the API is what gets past this. CryptoKit's `SecureEnclave` returns the
private key as a `dataRepresentation` blob that only that Secure Enclave can use.
The blob is an ordinary file, so there is no keychain item and no entitlement.
`age-plugin-se` is the proof: it is `adhoc, linker-signed`, carries no
entitlements and no team identifier, and works from a Homebrew bottle.

Verified on this hardware: an ad-hoc signed binary created a biometry-gated
Secure Enclave key and raised a Touch ID prompt.

## No index

Each secret is one file. The name and the policy live inside the encrypted
payload, and the filename is a random 16 byte id.

Rejected: a single `index.age` mapping names to ids. It changes on every write,
so two machines conflict on it constantly, and resolving that needs a git merge
driver that decrypts both sides, unions by name and re-encrypts. With one file
per secret there is no shared mutable file.

Rejected: hashing the name into the filename. Anyone holding the directory could
hash a wordlist against it.

Cost: listing names decrypts every file. At a few hundred secrets that is
milliseconds, and the broker caches the map while it holds the key.

## One store key, several wraps

One age x25519 key encrypts every secret. It is never written unwrapped. Two
kinds of wrap open it: one Secure Enclave key per machine, and a recovery
passphrase that exists only once sync is on.

## Sync is off, and the passphrase comes with it

`init` writes only the Enclave wrap. A fresh store holds no file that an
attacker could take away and grind at, because the only wrap is bound to one
Secure Enclave.

The passphrase wrap is created by `passbox sync --enable`, never before. This
matters because the passphrase is the weakest link in the design, and syncing is
the only thing that needs it: a second machine cannot open the copy any other
way. Tying its existence to the feature that requires it means the weak link
does not exist until the user has asked for it and been told the cost.

Rejected: asking for a passphrase at `init`, which is what the first version did.
It writes the one attackable file on day one, for a store that may never leave
the Mac.

Cost: a default store has no way back. Lose the Mac and the secrets are gone,
which `init` says in as many words.

git is kept separate from this. It backs up the encrypted secrets and excludes
the Enclave wraps, so a git remote holds nothing that can open anything. That
covers deleting a secret by accident, and deliberately does not cover losing the
machine. Sync covers that, and charges a passphrase for it.

Rejected: a Secure Enclave recipient per secret. It gives hardware enforcement on
every read, prompts on every read, and turns key rotation into a rewrite of the
whole store.

Rejected: the age plugin protocol. With wraps the Enclave key never appears as an
age recipient, so there is no plugin at runtime and the prompt text stays ours.

Cost: one key opens everything, so passbox enforces per-secret modes in software.
Cost: adding a Mac needs the recovery passphrase once.

The public key sits in the clear at `wraps/recipient`. Writing a secret therefore
needs no unlock and raises no prompt. Reading is what costs a prompt.

## The prompt

`age-plugin-se` passes an `LAContext` into the key operation but carries no reason
string, so it shows the generic system prompt. passbox authenticates first, with
`LAContext.evaluatePolicy` and its own `localizedReason`, then hands that
authenticated context to the key operation. One prompt, our wording.

macOS composes the dialog as `<binary> is trying to <reason>.`, so every reason
is written as a verb phrase that finishes that sentence, and the helper is
unpacked under the name `passbox` because the binary name is the title the reader
sees. The result is `passbox is trying to release the password for github/token
to claude-code.`

Both of those came from photographing a live prompt. Reading the code had given
`passbox-se is trying to claude-code wants the password for github/token.`, which
is broken English in the one place the design depends on being read.

The helper is Swift because CryptoKit's `SecureEnclave` is the only API that
returns a usable key blob. It is compiled by `build.rs`, embedded in the binary,
and unpacked to `~/Library/Caches/passbox` on first use, so `cargo install` and
`brew install` stay one step.

Cost: a second language, and `swiftc` at build time.

## What the prompt can and cannot tell you

**The secret name in the prompt is trustworthy. The agent name is not.**

The caller sets the agent name with `PASSBOX_AGENT`. The broker cannot verify it,
because the peer on the socket is always `passbox` itself and the real agent sits
somewhere up the process tree behind a shell. The broker reads the peer pid from
the kernel with `LOCAL_PEERPID`, walks the process ancestry, and records it in the
audit log.

What holds is that no agent gets a secret without a finger on the sensor, and the
secret named in the prompt is the secret that gets read.

Per-agent allowlists are therefore not implemented. They need verifiable identity,
which means matching the ancestor's code signature.

## The broker

A single process serving a unix socket at 0600, one connection at a time. No async
runtime, because a biometric prompt blocks anyway. The first command to need it
starts it, so there is no launchd plist and no install step.

It holds the store key for 300 seconds of inactivity and then exits. Exiting is
how the key is dropped.

Approval is keyed on the pair of agent and secret. The window runs from the
prompt, not from the last read, so a busy agent still asks again when it expires.

Cost: inside the window the broker process is the boundary. The alternative was a
prompt on every read.

`decide(mode, window, approved_at, now)` is a pure function with unit tests over
every mode, window expiry, a zero window, and an approval stamped in the future.

## Project manifests

A project lists the secrets it needs in `.passbox.toml`, and one prompt approves
the whole list for a window.

The file cannot be the authority. An agent working in the directory can write it,
so a manifest that granted access would let any agent grant itself anything. It
is a request: nothing is approved without a fingerprint, and the approval is
bound to the SHA-256 of the file. Editing the manifest changes the hash and
voids the grant, which is what stops an agent quietly adding a line and widening
its own access.

The kernel supplies the directory, through the caller's pid and `lsof`. A caller
that could name its own working directory could point at a manifest it had
approved somewhere else.

`never` is never covered, because the deny arm is reached before any manifest is
consulted.

Grants are written to `grants-<host>.age`, encrypted to the store key so a local
process cannot forge one, and excluded from sync. A grant that travelled would
let a machine you have never touched inherit an approval given here.

## Delivery

`passbox exec` injects into one child. The agent composes the command and never
sees the value.

`--env` is what every tool supports. `--stdin` is safer, because any process
running as you can read a child's environment with `ps eww`.

`passbox get` prints to stdout for interactive use. A `never` secret is refused
when the caller is an agent.

## Sync

The store is opaque files with no shared mutable state, so sync is a union copy:
every id on either side, newest modification time wins, and the loser goes into
`.versions`.

Deletes travel as tombstones. A `rm` writes `<id>.tomb`, which copies like any
other file and suppresses its id everywhere. The algorithm only ever copies files
and writes markers, so it cannot delete a secret it misunderstood. Tombstones are
pruned after 90 days.

`sync --enable` asks two questions: how a copy is opened, and where it goes. They
were one question before, which meant a store that already had a passphrase wrap
skipped straight past the destination and silently copied to iCloud. A wrap says
nothing about where the copy belongs.

The destination goes in `~/.passbox/remote` rather than a shell profile, so a bare
`passbox sync` cannot fall back to the iCloud default behind your back. passbox
tells the four kinds apart by shape, and tests the git URL forms before the rclone
colon so `git@host:repo` is not read as an rclone remote. That file is excluded
from the copy, since each machine picks its own destination.

Rejected: rclone for the default path. It is an external binary in the read path
of a password store, and the default remote is a local directory where a file copy
does the whole job. `rclone bisync` needs a `--resync` baseline and a state
database because it must tell a delete from a file it has not seen. Immutable ids
plus tombstones remove that problem. rclone stays available for real cloud
backends.

Rejected: rclone's `iclouddrive` backend. Marked experimental, and it wants an
Apple ID session with 2FA.

Rejected: putting the store inside iCloud Drive directly. A unix socket does not
belong in a synced folder, and iCloud evicts file contents to save disk.

Cost: the winner is chosen by file modification time, so a tool that rewrites
mtimes can pick the wrong one. The loser is still in `.versions`.
Cost: a delete racing an edit can resurrect a secret.

## Listing does not unlock the store

Names live inside the ciphertext, so `ls` decrypted every entry to read them. That meant a
prompt, and a store key left warm in the broker for five minutes afterwards: the largest
privilege there is, spent on the smallest question.

`~/.passbox/names` is a plaintext list, kept in step as the store changes. `ls` reads it and
needs no key. `get` is untouched and still does.

Cost: that one file names what you hold. It is local only, `0600`, skipped by sync and ignored
by a git store, so a copy elsewhere still says nothing. Someone with this disk but not the
Enclave learns what you have, not what it is. That is a real loss against the old behaviour and
it is the price of not escalating to the whole store to answer "what do I have".

A pull clears it, because a sync can bring names this machine has never decrypted. The next `ls`
rebuilds it with one prompt.

Rejected: an encrypted index. It would need the key to read, which is the thing being avoided.

## Fields are a read-time parse

An entry holds a first line and then `key: value` lines, which is what `pass` uses and what
`import-pass` preserves. `--field` parses that on read.

Rejected: a structured payload with typed fields. It would change the file format, need a
migration for every entry already imported, and buy nothing the convention does not already
carry. The parse is fifteen lines and works on stores written before it existed.

## Releasing

The version is computed in its own job before anything is built, because the binaries have to be
stamped with the version they ship as. An earlier layout built first and bumped after, so every
release carried a binary reporting the previous number.

A failure after the tag is pushed takes the tag back with it. A tag with no release behind it is
worse than no tag: `git describe` finds it, so every later run computes a version already taken
and the release line stalls until someone cuts it away by hand.

## Known limits

- Lose the Mac and the recovery passphrase and the store is gone.
- The file count is not the secret count, because tombstones linger for 90 days.
- `PASSBOX_PASSPHRASE` turns off the Enclave path. It exists for CI and headless
  use, and it makes the passphrase the only gate.
- A lease keeps one decrypted value in broker memory for its duration, and anything
  able to reach the socket as you can reads it without a prompt. That is the cost of
  running unattended, and why a lease is per secret rather than per store.
- Linux builds the client half only, behind the `host` cargo feature being off.
  It has no Enclave, no broker server and no `sync`, so it opens the store with a
  passphrase. Asking a Mac to approve a read is designed, not built.
