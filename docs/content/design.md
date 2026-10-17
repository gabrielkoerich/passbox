+++
title = "Design"
description = "Why passbox is built this way, and what each decision cost"
weight = 2
+++

Why passbox is built this way, and what each decision costs.

## The constraint that shaped it

It must build and run with no Apple Developer Program membership.

An earlier attempt at a Touch ID helper created a `kSecClassGenericPassword` item with biometric `SecAccessControl`. Unsigned it returned `-34018`. Ad-hoc signed with `keychain-access-groups` the process was SIGKILLed at launch. That entitlement needs a provisioning profile, which needs a paid identity.

A different API gets past this. CryptoKit's `SecureEnclave` returns the private key as a `dataRepresentation` blob that only that Secure Enclave can use. The blob is an ordinary file, so there is no keychain item and no entitlement. `age-plugin-se` is the proof: it is `adhoc, linker-signed`, carries no entitlements and no team identifier, and works from a Homebrew bottle.

Verified on this hardware: an ad-hoc signed binary created a biometry-gated Secure Enclave key and raised a Touch ID prompt.

## No index

Each secret is one file. The name and the policy live inside the encrypted payload, and the filename is a random 16 byte id.

Rejected: a single `index.age` mapping names to ids. It changes on every write, so two machines conflict on it constantly, and resolving that needs a git merge driver that decrypts both sides, unions by name and re-encrypts. With one file per secret there is no shared mutable file.

Rejected: hashing the name into the filename. Anyone holding the directory could hash a wordlist against it.

Cost: listing names decrypts every file. At a few hundred secrets that is milliseconds, and the broker reuses the key it already holds rather than prompting again.

## One store key, several wraps

One age x25519 key encrypts every secret. It is never written unwrapped. Two kinds of wrap open it: one Secure Enclave key per machine, and a recovery passphrase that exists only once sync is on.

## Sync is off, and the passphrase comes with it

`init` writes only the Enclave wrap. A fresh store holds no file that an attacker could take away and grind at, because the only wrap is bound to one Secure Enclave.

The passphrase wrap is created by `passbox sync --enable`, never before. The passphrase is the weakest link in the design, and only sync needs it: a second machine cannot open the copy any other way. So the passphrase does not exist until the user asks for sync and is told the cost.

Rejected: asking for a passphrase at `init`, which is what the first version did. It writes the one attackable file on day one, for a store that may never leave the Mac.

Cost: a default store has no way back. Lose the Mac and the secrets are gone, which `init` says in as many words.

git is kept separate from this. It backs up the encrypted secrets and excludes the Enclave wraps, so a git remote holds nothing that can open anything. That covers deleting a secret by accident. By design, it does not cover losing the machine: sync covers that, at the cost of a passphrase.

Rejected: a Secure Enclave recipient per secret. It gives hardware enforcement on every read, prompts on every read, and turns key rotation into a rewrite of the whole store.

Rejected: the age plugin protocol. With wraps the Enclave key never appears as an age recipient, so there is no plugin at runtime and the prompt text stays ours.

Cost: one key opens everything, so the Touch ID prompt is the gate on a read, not the key. Cost: adding a Mac needs the recovery passphrase once.

The public key sits in the clear at `wraps/recipient`. Writing a secret therefore needs no unlock and raises no prompt. Reading is what costs a prompt.

## The prompt

`age-plugin-se` passes an `LAContext` into the key operation but carries no reason string, so it shows the generic system prompt. passbox authenticates first, with `LAContext.evaluatePolicy` and its own `localizedReason`, then hands that authenticated context to the key operation. The user sees one prompt, with our wording.

macOS composes the dialog as `<binary> is trying to <reason>.`, so every reason is written as a verb phrase that finishes that sentence, and the helper is unpacked under the name `passbox` because the binary name is the title the reader sees. The result is `passbox is trying to release the password for github/token to claude-code.`

Both of those came from photographing a live prompt. Reading the code had given `passbox-se is trying to claude-code wants the password for github/token.`, which is broken English in the one place the design depends on being read.

The helper is Swift because CryptoKit's `SecureEnclave` is the only API that returns a usable key blob. It is compiled by `build.rs`, embedded in the binary, and unpacked to `~/Library/Caches/passbox` on first use, so `cargo install` and `brew install` stay one step.

Cost: a second language, and `swiftc` at build time.

## What the prompt can and cannot tell you

**The secret name in the prompt is trustworthy. The agent name is not.**

The caller sets the agent name with `PASSBOX_AGENT`. The broker cannot verify it, because the peer on the socket is always `passbox` itself and the real agent sits somewhere up the process tree behind a shell. The broker reads the peer pid from the kernel with `LOCAL_PEERPID`, walks the process ancestry, and records it in the audit log. When `PASSBOX_AGENT` is unset, the prompt name comes from that ancestry: the first process that is not passbox and not a shell. It is still a label, as unverified as the variable it replaces.

Two things hold: no agent gets a secret without a finger on the sensor, and the prompt names the secret that gets read.

Per-agent allowlists are therefore not implemented. They need verifiable identity, which means matching the ancestor's code signature.

## The broker

A single process serving a unix socket at 0600, a thread per connection. A prompt holds the broker's lock, so only one dialog is ever on screen and the next request that needs one waits for it, as long as it takes, with no timeout and no retry. Tokens sit behind a lock of their own, so a token read is answered while a prompt waits. No async runtime, because a biometric prompt blocks anyway. The first command to need it starts it, so there is no launchd plist and no install step.

It holds the store key for 300 seconds of inactivity and then drops it, and keeps running. Rejected: exiting to drop the key, which it did before the SSH agent. `SSH_AUTH_SOCK` must always reach a live socket, or every `ssh` and `git` call fails until something starts the broker again. Cost: the key is cleared in place, which relies on the wiping allocator below, where exiting handed the memory back to the kernel. It exits when the binary it was started as is replaced, as `brew upgrade` does, between requests, so launchd starts the new version. Rejected: a Homebrew `post_install` that restarts the LaunchAgent, which knows only that one install path. The cost is the same as any restart: live grants end.

Every read raises the prompt. A grant token is the only way to skip it: the broker holds the granted values in memory and releases them without asking again until the token lapses.

Rejected: per-secret modes and a per-agent approval window. An earlier version let a secret be marked open, approved for a window after one prompt, or blocked with a never flag. One rule is simpler, and a never flag gave false assurance, because one key opens the whole store and any process running as the user reads around a software flag. Cost: a secret an agent reads often now needs a grant or injection at launch.

While the broker holds the key it is the boundary, so it is hardened to hold it. It refuses a same-user debugger with `PT_DENY_ATTACH`, takes no core dump, and runs under a global allocator that wipes every freed block, so a decrypted secret does not linger in freed memory. The binary and the Enclave helper are signed with the hardened runtime, which needs no developer account. Root still gets past all of this.

Cost: the broker holds the key in memory while it runs, so a grant can release its secrets without asking again. The hardening stops a reader running as the same user. Root still reaches the key.

## The SSH agent

The broker serves the `ssh-agent` protocol on a second socket, `ssh-agent.sock`, next to its own. A secret is an SSH key when its value is an unencrypted Ed25519 or P-256 OpenSSH private key, so there is no naming rule and no change to the secret format. Rejected: keys only under `ssh/`, a rule to remember for no gain.

Listing keys does not prompt, because ssh lists before every connection. The public halves sit in the clear in `ssh-keys.pub`, which `add` writes and every unlock that reads values rewrites, so a removed key drops out and a synced one appears. Each line carries the key's own comment, never the secret's name. Cost: the comment and public key of every SSH key are readable without a prompt, and a key synced from another Mac is offered only after something on this one opens the store, such as `passbox ls`.

Every signature prompts, naming the key by its comment and the program that ran ssh, such as git. The prompt opens the store, the broker finds the private key whose public half matches, signs, and audits the secret name with the decision `signed`. The list decides only what is offered; the store decides what signs. Grants and project manifests do not cover signatures yet.

Rejected: `ssh-agent-lib`, which needs an async runtime the broker does not have. The protocol is two requests, listing and signing, and everything else fails. Rejected: RSA, which would pull in the `rsa` crate. Secure Enclave keys, which never leave the hardware but are P-256 only and do not sync, are a follow-up.

## Project manifests

A project lists the secrets it needs in `.passbox.toml`, and one prompt grants the whole list for that directory.

The file cannot be the authority. An agent working in the directory can write it, so a manifest that granted access would let any agent grant itself anything. It is a request: nothing is granted without a fingerprint, and the grant is bound to the SHA-256 of the file. Editing the manifest changes the hash and voids the grant, which is what stops an agent quietly adding a line and widening its own access.

The kernel supplies the directory, through the caller's pid and `lsof`. A caller that could name its own working directory could point at a manifest it had approved somewhere else.

Grants are written to `grants-<host>.age`, encrypted to the store key so a local process cannot forge one, and excluded from sync. A grant that travelled would let a machine you have never touched inherit an approval given here.

## Delivery

`passbox exec` injects into one child. The agent composes the command and never sees the value.

`--env` is what every tool supports. `--stdin` is safer, because any process running as you can read a child's environment with `ps eww`.

`exec` with two or more secrets asks once. It grants all the names for 30 seconds and reads each through that token, so a process start with fourteen secrets costs one fingerprint, and a refused grant falls back to one prompt per secret. Cost: the token stays valid for up to 30 seconds after the reads, and the `exec` process is the only caller that holds it.

Rejected: a batch read op in the broker. The grant already approves a list of names with one prompt and works from a client over the tailnet, so a second path would duplicate it.

`PASSBOX_TOKEN` and `PASSBOX_PASSPHRASE` leave the environment at startup. passbox copies them into memory it owns, overwrites the original bytes, because `ps eww` and `/proc/<pid>/environ` read the block exec wrote rather than the live table, and unsets them. A command passbox runs for someone else, an `exec` child, a plugin or an MCP command, also has both removed. Without this an agent could ask `run_with_secret` to print `$PASSBOX_TOKEN` and read the token, or the whole-store passphrase, in the tool result.

Rejected: removing them only from each child. It covers the commands an agent picks, and misses `ps eww` and every subprocess added later. Startup removal covers both, and the per-child removal stays as a second layer.

`passbox get` prints to stdout for interactive use. It refuses when stdout is not a terminal, because a pipe, a file or an agent's capture is where a printed secret leaks. A human who means to capture it, such as a library reading it in process, passes `--reveal`. The test is the terminal, not the caller, so it fails closed, an unknown tool is refused by the same rule that refuses a known one.

Rejected: a blocklist of known agent names. It fails open, because any agent not on the list passes, and the list never catches up. The terminal test needs no list.

Rejected: enforcing the refusal in the broker. `get` and `exec` both send the same read, and the caller's terminal is a client-side fact the broker does not see. A client that lies about which one it is defeats a broker check too, so the guard belongs in the client where the terminal is known.

`passbox copy` puts the value on the clipboard for the clipboard case. The value goes broker to the Swift helper to the pasteboard, never through stdout. The helper marks the entry with the `org.nspasteboard` concealed and transient types, which clipboard managers that honour the convention skip, so the secret never enters paste history. The helper stays alive to clear the clipboard after `--clear` seconds, 20 by default and at most 60, and clears only if the change count is untouched, so a value copied in the meantime is left alone. The cap keeps a secret from sitting on the clipboard for hours because of a typo.

## Sync

The store is opaque files with no shared mutable state, so sync is a union copy: every id on either side, newest modification time wins, and the loser goes into `.versions`.

Deletes travel as tombstones. A `rm` writes `<id>.tomb`, which copies like any other file and suppresses its id everywhere. The algorithm only ever copies files and writes markers, so it cannot delete a secret it misunderstood. Tombstones are pruned after 90 days.

`sync --enable` asks two questions: how a copy is opened, and where it goes. They were one question before, which meant a store that already had a passphrase wrap skipped straight past the destination and silently copied to iCloud. A wrap says nothing about where the copy belongs.

The destination goes in `~/.passbox/config.toml` rather than a shell profile, so a bare `passbox sync` cannot fall back to the iCloud default behind your back. An `engine` key names the kind. The file is excluded from the copy and from git, since each machine picks its own destination.

Rejected: the one-line `~/.passbox/remote` it replaces. It held a bare path, and the kind was guessed from its shape. An accidental YubiKey touch in an editor holding the file open typed a code and a newline into the path, and the next write created a folder with that name and synced there for a day, apart from every other Mac. TOML fails to parse on a stray line, and every value is checked on read. The old file is still read when there is no config.

Only `--enable` creates a destination. Every other sync refuses a folder that is missing, overlaps the store, or holds other files and no passbox copy. Cost: an unplugged USB stick turns each write's copy into a warning, and a new folder has to be chosen with `--enable` or made by hand.

Rejected: syncing the config itself. One edit would move every Mac, but a USB path on one Mac means nothing on another.

A destination given with `--remote` or `PASSBOX_REMOTE` names no engine, so passbox tells the four kinds apart by shape, and tests the git URL forms before the rclone colon so `git@host:repo` is not read as an rclone remote.

Rejected: rclone for the default path. It is an external binary in the read path of a password store, and the default remote is a local directory where a file copy does the whole job. `rclone bisync` needs a `--resync` baseline and a state database because it must tell a delete from a file it has not seen. Immutable ids plus tombstones remove that problem. rclone stays available for real cloud backends.

Rejected: rclone's `iclouddrive` backend. It is marked experimental, and it wants an Apple ID session with 2FA.

Rejected: putting the store inside iCloud Drive directly. A unix socket does not belong in a synced folder, and iCloud evicts file contents to save disk.

Cost: the winner is chosen by file modification time, so a tool that rewrites mtimes can pick the wrong one. The loser is still in `.versions`. Cost: a delete racing an edit can resurrect a secret.

## Listing costs a prompt

`ls` and the MCP `list_secrets` go through the broker like a read: approved with Touch ID and recorded in the audit log.

Rejected: a plaintext list at `~/.passbox/names`, shipped until 0.13.42. It let `ls` answer with no key, but any process running as the user could read every name with no prompt and no audit entry, which undid [No index](#no-index). Version 0.13.43 deletes the file on its first run.

Rejected: an encrypted list. Reading it needs the store key, which is the same cost as decrypting the secrets.

Listing decrypts each file to read its name, but parses only the name, so the value is never built into a string. The decrypted bytes wipe themselves when dropped.

Cost: listing takes a fingerprint, the same as a read. A grant is the only way to skip the prompt.

## Fields are a read-time parse

An entry holds a first line and then `key: value` lines, which is what `pass` uses and what `import-pass` preserves. `--field` parses that on read.

Rejected: a structured payload with typed fields. It would change the file format, need a migration for every entry already imported, and buy nothing the convention does not already carry. The parse is fifteen lines and works on stores written before it existed.

## Testing the broker

Every read on an Enclave store needs a finger, so the broker path was untested end to end. The `mock-enclave` feature swaps the Swift helper for `src/bin/fake-enclave.rs`, which speaks the same commands over the same JSON, prompts nobody, and logs each prompt a person would have seen. The tests run a real broker against it and count the prompts. `PASSBOX_NO_ENCLAVE`, which the tests and CI always set, refuses the real helper, so no test can reach a developer's fingerprint.

The fake must never reach a user. `wrap` sends the plaintext store key to the helper, so a shipped override would hand the key to whatever the environment names. Each guard holds if the ones before it fail:

| Guard | What it stops |
|---|---|
| The feature is off by default | Every release, Homebrew and publish build, none of which enable it |
| `compile_error!` without `debug_assertions` | A release-profile build with the feature, the CI release, `brew install --HEAD` and `cargo install` |
| `abort` outside a cargo target directory, found by `CACHEDIR.TAG` | A mock build that ships anyway. `abort` and not `panic!`, since a panic on a broker thread ends only that thread |
| The fake refuses a store outside the temp directory | The fake opening `~/.passbox` |
| The release job greps each binary for `PASSBOX_SE_HELPER` and runs it outside `target` | Any mistake in how the release was configured |

Rejected: a Rust trait with the Swift helper and a fake behind it. It adds an abstraction with one real implementation to production code, and it skips the process boundary and the JSON, which the fake exercises.

Rejected: gating on `debug_assertions` alone. Every debug build would honour the override, including a `target/debug/passbox` someone uses for real.

CI runs clippy and the tests on Linux, where the host build compiles with an empty Enclave helper and the fake in its place. The caller lookup has a Linux version, `SO_PEERCRED` and `/proc/<pid>/cwd`, beside the macOS one. macOS runs only the release build, which also cross-checks the ECIES and checks the ad hoc signature. The cost: the macOS caller lookup, `LOCAL_PEERPID` and `lsof`, is compiled by the release build but never tested, so a bug in which directory a project grant matches would ship.

Rejected: tests on a macOS runner. They cover the shipped caller lookup, but a macOS runner is slower to start and slower to run, and CI waited on it every push.

Cost: the fake's source ships in the crates.io package, since the binary target must exist to publish, and it builds only with the feature. A plain `cargo test` skips the broker tests, so the full run needs the flag.

## Releasing

The version is computed in its own job before anything is built, because the binaries have to be stamped with the version they ship as. An earlier layout built first and bumped after, so every release carried a binary reporting the previous number.

A failure after the tag is pushed takes the tag back with it. A tag with no release behind it is worse than no tag: `git describe` finds it, so every later run computes a version already taken and the release line stalls until someone cuts it away by hand.

## Known limits

- Lose the Mac and the recovery passphrase and the store is gone.
- The file count is not the secret count, because tombstones linger for 90 days.
- `PASSBOX_PASSPHRASE` turns off the Enclave path. It exists for CI and headless use, and it makes the passphrase the only gate.
- A token keeps its granted values in broker memory until it lapses, and whoever holds the token reads them without a prompt. That is the cost of running unattended, and why a grant names secrets rather than a namespace.
- Tokens live in the broker's memory only, so restarting it revokes every one of them.
- Linux builds the client half only, behind the `host` cargo feature being off. It has no Enclave, no broker server and no `sync`, so it opens the store with a passphrase. Asking a Mac to approve a read is designed, not built.
