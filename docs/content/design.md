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

One age x25519 key encrypts every secret. It is never written unwrapped. Three kinds of wrap open it: one Secure Enclave key per machine, a YubiKey, and a recovery passphrase. The last two exist only once sync is on.

## Sync is off, and the passphrase comes with it

`init` writes only the Enclave wrap. A fresh store holds no file that an attacker could take away and grind at, because the only wrap is bound to one Secure Enclave.

`passbox sync --enable` creates the portable wrap, a YubiKey or a passphrase, and nothing creates it before then. The passphrase is the weakest link in the design, and only sync needs it: a second machine cannot open the copy any other way. So the passphrase does not exist until the user asks for sync and is told the cost.

Rejected: asking for a passphrase at `init`, which is what the first version did. It writes the one attackable file on day one, for a store that may never leave the Mac.

Cost: a default store has no way back. Lose the Mac and the secrets are gone, which `init` says in as many words.

git stays separate from this. It backs up the encrypted secrets and excludes the Enclave wraps, so a git remote holds nothing that can open anything. That covers deleting a secret by accident. By design, it does not cover losing the machine: sync covers that, at the cost of a passphrase.

Rejected: a Secure Enclave recipient per secret. It gives hardware enforcement on every read, prompts on every read, and turns key rotation into a rewrite of the whole store.

Rejected: the age plugin protocol. With wraps the Enclave key never appears as an age recipient, so there is no plugin at runtime and the prompt text stays ours.

Cost: one key opens everything, so the Touch ID prompt is the gate on a read, not the key. Cost: adding a Mac needs the YubiKey or the recovery passphrase once.

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

For a request over the tailnet the host part is verified. The PROXY header gives the broker the node's address, `tailscale whois` names it from the control plane, and the prompt reads `<agent> on <host>`. The agent part is still what the client sent.

So passbox has no per-agent allowlists. They need verifiable identity, which means matching the ancestor's code signature.

## The broker

The broker is a single process serving a unix socket at 0600, with a thread per connection. A prompt holds the broker's lock, so only one dialog is ever on screen and the next request that needs one waits for it, as long as it takes, with no timeout and no retry. Tokens sit behind a lock of their own, so a token read is answered while a prompt waits. There is no async runtime, because a biometric prompt blocks anyway. The first command to need it starts it, so a local read needs no install step. `brew services start passbox` keeps it running as a LaunchAgent, which the SSH agent and tailnet clients need.

It holds the store key for 300 seconds of inactivity and then drops it, and keeps running. Rejected: exiting to drop the key, which it did before the SSH agent. `SSH_AUTH_SOCK` must always reach a live socket, or every `ssh` and `git` call fails until something starts the broker again. Cost: the key is cleared in place, which relies on the wiping allocator below, where exiting handed the memory back to the kernel. It exits when the binary it was started as is replaced, as `brew upgrade` does, between requests, so launchd starts the new version. Rejected: a Homebrew `post_install` that restarts the LaunchAgent, which knows only that one install path. The cost is the same as any restart: live grants end.

Every read raises the prompt. A grant token is the only way to skip it: the broker holds the granted values in memory and releases them without asking again until the token lapses.

A grant that presents a live token mints a child with no prompt when every name is in the parent and it expires no later. It is answered under the token lock, like a token read, so it never waits behind a prompt. The child keeps the parent's grant id, and the audit records it on `granted`, `delegated` and `by token`, so every worker read traces back to the one fingerprint. Rejected: a `passbox agent` socket like ssh-agent, which is a second daemon doing the broker's job and a bearer credential to whoever reaches it. Rejected: binding a grant to the supervisor's process tree through `LOCAL_PEERPID`, which cannot see into containers on the tailnet. Rejected: short-lived or single-use children, since workers restart and re-read all day, so the narrowing is by name. Cost: a leaked child opens its names until the parent lapses.

`--token-stdin` on `grant` and `exec` reads the token from stdin a byte at a time, so it is in no process environment and `exec` leaves the rest of stdin to its child. Rejected: a buffered read, which would take input meant for the child.

Rejected: per-secret modes and a per-agent approval window. An earlier version let a secret be marked open, approved for a window after one prompt, or blocked with a never flag. One rule is simpler, and a never flag gave false assurance, because one key opens the whole store and any process running as the user reads around a software flag. Cost: a secret an agent reads often now needs a grant or injection at launch.

While the broker holds the key it is the boundary, so it is hardened to hold it. It refuses a same-user debugger with `PT_DENY_ATTACH`, takes no core dump, and runs under a global allocator that wipes every freed block, so a decrypted secret does not linger in freed memory. The binary and the Enclave helper are signed with the hardened runtime. The release binary carries a Developer ID signature, the helper and source builds are ad hoc.

Cost: the broker holds the key in memory while it runs, so a grant can release its secrets without asking again. The hardening stops a reader running as the same user. Root still reaches the key.

## The SSH agent

The broker serves the `ssh-agent` protocol on a second socket, `ssh-agent.sock`, next to its own. A secret is an SSH key when its value is an unencrypted Ed25519 or P-256 OpenSSH private key, so there is no naming rule and no change to the secret format. Rejected: keys only under `ssh/`, a rule to remember for no gain.

Listing keys does not prompt, because ssh lists before every connection. The public halves sit in the clear in `ssh-keys.pub`, which `add` writes and every unlock that reads values rewrites, so a removed key drops out and a synced one appears. Each line carries the key's own comment, never the secret's name. Cost: the comment and public key of every SSH key are readable without a prompt, and a key synced from another Mac is offered only after something on this one opens the store, such as `passbox ls`.

Every signature prompts unless a [signing window](#signing-windows) covers it, naming what is signed, where to, the key by its comment, and the program that connected, or the one that ran ssh, such as git. What is signed comes from the shape of the data: an `SSHSIG` blob names its namespace, `git` for a commit, and a login names its user. Both strings come from the caller, so anything but short printable text shows as unrecognised. The prompt opens the store, the broker finds the private key whose public half matches, signs, and audits the secret name with the decision `signed`. The list decides only what is offered; the store decides what signs. Tokens and project manifests do not cover signatures.

Rejected: `ssh-agent-lib`, which needs an async runtime the broker does not have. The protocol is listing, signing and the `session-bind@openssh.com` extension, and everything else fails. Rejected: RSA, which would pull in the `rsa` crate. Secure Enclave keys, which never leave the hardware but are P-256 only and do not sync, are a follow-up.

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

`passbox get` prints to stdout for interactive use. It refuses when stdout is not a terminal, because a pipe, a file or an agent's capture is where a printed secret leaks. The test is the terminal, not the caller, so it fails closed: the rule that refuses a known tool also refuses an unknown one.

Rejected: a blocklist of known agent names. It fails open, because any agent not on the list passes, and the list never catches up. The terminal test needs no list.

Rejected: enforcing the refusal in the broker. `get` and `exec` both send the same read, and the caller's terminal is a client-side fact the broker does not see. A client that lies about which one it is defeats a broker check too, so the guard belongs in the client where the terminal is known.

Rejected: an override flag, `--reveal` until 2.0.0. The refusal named it, so anything that hit the refusal, an agent included, learned the way past it in the same message, and the check stopped only the honest mistake. Removing it also removed the library's in-memory reads, which were built on it, so a program now runs under `exec` and reads its environment.

Cost: this is no boundary. `passbox exec --env V=name -- printenv V` still prints the value, because `exec` hands it to a child and the child can print it. passbox no longer offers a command that prints a secret into a pipe, and a caller who means to can still build one.

`passbox copy` puts the value on the clipboard for the clipboard case. The value goes broker to the Swift helper to the pasteboard, never through stdout. The helper marks the entry with the `org.nspasteboard` concealed and transient types, which clipboard managers that honour the convention skip, so the secret never enters paste history. The helper stays alive to clear the clipboard after `--clear` seconds, 20 by default and at most 60, and clears only if the change count is untouched, so a value copied in the meantime is left alone. The cap keeps a secret from sitting on the clipboard for hours because of a typo.

## Plugin secrets

A plugin returns its data and never a secret. A first-party manifest can name one secret with `stdin = "<name>"`, which the `imap` plugin uses for its account: one entry, `mail/imap`, whose first line is the password and whose fields are host, port, user and TLS settings.

Such a plugin runs only inside the broker. The broker prompts naming the secret, audits it as `released`, writes the value to the child's stdin and closes it. It never puts the value in the child's env, argv, a file, a log or a reply. A request with `run` false, which asks only for approval, is refused before the prompt, so the CLI and MCP send a run request to the local broker the way a tailnet client does and print its output. With no broker, on the passphrase path, the CLI already holds the store key, so it feeds the child itself and prints the same scrubbed output.

The plugin files are writable by any process of the user, so an agent could edit `imap.py` to print the password encoded past the scrub, or edit `plugin.toml` to name another secret. Before the prompt, the broker reads every file of the first-party copy compiled into the binary and compares it byte for byte with the installed one. A difference, a missing file, or a plugin with `stdin` that is not first-party is refused with "reinstall it with `passbox plugin update <name>`". The race between that check and the run is closed by never reading the disk again: the manifest is parsed from the bundled bytes, and the script is passed from them as `/usr/bin/python3 -I -c <code>`, so a file swapped after the check never runs. The interpreter is an absolute path, so PATH cannot replace it, and `-I` keeps the plugin directory and user site packages off `sys.path`. The output is scrubbed of the value and its first line as a second guard.

Rejected: an `[env]` table mapping variables to secrets. Any process of the same user reads a child's env with `ps eww`, so an agent could poll and catch it, and on a local run the values went from the broker to the caller as JSON, over the socket to any local caller and over the tailnet to a remote one. Rejected: the password as a tool parameter, which is argv, readable by `ps`, and which the agent would have to hold. Rejected: reading the verified files from disk again at run time, which leaves a window between the check and the open. Rejected: plugin config for host and user, since one entry with fields is already how `--field` works and the whole account is one approval.

Cost: one secret per plugin, since stdin carries one value. A plugin you write yourself cannot read a secret, it has to run under `passbox exec`. The secret name is fixed in the bundled manifest, so a second account needs a new release. The script is in argv, which `ps` shows, but it is the public bundled code. Scrubbing covers the whole value and the password line, not every field, because a mail tool prints the user's own address.

## Plugins read, they never act

passbox gives what it was asked for, a secret or data, and never acts for the caller. Every first-party tool is a read. A tool that sends, adds, writes or pushes lets the caller act as the owner, and an approval or a window on it hands over that power for as long as it lasts. The `git` and `gh` plugins gated nothing, since an agent runs git and gh directly, so they were removed with `things3.add`, `mail.send` and `mail.attachments`, which wrote files. Gated git goes through the SSH agent, which prompts for every signature, and gh and a mail client get their credential for one command from `passbox exec`.

Rejected: keeping the acting tools behind a prompt on every call. A prompt then named the tool and not its arguments, so approving `mail.send` approved any recipient and any body, and a prompt that shows a cut body still cannot show all of it. Cost: 2.0.0 drops those tools, and a job that used them calls its own client under `passbox exec`.

## Calendar access

A remote plugin call runs inside the broker, a LaunchAgent, so EventKit checks Calendar access against passbox itself. A process with no `NSCalendarsFullAccessUsageDescription` is denied without a prompt, and icalBuddy then sees no calendars. The macOS host build embeds an Info.plist in the binary's `__TEXT,__info_plist` section at link time, with the identifier `com.gabrielkoerich.passbox` and the two calendar usage keys and nothing else, so the first remote calendar call raises the macOS prompt. The release job checks that the signed binary has the section bound. Rejected: an app bundle around the CLI, which Homebrew and `cargo install` do not install. Rejected: running icalBuddy on the caller's side, which a tailnet client cannot do.

The release binary is signed with a Developer ID and notarized, so TCC keeps the grant across upgrades. Its designated requirement is the identifier and team `ZEY9Z684DK`, which every release shares. Cost: the first signed release asks once more, since the grant made for the ad hoc binary does not match, and a source build is still ad hoc and may ask after every rebuild.

The Secure Enclave key does not depend on this signature. It is a CryptoKit `dataRepresentation` blob that only the Enclave can open, with no keychain item, access group or team prefix, and the embedded helper that opens it stays ad hoc. A store made by an ad hoc binary opens under the signed one. Rejected: a keychain item for the key, which would tie it to the team and need the `keychain-access-groups` entitlement.

## Plugin windows

A plugin call prompts by default. `[plugins.windows]` in `~/.passbox/config.toml` maps one exact `"<plugin>.<tool>"` to a duration, and after one approved call the broker skips the prompt for that tool from the same caller scope until the window ends. The policy belongs to the owner, who edits the file, and not to the caller, which only asks.

- A key is one plugin and one tool. A plugin name, `*` or `things3.*` is refused at load, as is a plugin that is not installed or a tool it lacks, so a window never covers a tool added later.
- Any installed tool can have a window. A `readonly` flag the plugin set itself was dropped: the plugin author wrote it, so it proved nothing, and the owner already decides by listing the tool.
- A window is capped at 24 hours, the grant ceiling, and lives in the broker's memory, so a restart ends it as it ends tokens.
- The scope is the caller identity the broker can check: the `tailscale whois` name for a tailnet request, and one local scope for everything on the Mac, since a local agent name is self declared.
- A fed plugin such as `imap` still runs from its checked bundled copy on every call. The window holds the secret in memory, as a token holds its values, and feeds it on stdin, so the key can lapse while the window runs. The call is audited `by window` and the secret `released`.

The tamper guard: the config is plain text that any process of the user can edit. The broker hashes the parsed section with each named tool's `run` and `stdin`, so an edit to the section or to a windowed tool's manifest changes the hash. A window applies only while the current hash is the approved one. A changed section makes the next plugin call prompt once with a reason listing the new windows, and approving it records the new hash in `windows-<host>.json` and ends the windows opened under the old one. A refused prompt leaves the old hash and its windows. The record is plain JSON with a MAC under the store key, so the broker can read it before a prompt to word that prompt, and a process that writes its own record cannot sign it, so a forged record opens nothing. Rejected: encrypting the record to the store recipient as project grants are, which needs the key to read it, so the broker could not word the prompt before it, and which proves nothing about who wrote it, since the recipient is public.

Rejected: grants naming plugin tools, as `passbox grant plugin:things3.logbook`. A grant is minted by the caller and travels as a bearer token, so whoever holds it sets the policy and anyone it leaks to inherits it. A window is set by the owner in a file on the Mac and covers one scope. Rejected: windows on secrets, which the broker section rejects as per-agent approval windows: a plugin window opens one read of an app, never a value. Rejected: refusing `config.toml` edits outright, which would leave no way to change a window without a new release.

A window is bound to the exact call. The prompt shows the bound arguments in call order, such as `run plugin:imap.search query="invoice" mailbox="INBOX" for claude`, and the window covers only that call, so a fingerprint allows only what its prompt showed. The window key is the scope, the tool and a SHA-256 of every declared parameter and its value, sorted by name, as JSON, with an omitted optional bound as empty, so an empty and an omitted value are one call and no value can move into its neighbour. A call with any other value prompts, and its approval opens its own window. The broker holds at most 256 windows per scope and drops the oldest first, and the idle sweep drops expired ones. The audit record of an `approved`, `by window` or `released` call carries `args`, the arguments as shown, encrypted with the rest of the record.

A shown value keeps printable ASCII: control characters are removed, other characters become `?`, a backslash and a quote are escaped. Each value is cut at 64 characters, as the SSH agent cuts the names in its purpose, and the argument list at 256, each cut marked `...`. The key is built from the raw values, so two values that look the same in the prompt are still two calls.

Binding is enforced only where the broker runs the command: a fed plugin such as `imap`, and every tailnet call. For a local plugin without `stdin`, the CLI and MCP send the params they built the command from and run it after approval, but any local process can run the underlying CLI, such as `things`, without passbox. There the approval is a prompt for the owner, not a boundary.

Rejected: a per-tool `window = false` flag for search, read and attachments. It forces a fingerprint per call on a job that repeats the same query, and a tool with no free argument can still be wide, such as `recent` with a large count. Arguments are also checked against `limits` in the manifest before any prompt, such as `count` at most 50 and an IMAP id as digits only, so a wide call cannot be asked for at all. The check is in `Tool::command`, which every path builds the command through.

Cost: a job whose arguments change prompts on every call. One approval opens that call for that scope for the whole window. On the Mac the scope is every local caller, so any process of the user can repeat a windowed call without a prompt until it ends, and only the audit log shows what ran during it. A windowed fed plugin keeps its secret in broker memory for the window, and a rotated password is not seen until the window ends. A windowed call still takes the broker lock, so it waits behind an open prompt.

## Signing windows

`[ssh.windows]` in `config.toml` maps a host name to a duration. After one approved login to that host, the broker signs later logins with the same key to the same host key without a prompt until the window ends. It is for scheduled jobs that connect while the owner is away, which a prompt on every signature stops.

- The destination is the host key, proved by the client. OpenSSH 8.9 sends `session-bind@openssh.com` on each agent connection: the host key, the session id, and the host's signature over it. The broker checks the signature, and a login signs that session id, so the signature is no use to another server. A window applies only when the connection has one bind, it is not forwarded, and the data is a login for the bound session. Commit signatures carry no host and always prompt.
- The name only picks the length. It comes from `known_hosts` or is the host key's SHA256 fingerprint. The window is keyed by the signing key and the host key, so a server that claims the name in a known_hosts edit opens a window of its own, after a prompt.
- The window holds the private key in memory, as a token holds its values, so a signature under it needs no prompt and no store key. That is what makes it work with the screen locked.
- The section uses the same tamper guard as [plugin windows](#plugin-windows): a hash of the parsed section, approved in one prompt and recorded with a MAC under the store key in `windows-ssh-<host>.json`. The MAC has its own domain, so a plugin record cannot pass as an SSH one. A bad section opens no window and logs the reason, and the login still prompts. The prompt promises the window, so it lists the section again until the broker has checked the record's MAC, which needs the store key. Rejected: promising the window from the hash alone, which a record with a bad MAC matches, so the prompt promised a window that never opened.
- A pattern such as `*` is refused, for the reason a namespace grant is refused.

Rejected: a host name the client claims. Any caller can claim one, and ssh does not send it to the agent. Rejected: a bearer grant for signing, `passbox grant --ssh`, which whoever holds the token could use and leak. Rejected: matching hashed known_hosts names, which needs HMAC-SHA1 for a case the fingerprint already covers. Not built yet: a length offered in the prompt itself, which needs a dialog the Touch ID sheet cannot show.

Cost: ed25519 and P-256 host keys only, since RSA verification would pull in the `rsa` crate, so a host with only an RSA host key always prompts. Every local program shares one window per key and host key, as plugin windows share one local scope, so only the audit log shows which one signed. A key removed from the store keeps signing for its windowed hosts until the window ends. A window takes the broker lock, so it waits behind an open prompt. The first windowed login after a restart lists the section again and records it anew, unless the store key is already unlocked.

## Sync

The store is opaque files with no shared mutable state, so sync is a union copy: every id on either side, newest modification time wins, and the loser goes into `.versions`.

What never syncs, one list in `src/sync.rs` that the directory copy and rclone's `--exclude` rules both use: `broker.sock`, `ssh-agent.sock`, `ssh-keys.pub`, `host`, `config.toml`, the old `remote` and `names`, `plugins/`, `.git/`, `.gitignore`, `store/.versions/`, `*.partial`, `grants-<host>.age`, `windows-<host>.json` and `windows-ssh-<host>.json`, matched without regard to case as macOS and iCloud Drive name files. The copy also skips anything that is not a regular file or a directory, so a new socket cannot stop it. A failed copy does not stop the rest. The run ends with one warning naming the destination, the count and the first error, so a folder macOS refuses to write gives one line, not one per file.

Deletes travel as tombstones. A `rm` writes `<id>.tomb`, which copies like any other file and suppresses its id everywhere. The algorithm only ever copies files and writes markers, so it cannot delete a secret it misunderstood. Tombstones are pruned after 90 days.

`sync --enable` asks two questions: how a copy is opened, and where it goes. They were one question before, which meant a store that already had a passphrase wrap skipped straight past the destination and silently copied to iCloud. A wrap says nothing about where the copy belongs.

The destination goes in `~/.passbox/config.toml` rather than a shell profile, so a bare `passbox sync` cannot fall back to the iCloud default behind your back. An `engine` key names the kind. The file is excluded from the copy and from git, since each machine picks its own destination.

Rejected: the one-line `~/.passbox/remote` it replaces. It held a bare path, and the kind was guessed from its shape. An accidental YubiKey touch in an editor holding the file open typed a code and a newline into the path, and the next write created a folder with that name and synced there for a day, apart from every other Mac. TOML fails to parse on a stray line, and every value is checked on read. The old file is still read when there is no config.

Only `--enable` creates a destination. Every other sync refuses a folder that is missing, overlaps the store, or holds other files and no passbox copy. Cost: an unplugged USB stick turns each write's copy into a warning, and a new folder has to be chosen with `--enable` or made by hand.

Rejected: syncing the config itself. One edit would move every Mac, but a USB path on one Mac means nothing on another.

A destination given with `--remote` or `PASSBOX_REMOTE` names no engine, so passbox tells a directory, a git URL and an rclone remote apart by shape, and tests the git URL forms before the rclone colon so `git@host:repo` is not read as an rclone remote.

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

An entry holds a first line and then `key: value` lines, which is what `pass` uses and what `import pass` preserves. `--field` parses that on read.

Rejected: a structured payload with typed fields. It would change the file format, need a migration for every entry already imported, and buy nothing the convention does not already carry. The parse is fifteen lines and works on stores written before it existed.

## 1Password import goes through `op`

`import 1password` runs the user's signed-in `op` CLI and maps each item into the first-line and `key: value` layout above. A secure note, a document and an SSH key go in as blobs, so their text is never parsed as fields. The values stay in the passbox process, and the name check needs one unlock for the whole run.

Both imports are one `passbox import <pass|1password>` command over a `Source` trait, with `Pass` and `OnePassword` implementing it. A source lists its entries with the names they get and fetches one value at a time, and one loop does the duplicate check, the dry run, the writes and the report. Rejected: a command per manager, which repeated that loop and gave `pass` neither `--prefix` nor `--dry-run`. Cost: `import-pass` and `import-1password` are gone, so a script that calls them breaks.

Rejected: reading a 1Password export file (`.1pux`). It is an unencrypted archive of every secret, written to disk by the user, which is the file this import exists to avoid.

Cost: one `op item get` per item, so a large account takes a while. TOTP seeds and multi-line fields are not imported, and the report names each one.

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

CI runs clippy and the tests on Linux, where the host build compiles with an empty Enclave helper and the fake in its place. The caller lookup has a Linux version, `SO_PEERCRED` and `/proc/<pid>/cwd`, beside the macOS one. macOS runs only the release build, which also cross-checks the ECIES and signs, checks and notarizes the binary. The cost: the macOS caller lookup, `LOCAL_PEERPID` and `lsof`, is compiled by the release build but never tested, so a bug in which directory a project grant matches would ship.

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
- Linux builds the client half only, behind the `host` cargo feature being off. It has no Enclave, no broker server and no `sync`, so it opens a local store with a passphrase, or asks the Mac named in `~/.passbox/host` or `PASSBOX_HOST` to approve the read over the tailnet.
