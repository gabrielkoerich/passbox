+++
title = "Roadmap"
description = "Not built and not committed to, written down so the reasoning survives"
weight = 8
+++

Little of this is built, and none of it is committed to. It is written down so the reasoning survives, and so a later session starts from the argument rather than from scratch. Where something here has since shipped, the section says so.

Two threads: where a plugin seam is worth opening, and asking another machine for something only that machine can do.

## The measurement first

Non-test lines, measured 2026-09-24 at v0.13.1. Tests are excluded because a module does not become harder to move by being well tested.

| Module | Lines | What it is |
|---|---|---|
| `main.rs` | 863 | the CLI |
| `broker.rs` | 585 | approvals, windows, audit |
| `store.rs` | 512 | the file format and versions |
| `sync.rs` | 197 | the union copy |
| `mcp.rs` | 181 | the MCP server |
| `se.rs` | 125 | the Enclave helper |
| `yubikey.rs` | 124 | the token wrap |
| `import.rs` | 124 | reading a `pass` store |
| `project.rs` | 109 | manifests and grants |
| `crypto.rs` | 55 | encrypt and decrypt |
| `tree.rs` | 47 | rendering `ls` |

2,922 lines, plus 441 of integration tests.

## Two different things are called plugins

They have different costs and different timelines.

**Subcommand extensions** add verbs. `pass` grew a community on these: `pass otp`, `pass-import`, `pass-update`, and the browser and mobile clients around them. They use the store and replace no mechanism.

**Backend plugins** replace a mechanism, such as how the key is unwrapped or who is asked for approval.

The first is cheap here and worth doing early. The second is the rest of this document.

## Subcommand extensions, and why passbox starts ahead

`pass` sources an extension into its own shell process, so the extension inherits everything pass can do. That is why user extensions are gated behind `PASSWORD_STORE_ENABLE_EXTENSIONS=true`.

passbox does not need that trade, because the broker already is the extension API. A `passbox-otp` asks the broker over the socket exactly as any agent does, and gets the same prompt, the same window and the same audit line. It never holds the store key, so it is not in the trust base the way a backend plugin is.

Only dispatch is missing: `passbox foo` should exec `passbox-foo` from `PATH` when `foo` is not a built-in verb. That is roughly twenty lines, and it buys the ecosystem shape that grew `pass`.

Cost: any `passbox-*` binary on `PATH` can then be launched by typing a passbox command, and can name itself whatever it likes when it calls the broker. The prompt still names the secret, which is the part that cannot be faked, and the audit log still records the real process ancestry. Gate it behind an opt-in the way `pass` does.

## What the core should keep

One question decides it: **does this need the store key in plaintext?**

Everything that does is the product and stays. Everything that does not can be a separate binary, and then "this program can never see a secret" is a property someone can check by reading the dependency list rather than the code.

| Keeps the key | Why |
|---|---|
| `crypto.rs`, `store.rs` | the file format |
| `se.rs` | the Enclave and the prompt |
| `broker.rs` | approvals, windows, audit |
| `project.rs` | grants, which the broker reads |
| `init`, `add`, `get`, `ls`, `rm`, `exec` | the idea itself |

| Never needs the key | Size |
|---|---|
| `sync.rs` | 197 |
| `mcp.rs`, which asks the broker like any agent | 181 |
| `tree.rs`, which renders names it is handed | 47 |
| the `git` passthrough | about 20 |

That is roughly 445 of 2,922 lines.

## Sync moves out whole, rather than behind an interface

An earlier draft of this document argued against extracting sync, on the grounds that only about 15 of its 152 non-test lines are backend specific and the union copy with tombstones would stay in core anyway.

That argument holds against making sync a **backend interface** with pluggable drivers. It does not hold against moving the whole thing out, because `sync.rs` never decrypts anything. It walks two directories, compares modification times, copies files and writes tombstones. A `passbox-sync` binary needs no key, no broker and no prompt.

So the union copy leaves with it, and core loses 346 lines rather than 15.

Rejected: a pluggable sync backend inside core. Every target so far reduces to a directory, and rclone already covers the rest in fifteen lines.

## The wrap and the approver are the right seam

Two implementations exist and two more are planned:

| | Unwraps the store key | Proves a human agreed |
|---|---|---|
| macOS | Secure Enclave blob | Touch ID |
| any | scrypt passphrase | typing it |
| any, shipped v0.11.0 | YubiKey | a touch on the key |
| planned, servers | asks another machine | Touch ID over there |

The YubiKey wrap turned out not to be Linux specific, which is how this table first listed it. It is a recovery and sync wrap on any platform, and it does not replace Touch ID for day to day reads.

This is already an interface in everything but name. `Store::unlock_with_se` and `Store::unlock_with_passphrase` return the same type and `unlock` in `main.rs` picks between them. The broker calls `unlock_with_se` directly, which is the line that stops passbox running anywhere else.

Four implementations of one operation justify an interface.

## Build the third one first

Do not design the plugin interface before writing each path as concrete code. An interface drawn from two cases tends to fit neither the third nor the fourth, and remote approval is the one most likely to break assumptions, since it is the only approver that is not a local function call.

Order: YubiKey concretely, then remote approval concretely, then extract whatever the three actually share.

The YubiKey half shipped in v0.11.0 and the advice held. It needed things a two-case interface would not have exposed: several recipients on one wrap, a check of the PIV applet before provisioning a slot, and an offer to install the age plugin. Remote approval is still unwritten, so the extraction still waits.

## When it is time, use executables

An external binary, `passbox-<name>` on `PATH`, speaking newline delimited JSON on stdio. It is the same shape as age plugins and git remote helpers, and the same shape `se.rs` already uses to talk to the Swift helper.

Rejected: dynamic libraries. Rust has no stable ABI, so every plugin would need rebuilding against every release.

Rejected: in-process traits. They keep the code smaller, and they also mean a plugin shares address space with the process holding the store key.

## What an executable plugin costs

Anything named `passbox-*` on `PATH` becomes part of the trust base, and `PATH` is writable by anything running as the user. A plugin therefore has to be recorded in the store, by name and by hash of its binary, with the same rule the project manifests use: a changed hash means it asks again.

Without that rule this feature hands an attacker a way to be asked for the store key. It should not ship before the allowlist does.

## An SSH agent, the way 1Password does it

1Password exposes an `SSH_AUTH_SOCK`, answers the SSH agent protocol on it, and asks for biometrics per signature. `ssh` needs no configuration beyond the socket path, so every tool that already speaks to an agent works unchanged: git, scp, rsync, ansible.

passbox already has the two hard parts. The broker is a long-lived process holding keys behind Touch ID, and it already serves a unix socket with peer identification. What is missing is the protocol and the key material.

**The protocol.** `SSH_AGENT_IDENTITIES_ANSWER` to list, `SSH_AGENT_SIGN_RESPONSE` to sign. It is a small binary protocol and the signing side is the only part that matters, because listing hands out public keys, which are public.

**The key material.** A secret is an opaque string today, and signing needs a parsed key an implementation can compute with. Ed25519 is the case worth supporting; it is one algorithm, and everything modern uses it.

The prompt is the reason to build it: `github.com wants to authenticate as your key`, once per session or once per signature.

| | |
|---|---|
| Keeps | the private key never leaves the broker, and every use is audited |
| Costs | a second protocol to implement, and a key format to parse |
| Rejected | shelling out to `ssh-add`, which puts the key in another agent's memory where passbox cannot gate it |

Worth pairing with a Secure Enclave key directly: a P-256 key in the Enclave can sign, so an SSH key could be hardware-bound rather than a stored secret. That turns "passbox holds your key" into "your key cannot be copied", which is the stronger claim.

Not started. It is a bigger piece than anything above, and the wrap and approver work should settle first.

## Not plugins

- **Secret types**, such as TOTP or SSH keys. These change the payload schema rather than the mechanism, so they belong in `store.rs`.
- **The MCP server.** One implementation, and the protocol is the interface.
- **Output formats.** JSON on a flag is smaller than any plugin.

## Hosts and clients

The shape is one **host** and many **clients**, not peers.

| | Host | Client |
|---|---|---|
| Secure Enclave | yes, and it is why it is the host | no |
| The store | holds it | holds nothing |
| The broker | runs it, raises the prompt | asks the host |
| Examples | the Mac you sit at | a Linux server, a Mac running lid closed |

A client asks the host. The human approves on the host, where the sensor is. The value comes back over the same channel, and the client never holds the key.

`init` decides which it is. `canEvaluatePolicy` already tells us whether biometry is usable, so a machine that cannot reach a sensor becomes a client pointed at a host rather than binding to an Enclave it cannot use.

This also fixes a real bug found by installing on a lid closed MacBook: `init` bound to the Secure Enclave and reported "reads will ask for your fingerprint", on a machine whose sensor is sealed inside a shut lid, leaving a store that nothing could open and no recovery wrap to fall back to.

## Finding the host

passbox should not resolve addresses. A client stores an ssh destination and lets ssh do the rest, because `ssh_config` already handles aliases, jump hosts, `ProxyCommand`, Bonjour names and Tailscale names.

| Addressing | Reaches the host |
|---|---|
| a LAN address | on that network, until DHCP moves it |
| an mDNS name such as `host.local` | on the same network, with no configuration |
| a `Host` block in `~/.ssh/config` | wherever it is configured to |
| Tailscale MagicDNS | anywhere, and it carries node identity |

So the client config is one line naming a destination. Tailscale is worth adding because it makes that name resolve from a datacentre as easily as from the next room, with no port forwarding, and by adding a second verifiable identity beside the ssh key.

The destination has to be an `ssh_config` entry rather than a shell alias. An alias such as `alias ssh-host='ssh you@10.0.0.2'` is visible only to an interactive shell, so passbox cannot use it. The same name written as a host block works for passbox, scp, rsync and git at once:

```
Host passbox-host
  HostName 10.0.0.2
  User you
```

Swapping `HostName` for a Tailscale name later moves every tool with it, and changes nothing in passbox.

Nothing here wakes a sleeping Mac, and a host that cannot be reached cannot approve. The client needs a timeout and a plain message rather than a hang.

## What each role needs from the network

Measured on 2026-09-24 across two Macs on one tailnet.

The client only makes outbound connections, so the sandboxed App Store Tailscale build is enough. That build does create a `utun` interface and does answer `tailscale ping`, and it still does not deliver inbound TCP to services on the host, because it runs as a sandboxed network extension. None of that matters for a client.

The host has to accept inbound connections, so it needs the standalone Tailscale build, which does create a real interface, and it needs Remote Login enabled.

| | Build | Interface | Accepts inbound |
|---|---|---|---|
| host | standalone | `utun` with a 100.x address | yes |
| client | App Store is fine | none | no |

Getting this backwards is easy and the symptom is misleading. Measured against the App Store build: `tailscale ping` answers, MagicDNS resolves, the interface holds the right address, `ShieldsUp` is false, sshd listens on `*:22`, and TCP to any port over the tailnet still times out while the same port is open on the LAN.

Test reachability with `nc -z` against a port rather than with `tailscale ping`.

Traffic between two machines on the same LAN was relayed through a DERP server in another country at 30ms rather than going direct. Check this before blaming passbox for latency.

Headscale, the open source control server, is worth a look later. It replaces the coordination server and leaves the rest of this unchanged.

## The broker has to outlive the request

A request arriving over SSH cannot raise the prompt itself. Measured on 2026-09-24: a process spawned by SSH gets `canEvaluatePolicy` false with `systemCancel`, and so does a launchd agent in the Aqua session when the lid is shut. Whoever calls `evaluatePolicy` has to be somewhere a sensor is reachable.

So the broker becomes a LaunchAgent in the host's login session, and the SSH side only carries bytes to its socket. Spawning a broker on demand, which is what passbox does today, would put it inside the SSH session where it cannot ask anybody anything.

This is the one hard constraint the remote design adds.

## Reaching the host without a shell

Remote Login is the wrong tool. It grants a shell to anything holding a key, for a design that needs one socket.

Two narrower options exist, both confirmed present on the standalone macOS build on 2026-09-24:

- `tailscale serve --tcp=PORT` forwards raw TCP from the tailnet to a local port.
- The broker binds directly to the tailnet address, so only tailnet peers and local processes can reach it.

Rejected: `tailscale set --ssh`. It is keyless and gated by tailnet policy, and it still hands out a shell.

Either option has one caveat. The broker's unix socket is 0600, so only this user can reach it. A TCP port on loopback has no such protection and any local user could connect. Binding to the tailnet address rather than loopback keeps that narrower.

## Tailscale whois makes the caller verifiable

This is the part worth building for.

`tailscale whois <peer address>` returns the machine name and the user of the connecting node, authenticated by the control plane rather than claimed by the caller:

```
Machine:  client.example-tailnet.ts.net
User:     you@example.com
```

Everywhere else in passbox the agent name is self declared and unverifiable, which is why per agent policy was deferred. A remote caller arriving over the tailnet can be identified for real, so the prompt can name a machine the host has actually authenticated, and policy per machine becomes enforceable rather than advisory.

Local callers still declare their own name. A prompt that mixes the two should say which kind it is showing.

## SSH already carries an identity

A client connecting over SSH has authenticated with a key, and the host knows which key. That is a real caller identity, and it is the first thing in this design that could make per agent policy enforceable rather than advisory.

Tailscale would do the same through node identity.

## Approving from a phone, declined

The idea: a push notification to the phone, approve there, the value is released. It answers what a machine with no sensor does, and it removes the requirement that the host be awake.

Declined, because building it means rebuilding a password manager.

It needs an iOS app, push infrastructure, a credential the phone can unwrap with, and a way for the answer to travel back. iOS has no background daemons, so the phone cannot listen; there is no cheap version of this. A passkey makes the credential part easier, because one lives in iCloud Keychain and syncs, and the WebAuthn PRF extension can derive a key-encryption key from it. That would replace the per-machine Enclave wrap and make a phone a first-class client. It still does nothing for delegation: a passkey authenticates on the device in your hand, and has no notion of one machine asking and another approving.

So the full feature is an app, sync, push, and device key management. That is the part of a password manager other people have spent a decade on, and it is not the part passbox is for.

passbox does something narrow: a secret goes into one child process rather than into an agent's context, the prompt names which agent wants which secret, and the audit log says what was released to whom. None of that is a phone feature.

The sharper version of the problem this was meant to solve is "nobody is awake at 3am", not "approve from my phone". Injection at launch and a scoped grant already answer that, and they answer it better, because they need no one at all.

Rejected: a phone as approver, and the passkey work that would support it. Revisit only if the agent boundary is finished and this is still the largest missing thing, which it is not today.

## Knowing when to stop

This file is where features get argued with before anyone agrees to them. Answer three questions before building anything here:

**Does it serve the one sentence?** passbox keeps a secret out of an agent's context. A feature that does not make that truer, or cheaper, or harder to get wrong, belongs in another product.

**Is it the part nobody else is building?** Sync, mobile apps, device management and key recovery all have mature answers. Duplicating them costs the years they took and wins nothing.

**Is it the largest missing thing?** Not the most interesting one. The tailnet client shipped because a Linux box could not read a secret at all. A phone approver is a convenience for a problem already solved another way.

Two failure modes: building a feature because it is fun, and keeping a mechanism beside its replacement. The lease was removed once grants existed, because two answers to one question is how documentation goes wrong.

## Remote capabilities, a later idea

The motivating examples: Things and Mail run on the Mac, a Linux box cannot have them, and an agent there needs the data. Generalised, a machine asks another machine for something only that machine can provide.

Mail is the sharper case. The alternative is giving the Linux box an IMAP credential, which hands it standing access to the whole mailbox. Asking the Mac for `mail.search` returns the messages that matched and nothing else, and the credential never leaves the Mac. The same argument covers Messages, Calendar, Photos and anything else holding an account rather than a file.

This is the broker with the word "secret" removed. The requester never receives the underlying access, only the result, which is what `run_with_secret` already does locally.

Transport, in order of preference:

- **SSH.** No new infrastructure and the trust already exists.
- **Tailscale.** Stable per node identity, which is a better caller identity than the self declared agent name, and no ports to manage.
- Rejected: **Cloudflare Tunnel.** Built for public exposure, which is the wrong shape for a personal broker, and it puts a third party in the path.

It never offers a remote shell. The Mac declares named capabilities such as `things.today` and `things.add`, each carrying the same mode a secret carries, and each raising the same prompt naming the caller and the capability.

A capability provider never needs the store key, so it is a subcommand extension rather than a backend plugin, and it inherits the broker's policy unchanged.
