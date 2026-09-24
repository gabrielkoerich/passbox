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

## Hosts and clients

The shape is one **host** and many **clients**, not peers.

| | Host | Client |
|---|---|---|
| Secure Enclave | yes, and it is why it is the host | no |
| The store | holds it | holds nothing |
| The broker | runs it, raises the prompt | asks the host |
| Examples | the Mac you sit at | a Linux server, a Mac running lid closed |

A client asks the host. The human approves on the host, where the sensor is. The
value comes back over the same channel, and the client never holds the key.

`init` decides which it is. `canEvaluatePolicy` already tells us whether biometry
is usable, so a machine that cannot reach a sensor becomes a client pointed at a
host rather than binding to an Enclave it cannot use.

This also fixes a real bug found by installing on a lid closed MacBook: `init`
bound to the Secure Enclave and reported "reads will ask for your fingerprint",
on a machine whose sensor is sealed inside a shut lid, leaving a store that
nothing could open and no recovery wrap to fall back to.

## Finding the host

passbox should not resolve addresses. A client stores an ssh destination and
lets ssh do the rest, because `ssh_config` already handles aliases, jump hosts,
`ProxyCommand`, Bonjour names and Tailscale names.

| Addressing | Reaches the host |
|---|---|
| a LAN address such as `192.168.1.253` | on that network, until DHCP moves it |
| `m4.local` | on the same network, with no configuration |
| a `Host m4` block in `~/.ssh/config` | wherever it is configured to |
| Tailscale MagicDNS | anywhere, and it carries node identity |

So the client config is one line naming a destination. Tailscale earns its place
by making that name resolve from a datacentre as easily as from the next room,
with no port forwarding, and by adding a second verifiable identity beside the
ssh key.

The destination has to be an `ssh_config` entry rather than a shell alias. An
alias such as `alias ssh-mac='ssh gabriel@192.168.1.253'` is visible only to an
interactive shell, so passbox cannot use it. The same name written as a host
block works for passbox, scp, rsync and git at once:

```
Host m4
  HostName 192.168.1.253
  User gabriel
```

Swapping `HostName` for a Tailscale name later moves every tool with it, and
changes nothing in passbox.

Nothing here wakes a sleeping Mac, and a host that cannot be reached cannot
approve. The client needs a timeout and a plain message rather than a hang.

## What each role needs from the network

Measured on 2026-09-24 across two Macs on one tailnet.

The client only makes outbound connections, so the sandboxed App Store Tailscale
build is enough. That build does create a `utun` interface and does answer
`tailscale ping`, and it still does not deliver inbound TCP to services on the
host, because it runs as a sandboxed network extension. None of that matters for
a client.

The host has to accept inbound connections, so it needs the standalone Tailscale
build, which does create a real interface, and it needs Remote Login enabled.

| | Build | Interface | Accepts inbound |
|---|---|---|---|
| host | standalone | `utun` with a 100.x address | yes |
| client | App Store is fine | none | no |

Getting this backwards is easy and the symptom is misleading. Measured against
the App Store build: `tailscale ping` answers, MagicDNS resolves, the interface
holds the right address, `ShieldsUp` is false, sshd listens on `*:22`, and TCP to
any port over the tailnet still times out while the same port is open on the LAN.
Every check says reachable except the one that matters.

Test reachability with `nc -z` against a port rather than with `tailscale ping`.

Traffic between two machines on the same LAN was relayed through a DERP server in
another country at 30ms rather than going direct. Worth checking before blaming
passbox for latency.

Headscale, the open source control server, is worth a look later. It replaces the
coordination server and leaves the rest of this unchanged.

## The broker has to outlive the request

A request arriving over SSH cannot raise the prompt itself. Measured on
2026-09-24: a process spawned by SSH gets `canEvaluatePolicy` false with
`systemCancel`, and so does a launchd agent in the Aqua session when the lid is
shut. Whoever calls `evaluatePolicy` has to be somewhere a sensor is reachable.

So the broker becomes a LaunchAgent in the host's login session, and the SSH side
only carries bytes to its socket. Spawning a broker on demand, which is what
passbox does today, would put it inside the SSH session where it cannot ask
anybody anything.

This is the one hard constraint the remote design adds.

## Reaching the host without a shell

Remote Login is the wrong tool. It grants a shell to anything holding a key, for
a design that needs one socket.

Two narrower options exist, both confirmed present on the standalone macOS build
on 2026-09-24:

- `tailscale serve --tcp=PORT` forwards raw TCP from the tailnet to a local port.
- The broker binds directly to the tailnet address, so only tailnet peers and
  local processes can reach it.

Rejected: `tailscale set --ssh`. It is keyless and gated by tailnet policy, and
it still hands out a shell.

One caveat for either. The broker's unix socket is 0600, so only this user can
reach it. A TCP port on loopback has no such protection and any local user could
connect. Binding to the tailnet address rather than loopback keeps that narrower.

## Tailscale whois makes the caller verifiable

This is the part worth building for.

`tailscale whois <peer address>` returns the machine name and the user of the
connecting node, authenticated by the control plane rather than claimed by the
caller:

```
Machine:  m1-max.tail342cb6.ts.net
User:     whkg24mbff@privaterelay.appleid.com
```

Everywhere else in passbox the agent name is self declared and unverifiable,
which is why per agent policy was deferred. A remote caller arriving over the
tailnet can be identified for real, so the prompt can name a machine the host has
actually authenticated, and policy per machine becomes enforceable rather than
advisory.

Local callers still declare their own name. The asymmetry is worth stating in any
prompt that mixes the two.

## SSH already carries an identity

The agent name in a prompt is self declared and unverifiable. A client connecting
over SSH has authenticated with a key, and the host knows which key. That is a
real caller identity, and it is the first thing in this design that could make
per agent policy enforceable rather than advisory.

Tailscale would do the same through node identity.

## The phone could approve, and that is a fork

A phone on the tailnet is reachable and `whois` identifies it the same way it
identifies a Mac. As a client it is unremarkable. As an **approver** it answers
the question the first design notes left open, which is what a machine with no
sensor does, and it removes the requirement that the host be awake and unlocked.

It cannot be bolted on. The host's Enclave key is `.biometryAny` today, so it
cannot be used at all without a fingerprint on that Mac. Approving somewhere else
means choosing one of these:

| | The host key becomes | Keeps | Costs |
|---|---|---|---|
| A | access control `.none`, still hardware bound | the key cannot be stolen off the Mac | the key can be used with nobody at the Mac, so the broker is the only presence check |
| B | the phone holds its own wrap in its own Enclave | real biometric presence | the key exists on two devices |
| C | `.none`, opened only on a signed approval from the phone | both guarantees | a signing key on the phone and more parts |

iOS has no background daemons, so the phone cannot listen for requests. An
approver needs a push notification into an app, or a Shortcut the user triggers.
That weighs against B and C more than against A.

Undecided. Worth deciding before any of it is built, because the answer changes
the access control on the host key, and that is not a setting you can flip on a
store that already exists.

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


# The real driver: moving orch off the Mac

Gabriel runs `orch` on the Mac, scheduling agent jobs for `bean`, his finance and
notes project. He wants that compute on a Linux box or the m1 server, while some
of the data stays on the Mac. This is the requirement the remote design exists to
serve, so it should be measured against these jobs rather than invented.

## What is actually pinned to the Mac

Of 23 scheduled jobs in `bean/prompts/jobs`, measured 2026-09-24:

| Capability | Jobs blocked |
|---|---|
| Things | 9 |
| Calendar | 5, all overlapping the Things set |
| Mail or Proton | 1, `daily-bean-close` |
| `pass` | 1, `daily-overnight-task-scanner` |

Twelve jobs have no Mac dependency at all. They are the quant and market ones,
which are also the jobs that most want a machine that never sleeps.

Eleven remain, and **four capabilities unlock all of them**. That is a far
smaller surface than exposing a Mac to the network.

## bean already has both seams

Two abstractions exist, so passbox plugs in rather than replacing anything.

`packages/credentials/provider.py` defines `CredentialProvider` with `get`,
`get_fields` and `is_available`, and seven backends implement it. A
`PassboxProvider` is a new file, not a migration.

`packages/importers/downloader/__init__.py` defines a `Downloader` protocol with
four implementations.

## pass-bridge is the broker without the approval

`packages/credentials/pass_bridge.py` already serves an allowlisted set of `pass`
secrets over localhost HTTP to a container, with a bearer token, and never logs
values. The instinct matches passbox: a host side daemon, an allowlist, a network
boundary.

Its own docstring states the limit plainly, that anything able to read the token
can already read `pass`. So it adds a boundary and no approval. Any client
holding the token reads those secrets forever and silently.

passbox adds what it deliberately left out: a human gate per secret, a caller
identity that is verified rather than shared, and an audit log. Once a
`PassboxProvider` is proven, `pass_bridge.py` and `http_pass.py` can go.

## The mail dependency is smaller than it looks

`ProtonDownloader` is 45 lines and is plain IMAP against `127.0.0.1:1143`, the
Proton Bridge, with host and port already read from the environment. So the
blocked job needs no capability work at all:

- Point `PROTON_BRIDGE_HOST` at the Mac and expose only that port to the tailnet
  with `tailscale serve --tcp`. No code changes.
- Or run Proton Bridge on the Linux box, which has official builds, and the job
  stops needing the Mac entirely.

Only `mail_app_downloader.py`, which drives Mail.app through AppleScript, is
genuinely Mac bound. Check whether Proton already covers the same mail before
building a capability for it.

## The order to do this in

1. Move the twelve portable jobs. No new code, and it proves the deployment.
2. Mail, by pointing `PROTON_BRIDGE_HOST` over the tailnet, or by running the
   bridge on Linux. No new code.
3. `pass` to passbox, with a `PassboxProvider` behind the existing ABC. This is
   the first step that needs passbox at all, and it also retires `pass_bridge`.
4. Things and Calendar as read capabilities, `things.today` and
   `calendar.agenda`. This is the only genuinely new build, and it unblocks nine.

Three of those four steps need no capability system. Build it last, for the case
that actually requires it.
