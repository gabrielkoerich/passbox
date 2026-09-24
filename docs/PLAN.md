# Moving orch off the Mac, in order

The goal is `orch` and its 23 `bean` jobs running on Linux or the m1 server,
with the Mac keeping only the data that cannot leave it. The reasoning behind
each choice is in [IDEAS.md](IDEAS.md). This is the order of work.

Each phase is useful on its own and ends with something you can check. Three of
the five need no passbox work at all, so passbox gets built for the jobs that
actually require it rather than up front.

## Phase 0, decide three things first

All cheap now and expensive later.

**Which machine is the host.** m4 has the Secure Enclave, the standalone
Tailscale build and a real interface, so it is the host. Everything else is a
client. A client needs no Enclave, no store and no inbound connections.

**Which machine is the target.** m1-max and a Linux box are not equivalent, and
Proton Bridge decides it. Proton documents Bridge for the latest Ubuntu LTS and
Fedora **Workstation**, describes no headless or CLI mode, and excludes ARM
except Apple silicon Macs. A headless Linux server is therefore outside what
Proton supports.

m1-max is Apple silicon, so Bridge is supported there. The split that follows is
a Linux box for the twelve portable jobs if you want one, and m1-max for
anything touching mail.

**Where approval happens.** On the Mac, or on the phone. This sets the access
control on the host's Enclave key, which is chosen when the key is created and
cannot be changed on a store that already holds secrets. See the fork table in
IDEAS.md. Choosing "the Mac, for now" is fine. Choosing after Phase 3 is a
re-key.

## Phase 1, move the twelve jobs that already move

No new code. A deployment exercise that proves the environment before anything
depends on passbox.

1. Install `orch` on the target box.
2. Move the twelve jobs with no Mac dependency: `8h-paper-trading`,
   `daily-macro-monitor`, `daily-twitter-trending-watch`,
   `monthly-financial-risk-report`, `weekly-fundamentus-screener`,
   `weekly-hyperlend-health`, `weekly-minervini-screeners`,
   `weekly-positions-monitor`, `weekly-quant-rebalancer`,
   `weekly-solana-jobs-scan`, `weekly-trading-review`,
   `weekly-twitter-bookmarks`.
3. Run them on both machines for one cycle and compare the artifacts.

Done when the twelve produce the same output on the new box and are switched off
on the Mac.

## Phase 2, mail

`ProtonDownloader` is 45 lines of IMAP against `127.0.0.1:1143`, and the host
and port already come from the environment. Which option applies depends on the
target chosen in Phase 0.

**Run the mail job on m1-max.** Install Proton Mail Bridge, sign in, leave
`PROTON_BRIDGE_HOST` at `127.0.0.1`. No new code and nothing exposed. This is
the supported configuration.

**A headless Linux server is not a supported target for Bridge.** Deb and rpm
packages exist, and Proton supports them on desktop Ubuntu and Fedora
Workstation, documents no headless mode, and excludes non Apple ARM. Running it
with `--noninteractive` against a `pass` keyring is a community practice rather
than a supported one. Do not plan around it.

**If mail must reach a Linux box**, forward the Mac's bridge port to the tailnet with
`tailscale serve --tcp=1143`. This is the last choice, and it has a cost. The
bridge password hardcoded in `proton_downloader.py` is harmless today only
because the bridge is loopback bound. Forwarding removes that protection, so
taking this option means rotating the password, moving it behind
`CredentialProvider`, and restricting the port to one client with a tailnet ACL.

Done when a statement downloads and parses on the target. That is thirteen of
twenty three jobs moved.

## Phase 3, secrets move to passbox, still on the Mac

Prove the chain locally before adding the network.

1. ~~**`passbox import-pass <entry>`**, decrypting through GPG and re-encrypting
   to the store key.~~ Built, and the `bean` namespace is imported, 21 entries.
2. **`PassboxProvider`** in `bean/packages/credentials/`, implementing the
   existing `CredentialProvider` ABC: `get`, `get_fields`, `is_available`.
   `test_credentials.py` already exists to cover it.
3. **Route by path** in `manager.py` so `PassboxProvider` and
   `PasswordStoreProvider` coexist. No cutover.
4. Move the secrets `daily-overnight-task-scanner` uses, and run it on the Mac.
5. Fix the hardcoded bridge password while here: rotate it, store it, and have
   `ProtonDownloader` take a provider rather than an environment default.

Done when a bean job reads a secret through passbox, a prompt names it, and
`passbox audit` shows the read.

## Phase 4, passbox serves clients

The first real passbox build, and what lets a job on the target use a secret
held by the Mac.

1. **Broker as a LaunchAgent** in the login session. Required rather than tidy:
   a process spawned by an incoming connection cannot raise a Touch ID prompt,
   measured 2026-09-24.
2. **Listen on the tailnet address** as well as the unix socket. Prefer the
   Tailscale address over loopback, since loopback has no permission check while
   the unix socket is 0600.
3. **Identify the caller with `tailscale whois`**, which returns an
   authenticated machine and user. Put that in the prompt. It is the first
   caller identity in passbox that is verified rather than declared.
4. **Client mode**: `init` on a machine with no usable Enclave writes a client
   config naming a destination instead of binding to hardware it cannot reach.
   `canEvaluatePolicy` already makes that decision correctly.
5. Point `PassboxProvider` on the client at the host.

Done when `daily-overnight-task-scanner` runs on the client, the prompt appears
on the Mac naming the verified client machine, and the audit log records it.

## Phase 5, Things and Calendar

Nine jobs need these, and they are the only ones needing anything new.

1. Reads first: `things.today` and `calendar.agenda`. Nine jobs only need to
   know what is on a list.
2. Named capabilities, never a remote shell. Each carries the same modes a
   secret carries.
3. Writes later, and only for jobs that prove they need them.

Done when the nine run on the client. That is all twenty three moved.

## Shipping binaries, done

Shipped in v0.9.0. `cargo install` cost one to three minutes on every install and
upgrade and needed Rust and the Command Line Tools. The release workflow now
builds three targets and the formula picks between them.

It is **three separate binaries**, not one universal one. An earlier draft here
planned arm64 and x86_64 joined with `lipo`, which would have meant teaching
`build.rs` to pass a target architecture to `swiftc`. Three targets were already
needed for Linux, so a fourth matrix entry cost less than cross compiling Swift.

| Target | Build |
|---|---|
| `aarch64-apple-darwin` | host |
| `x86_64-apple-darwin` | host |
| `x86_64-unknown-linux-gnu` | client |

Source builds still work, through the `head` block in the formula. For a tool
holding passwords, compiling what you can read is a fair position.

Still unchecked: Gatekeeper. The binary is ad-hoc signed with no Developer ID, so
a downloaded archive carries a quarantine attribute. Homebrew normally strips it,
which is the kind of thing that works locally and fails for a stranger.

## Linux is a client only

Decided 2026-09-24. A Linux build never holds the Enclave, the broker server or
the Enclave wraps, because the host returns values and the client only asks.

The split is a cargo feature, `host`, on by default. An earlier draft here chose
`cfg(target_os)` instead. The feature won because the client build then has to be
compilable on macOS, which is the only way CI can prove it still builds without
running a Linux job for every commit.

What is host gated today: `se.rs`, the Enclave functions in `store.rs`, the broker
server, and the `sync`, `audit`, `import-pass`, `machine add` and `yubikey add`
verbs.

**What a Linux build does today is less than the name suggests.** It opens the
store with a passphrase, because the "ask the host" path is Phase 4 and is not
built. So a Linux box can hold a synced copy and read from it with a passphrase,
which is not the same as asking the Mac and having a human approve there.

## What is deliberately not here

- A plugin system. Subcommand dispatch exists on the `poc-extensions` branch at
  17 lines, and the trust allowlist it needs has not been built. Nothing above
  requires either.
- Moving `sync.rs` or `mcp.rs` out of the passbox core.
- Approval from the phone, unless Phase 0 chooses it.
- `pass_bridge.py` and `http_pass.py`, which can be deleted once Phase 3 is
  proven, rather than migrated.
