# passbox

A password store for machines that run agents. An agent asks for a secret, macOS
raises a Touch ID prompt naming the agent and the secret, and the value goes into
one child process rather than into the agent.

Secrets are ordinary [age](https://age-encryption.org) files. The broker that
decides who may open them is the part that matters. See [docs/DESIGN.md](docs/DESIGN.md)
for why it is built this way and what it costs.

Runs with no Apple Developer Program membership.

## Install

```sh
brew install gabrielkoerich/tap/passbox
passbox init
```

`init` creates the store, asks for a recovery passphrase, and binds this Mac's
Secure Enclave. Keep the passphrase somewhere safe. A Secure Enclave key cannot
leave the Mac that made it, so the passphrase is the only way back.

## Use

```sh
printf 'ghp_xxx' | passbox add github/token
passbox ls
passbox get github/token
```

### Giving a secret to an agent

The value goes into one child process and never into the agent.

```sh
passbox exec --env GITHUB_TOKEN=github/token -- gh api /user
passbox exec --stdin db/password -- psql
```

Prefer `--stdin` where the tool accepts it. Any process running as you can read a
child's environment with `ps eww`.

Set `PASSBOX_AGENT` so the prompt names the caller.

```sh
PASSBOX_AGENT=claude-code passbox exec --env GH_TOKEN=github/token -- gh pr list
```

The prompt then reads `claude-code wants the password for github/token`.

### Permission modes

Every secret carries one.

| Mode | Behaviour |
|---|---|
| `open` | No prompt, for a token an agent reads all day |
| `window` | One prompt per agent and secret per window, the default |
| `always` | A prompt on every read |
| `never` | Never released to an agent, interactive `get` only |

```sh
passbox mode banking/login never
passbox add github/token --mode window --window 600
```

A new value never widens access. Adding over an existing secret keeps the mode it
already had unless you pass `--mode`.

### Seeing what was released

```sh
passbox audit --tail 50
```

Every decision is logged, encrypted, one record per line.

## Sync

```sh
passbox sync
```

The default target is the iCloud Drive folder, which is an ordinary directory on
macOS. No account, no rclone, no network code.

```sh
PASSBOX_REMOTE=~/Dropbox/passbox passbox sync   # any directory
PASSBOX_REMOTE=b2:passbox passbox sync          # any rclone remote
```

A remote containing a colon goes through `rclone bisync`, which covers every
backend rclone supports. Nobody on the default path needs rclone installed.

If the store directory is also a git repo, `passbox sync` commits and pushes after
the copy, which gives you history and an off-site remote. Commit subjects are
generic, since a subject naming an entry would undo the encrypted names.

On a second Mac, pull the store and then bind it.

```sh
passbox sync
passbox machine add
```

## Recovering

Every write keeps the last 5 versions, and `rm` keeps the file too.

```sh
passbox restore github/token            # list versions
passbox restore github/token --index 0  # put the newest one back
```

## What is on disk

```
~/.passbox/
  store/<random-id>.age     one self describing secret per file
  store/<random-id>.tomb    deletion marker
  store/.versions/<id>/     earlier versions, kept local
  wraps/recipient           the store public key, no secret in it
  wraps/recovery.age        the store key under your recovery passphrase
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
| `PASSBOX_REMOTE` | Sync target, default the iCloud Drive folder |
| `PASSBOX_AGENT` | Name shown in the prompt beside the secret |
| `PASSBOX_PASSPHRASE` | Supplies the passphrase for CI and headless use, and turns off the Enclave path |

## Building

```sh
cargo test
cargo test -- --ignored   # the Secure Enclave round trip, needs a finger
```

`build.rs` compiles the Swift helper with `swiftc` from the Command Line Tools.

## Licence

MIT
