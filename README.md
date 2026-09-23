# passbox

A password store for machines that run agents. An agent asks for a secret, macOS
raises a Touch ID prompt naming the agent and the secret, and the value goes into
one child process instead of into the agent.

Secrets are ordinary [age](https://age-encryption.org) files. The part that matters
is the broker that decides who may open them.

Status: the store core works. The Secure Enclave prompt, the broker and sync are
in progress.

## Install

```sh
brew install gabrielkoerich/tap/passbox
passbox init
```

## Use

```sh
printf 'ghp_xxx' | passbox add github/token
passbox ls
passbox get github/token
```

Every secret carries a permission mode.

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
```

The filename is a random id. Names live inside the ciphertext, so nothing on disk
says what a secret is called. What still leaks: how many secrets exist, their
sizes, and their modification times.

## Design

- One age key encrypts every secret. It is never written unwrapped.
- The recovery passphrase is the only way back if you lose the Mac, because a
  Secure Enclave key cannot leave the machine that made it.
- Writing a secret needs no unlock, since the public key sits in the clear.
  Reading is what costs a prompt.

`PASSBOX_DIR` moves the store. `PASSBOX_PASSPHRASE` supplies the passphrase for CI
and headless use.

## Licence

MIT
