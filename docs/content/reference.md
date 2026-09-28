+++
title = "Reference"
weight = 6
+++


### Undoing a change

Every write keeps the last 5 versions, and `rm` keeps the file too.

```bash
passbox restore github/token            # list versions
passbox restore github/token --index 0  # put the newest one back
```

### What is on disk

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

### Environment

| Variable | Effect |
|---|---|
| `PASSBOX_DIR` | Where the store lives, default `~/.passbox` |
| `PASSBOX_REMOTE` | Overrides the destination for one run, ahead of the one `sync --enable` recorded |
| `PASSBOX_AGENT` | Name shown in the prompt beside the secret |
| `PASSBOX_PASSPHRASE` | Supplies the passphrase for CI and headless use, and turns off the Enclave path |

### Building

```bash
cargo test
cargo test -- --ignored   # the Secure Enclave round trip, needs a finger
```

`build.rs` compiles the Swift helper with `swiftc` from the Command Line Tools.

### Listing names without unlocking

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

### Fields in one entry

An entry can hold more than a password. The first line is the secret, later `key: value` lines
are fields, which is the layout `pass` uses and `import-pass` keeps.

```bash
passbox get db/prod                  # the whole thing
passbox get db/prod --field username # just that one
```

Reading one field hands a caller the password without the note beside it.

