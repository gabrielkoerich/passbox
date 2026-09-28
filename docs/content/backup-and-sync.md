+++
title = "Backup and sync"
weight = 3
+++


git carries the encrypted secrets and nothing that opens them.

```bash
passbox git init
passbox git remote add origin git@github.com:you/passbox-store.git
```

After that every write commits on its own, the way `pass` does: `add`, `rm`, `mode`, `restore`
and `import-pass`. `sync` is what pushes, since pushing on every write would be slow. Nothing
happens until you run `git init`, so the history is a choice.

**A write also updates the copy.** Once `sync --enable` has chosen a directory, every write
copies to it, because nobody remembers to run `sync` and a secret that exists only on this Mac
is a secret you can lose. A delete travels too, as a tombstone.

Only a directory, which is a few milliseconds. Git and rclone remotes are a network round trip
and stay on `passbox sync`. It is best effort: the value is already written and encrypted, so an
unplugged USB stick warns rather than failing the command. `PASSBOX_NO_AUTOSYNC=1` turns it off
for a script that writes in a loop.

Commit subjects name the operation and never the entry, because a subject naming a secret would
undo the work of keeping names out of filenames.

**What history costs.** `passbox rm` writes a tombstone and prunes after 90 days, so a secret
really goes. Git keeps it: the old `.age` blob stays in the history, still readable by the store
key. With a repo, delete stops meaning delete. That is the same trade `pass` makes, and it is
worth making deliberately.

Git and sync are not alternatives. With both set up a write does both, and they answer different
questions: the repo is this machine's history, the copy is what survives the machine. The repo
is never copied to the mirror, because a shared directory holding two machines' git internals
would be a mess, and the remote is a mirror rather than a clone.

The Secure Enclave wraps are excluded, so the remote holds opaque age files that
only this Mac can read. That protects you from deleting a secret by accident. It
does **not** protect you from losing the Mac, because nothing in the backup can
open it. For that, turn on sync.

### Sync

Sync is off, and nothing leaves the Mac until you run `passbox sync` yourself.
There is no timer and no syncing on write.

```bash
passbox sync --enable
passbox sync
```

`--enable` asks two questions.

The first is how a second machine gets in, a YubiKey or a passphrase. See [If you
lose the Mac](/backup-and-sync#if-you-lose-the-mac).

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

### If you lose the Mac

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

passbox uses the **PIV** applet. OpenPGP keys live in a separate applet on the
same chip and are never touched. Before provisioning a slot it reads what PIV
already holds and shows you, using `ykman` when it is installed.

### When the YubiKey will not cooperate

Four failures, each with an error naming neither the cause nor the fix. In the order you are
likely to meet them.

**`Failed to authenticate with the PIN-protected management key`**

Firmware 5.7 sets the PIV management key algorithm to **AES192**, and `age-plugin-yubikey`
supports TDES only. A factory reset does not help, because the reset sets AES192 too, so a
brand new token arrives in this state.

```bash
ykman piv info | grep "Management key algorithm"   # AES192 means read on
ykman piv access change-management-key -a tdes \
  -n 010203040506070801020304050607080102030405060708
```

passbox checks this before it asks the plugin for anything, so it says which algorithm is set
rather than failing inside the plugin.

**`Error while communicating with YubiKey: authentication error`, after the touch**

GPG's `scdaemon` opens the smart card exclusively and holds it. It lands between the plugin's
key generation and its certificate write, and the write comes back as an authentication error.
Anything that calls `pass` starts it again, including a scheduled job, so it can reappear
mid-operation.

```bash
gpgconf --kill scdaemon
```

passbox offers to do this before generating. If something on a timer keeps restarting it, stop
that first.

**The touch never registers**

On a 5C Nano the contact sits flush in the port and is hard to reach. The plugin waits, gets
nothing, and reports it as an authentication error.

```bash
age-plugin-yubikey --generate --touch-policy never
```

For a Nano that is the right setting rather than a workaround: the form factor exists to live
in a port permanently. The PIN still applies, so a stolen token is useless without it.

**A prompt appears and the PIN is refused**

If generation failed *after* the plugin's PIN-change step, your PIN is already the new one even
though nothing was provisioned. Retrying with the old PIN burns attempts, and three wrong tries
locks the applet. Check `ykman piv info` for `PIN tries remaining` before retrying, and reset
rather than guess:

```bash
ykman piv reset       # needs no PIN, wipes the PIV applet only
```

A reset leaves your OpenPGP keys and their PIN untouched. They are a separate applet on the
same chip. Remember to set TDES again afterwards.

**A half-provisioned slot**

A failed generation can leave a private key with no certificate. `ykman piv info` shows the
slot; `ykman piv keys delete <slot>` clears it, or `ykman piv reset` clears everything.

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

