+++
title = "Install"
weight = 1
+++


```bash
brew install gabrielkoerich/tap/passbox
passbox init
```

Recent Homebrew asks you to trust a third party tap before it will build from
one. If the install stops and says so, run `brew trust --formula
gabrielkoerich/tap/passbox` and try again.

That downloads a prebuilt binary. Nothing is compiled, so Rust is not needed.
Building from source, with `--build-from-source` or `--HEAD`, needs Rust and the
Command Line Tools for `swiftc`. A full Xcode is not needed either way.

### On Linux

Take the binary from a [release](https://github.com/gabrielkoerich/passbox/releases):

```bash
curl -sSfL -o passbox.tar.gz \
  https://github.com/gabrielkoerich/passbox/releases/latest/download/passbox-x86_64-unknown-linux-musl.tar.gz
tar -xzf passbox.tar.gz && sudo install passbox /usr/local/bin/
```

That binary is statically linked against musl, so it runs on any distribution regardless of its
glibc. It is the client build: no Secure Enclave, no broker and no `sync`, so it opens a store
with a passphrase rather than a fingerprint. Asking a Mac to approve a read is designed, not built.
See [Known limits](/design#known-limits).

`init` binds the store to this Mac's Secure Enclave and asks for nothing else.
There is no passphrase, so there is no file anyone can carry off and grind at.

The cost is plain: the store opens on this Mac only. Lose it and the secrets are
gone. Turning on sync is what adds a way back, and it is off until you ask.

