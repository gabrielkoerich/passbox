+++
title = "Unattended"
weight = 4
+++


A daemon cannot answer a fingerprint prompt at 3am, so the goal is that it never has to read
passbox at all after it starts.

### Inject at launch, and stop reading

The first thing to reach for. One approval, and the value lands in the process environment
where every child inherits it:

```bash
passbox exec --env GITHUB_TOKEN=github/token -- ./your-daemon
```

Nothing shells out to passbox again for the life of that process, so it runs for weeks on one
fingerprint and needs you only when you restart it. This works with no code change wherever a
credential layer already prefers an environment variable over its providers.

Cost: the value sits in the environment for the process's lifetime, and anything running as you
can read it with `ps eww`. Use `--stdin` where the child takes a secret that way.

### A grant, for what cannot be injected

Some secrets have no usable variable name, and some jobs pick what they read at runtime. For
those, one approval mints a **token** that opens exactly the secrets it was granted, to whoever
holds it, until it lapses:

```bash
export PASSBOX_TOKEN=$(passbox grant acme/signing-key acme/api-key --for 86400)
```

The token goes to stdout and the covered names to stderr, so `$(...)` captures the token alone.
Reads that present it are audited as `by token`.

**A namespace is refused.** `grant acme` would hand over everything under it to save one prompt,
and it scopes on how the store happens to be laid out rather than on what the job reads: put
everything at the root and a namespace rule protects nothing.

```bash
passbox grant acme
passbox: acme is a namespace holding 9 secrets, ask for the ones this needs:
  acme/api-key
  acme/signing-key
  ...
```

The refusal lists them, so naming them is a copy rather than a chore, and it costs no
fingerprint: the names come from the local index before the broker is involved.

**24 hours is the ceiling** and it cannot be raised. A token that never lapses is a password
with extra steps. Something that must run untended indefinitely wants injection, not a token.

Restarting the broker tears up every outstanding token:

```bash
pkill -f "passbox broker"
```

### Mint once per process

A token caches on the client that minted it. A factory that builds a fresh client per call
mints a fresh grant per call, and each one is a fingerprint. Memoise it. The symptom is
repeated `approved` for one secret and one agent in `passbox audit`.

