# Examples

Each is a small client over the CLI, with a runnable self-check against a throwaway store. No
library to depend on, and no key material in the calling process.

| | Run the self-check |
|---|---|
| [`python`](python) | `python3 python/passbox.py` |
| [`rust`](rust) | `rustc --edition 2021 rust/passbox.rs -o /tmp/pb && /tmp/pb` |
| [`typescript`](typescript) | `npx tsx typescript/selfcheck.ts` |
| [`linux-client`](linux-client) | a container that asks a Mac over the tailnet |

Both show the same three things, which are what any language needs:

**Inject, do not read.** `run_with` shells out to `passbox exec`, so the value goes broker to
child and a crash in the calling process cannot carry it.

**Mint one grant per process.** A token caches on the client. Build a fresh client per call and
you mint a fresh grant per call, which is a fingerprint per read. An inherited `PASSBOX_TOKEN`
always wins, so a daemon can hand one to the jobs it spawns.

**Do not use `ls` as a health check.** It needs the store key and raises a prompt every time.
Check for the binary and the store directory instead.
