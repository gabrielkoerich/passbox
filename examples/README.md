# Examples

Each is a small client over the CLI, with a runnable self-check against a throwaway store. None reads a value into the calling process, since `passbox get` refuses a pipe. The Rust one has no dependency: it runs itself under `passbox exec` and reads its environment.

| | Run the self-check |
|---|---|
| [`python`](python) | `python3 python/passbox.py` |
| [`rust`](rust) | `cargo run --manifest-path rust/Cargo.toml` |
| [`mcp`](mcp) | `python3 mcp/passbox_mcp.py` |
| [`typescript`](typescript) | `npx tsx typescript/selfcheck.ts` |
| [`linux-client`](linux-client) | a container that asks a Mac over the tailnet |

The Python client shows three things any language needs:

**Inject, do not read.** `run_with` shells out to `passbox exec`, so the value goes broker to child and a crash in the calling process cannot carry it. There is no other way to get a value from a program.

**Mint one grant per process.** A token caches on the client. Build a fresh client per call and you mint a fresh grant per call, which is a fingerprint per read. An inherited `PASSBOX_TOKEN` always wins, so a daemon can hand one to the jobs it spawns.

**Do not use `ls` as a health check.** It needs the store key and raises a prompt every time. Check for the binary and the store directory instead.
