# passbox, for agents

passbox holds secrets so an agent never has to. A read raises a Touch ID prompt naming the agent and the secret, and the value goes into one child process. It never enters the agent's context.

If you are an agent reading this: the rule is **never put a secret in your context**. Run the command that needs it instead.

## The one thing to do

```bash
passbox exec --env GITHUB_TOKEN=github/token -- gh api /user
```

The value goes broker to child. It is not in your transcript, your logs, or any tool result you send onward. Use `--stdin` where the command accepts a secret that way, since anything running as the user can read a child's environment with `ps eww`.

`passbox get` exists for a human at a terminal. It writes the secret to stdout, so it refuses when stdout is not a terminal, which is where an agent runs. No flag gets past that. Use `exec` or `run_with_secret`.

## Through MCP

This is the better path for an agent, because the tools cannot hand you a value at all.

```bash
claude mcp add passbox -- passbox mcp          # Claude Code
codex mcp add passbox -- passbox mcp           # Codex
```

Any client that speaks MCP over stdio works; the command is always `passbox mcp`. For one that wants JSON:

```json
{ "mcpServers": { "passbox": { "command": "passbox", "args": ["mcp"] } } }
```

| Tool | Returns |
|---|---|
| `list_secrets` | names only |
| `run_with_secret` | the command's output, with the value scrubbed out |

There is no `get_secret`. A tool result lands in the model's context, where it is logged and sent onward, so the tools run the command for you instead. If the command prints the secret anyway, passbox replaces it in the output first.

The agent name in the prompt comes from the MCP handshake, so it is the client's own `clientInfo.name`.

## Running unattended

An agent on a schedule cannot answer a prompt. Inject at launch and the process never reads passbox again:

```bash
passbox exec --env API_KEY=svc/key -- ./scheduled-job
```

Where that is not possible, mint a token for the secrets the job reads. It opens those and nothing else, for at most 24 hours:

```bash
export PASSBOX_TOKEN=$(passbox grant svc/key svc/other --for 86400)
```

A namespace is refused: name what the job reads. See the [README](README.md#unattended).

## What you cannot do

- Read a secret without the user approving it, unless a token or an injected variable already covers it.
- Grant yourself more than you were given. A token opens the names it was granted, and a child minted from it with `passbox grant --token-stdin` opens a subset of those and ends no later.
- Escape the audit log. Every release and every refused prompt is recorded, and `passbox audit` shows it.

## If you are asked to store a secret

```bash
printf '%s' "$VALUE" | passbox add service/name
```

Never write it to a file first, never echo it, and never put it in a commit. `gitleaks` will catch the last one, but only after you have already leaked it to the working tree.

<!-- shipcheck:start v4 -->

## Tests and commits

- Do not run the test commands (`pytest`, `cargo test`, `npm test`, `go test`, `just test` and the like). Run `shipcheck run`. It runs this repository's CI on your working copy, and its result is the PR's required check.
- Commit with `shipcheck commit -m "<subject>"`, never `git commit`. It commits every file, exactly the tree that passed.
- Work in small steps: one change, `shipcheck run`, `shipcheck commit`. Delete scratch files first, because every file is committed.
- Exit 1: read `shipcheck logs`, fix, then `shipcheck run --job <id>` for the failed job as often as needed. A partial run is never the check, so finish with one full `shipcheck run`, then `shipcheck commit`. Exit 2: shipcheck could not run, so run `shipcheck doctor` and follow it.
- If `shipcheck` is not on PATH, run the project's tests and commit with git.
- Never edit `.github/workflows/` or `shipcheck.toml` to get a pass. Details: https://shipcheck.run/llms.txt

<!-- shipcheck:end -->
