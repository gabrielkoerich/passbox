# passbox, for agents

passbox holds secrets so an agent never has to. A read raises a Touch ID prompt naming the
agent and the secret, and the value goes into one child process rather than into the agent's
context.

If you are an agent reading this: the rule is **never put a secret in your context**. Run the
command that needs it instead.

## The one thing to do

```bash
passbox exec --env GITHUB_TOKEN=github/token -- gh api /user
```

The value goes broker to child. It is not in your transcript, your logs, or any tool result
you send onward. Use `--stdin` where the command accepts a secret that way, since anything
running as the user can read a child's environment with `ps eww`.

`passbox get` exists for a human at a terminal. Reach for it only when a library needs the
value in-process, and never to show it.

## Through MCP

Preferred for an agent, because the tools cannot hand you a value at all.

```bash
claude mcp add passbox -- passbox mcp          # Claude Code
codex mcp add passbox -- passbox mcp           # Codex
```

Any client that speaks MCP over stdio works; the command is always `passbox mcp`. For one that
wants JSON:

```json
{ "mcpServers": { "passbox": { "command": "passbox", "args": ["mcp"] } } }
```

| Tool | Returns |
|---|---|
| `list_secrets` | names only |
| `run_with_secret` | the command's output, with the value scrubbed out |

There is deliberately no `get_secret`. A tool result lands in the model's context, where it is
logged and sent onward, so the tools run the command for you instead. If the command prints the
secret anyway, passbox replaces it in the output first.

The agent name in the prompt comes from the MCP handshake, so it is the client's own
`clientInfo.name`.

## Running unattended

An agent on a schedule cannot answer a prompt. Inject at launch and the process never reads
passbox again:

```bash
passbox exec --env API_KEY=svc/key -- ./scheduled-job
```

Where that is not possible, mint a token for the secrets the job reads. It opens those and
nothing else, for at most 24 hours:

```bash
export PASSBOX_TOKEN=$(passbox grant svc/key svc/other --for 86400)
```

A namespace is refused: name what the job reads. See the [README](README.md#a-job-that-runs-unattended).

## What you cannot do

- Read a secret without the user approving it, unless a token or an injected variable already
  covers it. That is the point.
- Grant yourself more than you were given. A token opens the names it was granted.
- Escape the audit log. Every release is recorded, and `passbox audit` shows it.

## If you are asked to store a secret

```bash
printf '%s' "$VALUE" | passbox add service/name
```

Never write it to a file first, never echo it, and never put it in a commit. `gitleaks` will
catch the last one, but only after you have already leaked it to the working tree.
