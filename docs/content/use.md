+++
title = "Use"
weight = 2
+++


```bash
printf 'ghp_xxx' | passbox add github/token
passbox ls
passbox get github/token
```

### Coming from pass

```bash
passbox import-pass              # everything
passbox import-pass bean         # one namespace
passbox import-pass bean/token   # one entry
```

Each entry is decrypted through GPG and re-encrypted to the store key. The whole
body is kept, so the `key: value` lines many pass entries carry under the
password survive. Entries already in the store are skipped unless you pass
`--force`, and nothing in `pass` is changed or removed.

### Giving a secret to an agent

The value goes into one child process and never into the agent.

```bash
passbox exec --env GITHUB_TOKEN=github/token -- gh api /user
passbox exec --stdin db/password -- psql
```

Prefer `--stdin` where the tool accepts it. Any process running as you can read a
child's environment with `ps eww`.

Set `PASSBOX_AGENT` so the prompt names the caller.

```bash
PASSBOX_AGENT=claude-code passbox exec --env GH_TOKEN=github/token -- gh pr list
```

The prompt then reads `passbox is trying to release the password for
github/token to claude-code.` macOS writes the opening clause from the binary
name, and passbox writes the rest.

### Through MCP

An agent asks through tools rather than a shell, and the tools cannot hand it a value at all.

```bash
claude mcp add passbox -- passbox mcp          # Claude Code
codex mcp add passbox -- passbox mcp           # Codex
```

Any client that speaks MCP over stdio works, and the command is always `passbox mcp`. For one
configured by file:

```json
{
  "mcpServers": {
    "passbox": { "command": "passbox", "args": ["mcp"] }
  }
}
```

That file is `~/.claude.json` for Claude Code, `~/.codex/config.toml` for Codex in TOML form,
and `~/.cursor/mcp.json` for Cursor. Check it took with `claude mcp list`.

The server exposes two tools, and neither returns a secret.

| Tool | Returns |
|---|---|
| `list_secrets` | names only |
| `run_with_secret` | the command's output, with the value scrubbed out of it |

There is deliberately no `get_secret`. A tool result lands in the model's context,
where it is logged and sent onward, so the tools run the command for the agent
instead of handing it the value. If the command prints the secret anyway,
passbox replaces it in the output before returning.

The agent name in the prompt comes from the MCP handshake, so it is the client's
own `clientInfo.name` rather than a guess up the process tree.

### Approving a project once

A project declares what it needs in `.passbox.toml`:

```toml
secrets = ["github/token", "npm/token"]
window_secs = 3600
```

The first time an agent working in that directory asks for one of them, passbox
shows a single prompt covering the whole list, and does not ask again for the
window. The default is an hour and the cap is twelve.

**The file is a request, not a grant.** An agent can write one itself, so nothing
is approved until you put your finger on the sensor. The approval is bound to the
file's SHA-256: add a secret to the list and the hash changes, so it asks again.
A secret set to `never` is refused no matter what the manifest says.

The project is the caller's working directory, read from the kernel rather than
taken from the request, so a caller cannot point at a manifest somewhere else.
Grants live in `grants-<host>.age`, encrypted, and never sync.

### Permission modes

Every secret carries one.

| Mode | Behaviour |
|---|---|
| `open` | No prompt, for a token an agent reads all day |
| `window` | One prompt per agent and secret per window, the default |
| `always` | A prompt on every read |
| `never` | Never released to an agent, interactive `get` only |

```bash
passbox mode banking/login never
passbox add github/token --mode window --window 600
```

A new value never widens access. Adding over an existing secret keeps the mode it
already had unless you pass `--mode`.

### Seeing what was released

```bash
passbox audit --tail 50
```

Every decision is logged, encrypted, one record per line.

