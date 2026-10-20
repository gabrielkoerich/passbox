# TypeScript

`dotenv`, without the secrets on disk.

A `.env` holds values, so it gets gitignored, passed around in chat, and read by anything running as you. `.env.passbox` holds **names**:

```
DATABASE_URL=db-url
STRIPE_KEY=stripe
```

That file is safe to commit. It documents what the service needs without being worth stealing, and a new machine needs no copy of anything.

[`.passbox.toml`](../../README.md#approving-a-project-once) is a different file. It asks the broker to approve a list of secrets in one prompt. `.env.passbox` says which variable each value lands in. A project can have both, and then one approval covers the whole startup.

## Launching under passbox exec

```bash
passbox exec --env DATABASE_URL=acme/db-url -- node server.js
```

`execArgs()` builds that command line from the manifest. The value goes from the broker into the child, and the code keeps reading `process.env`. A heap dump or an unhandled rejection in the process that launches it cannot carry what that process never held.

There is no in-process loader. It needed `passbox get` to print into a pipe, which passbox refuses.

## Running the self-check

```bash
npx tsx selfcheck.ts
```

It builds a throwaway store, so it needs no hardware and raises no prompt.
