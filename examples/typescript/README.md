# TypeScript

`dotenv`, without the secrets on disk.

A `.env` holds values, so it gets gitignored, passed around in chat, and read by anything
running as you. `.env.passbox` holds **names**:

```
DATABASE_URL=db-url
STRIPE_KEY=stripe
```

That file is safe to commit. It documents what the service needs without being worth stealing,
and a new machine needs no copy of anything.

## Loading into process.env

```ts
import { config } from "./passbox.js";

config({ namespace: "acme", agent: "api-server" });
// the rest of the code keeps reading process.env and never knows the difference
```

One approval covers every name in the file, rather than one prompt per variable. A variable
already set is left alone, so a deployment can override without touching the file. If the grant
fails, the reads fall back to prompting rather than the process dying.

## Better: do not load them at all

```bash
passbox exec --env DATABASE_URL=acme/db-url -- node server.js
```

The value goes from the broker into the child. A heap dump or an unhandled rejection in the Node
process cannot carry what the process never held. `execArgs()` builds that command line from the
same manifest.

Use `config()` only where something has to run in-process before the values are known.

## Running the self-check

```bash
npx tsx selfcheck.ts
```

It builds a throwaway store, so it needs no hardware and raises no prompt.
