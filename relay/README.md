# Push relay

Wakes the passbox iPhone app when its Mac has a request waiting. Only the app's owner can ask Apple to send the app a notification, so the APNs key lives here and never on a Mac.

The phone registers its device token and gets back an id and a secret, and hands both to its Mac when they pair. When a prompt waits, the broker sends the relay those two, and the phone shows "Your Mac is waiting for an approval". The secret's name and the agent never leave the Mac.

| Path | Body | Answer |
|---|---|---|
| `POST /register` | `token` (hex), `environment` (`production` or `sandbox`), and `id` and `secret` to keep an existing registration | `id`, `secret` |
| `POST /push` | `id`, `secret` | `ok`, or why Apple refused |

The store keeps a SHA-256 of each secret, so reading it is not enough to push. A push only reads. A token Apple reports as unregistered is deleted.

`src/relay.ts` knows nothing about where it runs. It takes a place to keep phones and a way to reach Apple, which has to be HTTP/2.

## On Cloudflare

`src/cloudflare.ts` keeps phones in KV and reaches Apple with the Worker's fetch.

```bash
bunx wrangler login
bunx wrangler kv namespace create PHONES     # put the id in wrangler.toml
bunx wrangler secret put APNS_KEY < AuthKey_XXXXXXXXXX.p8
bunx wrangler deploy
```

The free plan allows 100,000 requests and 1,000 KV writes a day for the whole account. Only a registration writes.

## On a server

`src/server.ts` runs under Bun, keeps phones in SQLite and reaches Apple over `node:http2`, since Bun's fetch speaks HTTP/1.1, which APNs refuses. It listens on `127.0.0.1:8788` without TLS, so put a proxy such as Caddy in front for HTTPS.

```bash
APNS_KEY_FILE=AuthKey_XXXXXXXXXX.p8 KEY_ID=XXXXXXXXXX TEAM_ID=XXXXXXXXXX \
  TOPIC=com.gabrielkoerich.passbox.signer DATA=/var/lib/passbox-push/phones.db bun src/server.ts
```

## Test

```bash
bun test && bunx tsc --noEmit
```

The tests run the relay against a fake Apple, and the HTTP/2 sender against a local HTTP/2 server.
