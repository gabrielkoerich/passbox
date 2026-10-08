# A Linux client

Proof that a machine with no Secure Enclave can read a secret held by a Mac, with the fingerprint happening on the Mac.

This container holds **no store and no key**. `passbox get` opens a TCP connection to the Mac's broker over the tailnet, a Touch ID prompt appears there naming this machine, and the value comes back. A copy of the container is worth nothing.

## On the Mac

The broker has to be running already. One spawned by an incoming connection cannot raise a Touch ID prompt. Testing shows that a process without a GUI session gets `canEvaluatePolicy` false.

```bash
tailscale status          # up, and this machine has a 100.x address
passbox ls                # starts a broker, which then listens on the tailnet too
```

The broker binds to the tailnet address only. It does not bind loopback, which has none of the unix socket's `0600` protection, or every interface, which would put a secrets daemon on the LAN. With Tailscale down it opens no port at all and says so.

## Here

```bash
docker build -t passbox-client examples/linux-client
docker run -it --rm \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e TS_AUTHKEY=tskey-auth-... \
  -e PASSBOX_HOST=m4 \
  passbox-client
```

Then inside:

```bash
passbox get github/token
```

`PASSBOX_HOST` is the Mac's tailnet name, or `name:port` for a port other than 8787. It can also live in `~/.passbox/host`, which is what the entrypoint writes.

## Plugins

A plugin action runs on the Mac too. The container names the tool, the broker on the Mac approves it with Touch ID, runs it against the local app, and sends the output back.

```bash
passbox plugin things3 today
passbox plugin mail search --query invoice
```

Only the Mac has Mail, Things and the plugin files. The container just names the tool and its parameters, so a plugin needs nothing installed here. A tool that acts on the caller's own directory, such as `git` or `gh`, is refused: there is no repo here to act on.

Run the opt-in plugin check in the smoke test with `PASSBOX_DEMO_PLUGINS=1 ./smoke.sh <a-secret-name>`.

## What this does not give you

**The client cannot list.** `ls` needs names, which needs the store key, which lives on the Mac. Ask for a name you know.

**The agent name is still self declared.** `PASSBOX_AGENT` is whatever the caller sets. Over the tailnet the broker also runs `tailscale whois` on the peer address. The control plane authenticated that name, so the prompt shows a machine rather than a claim.

**The Mac has to be awake, unlocked, and lid open.** No prompt can be answered otherwise. A closed lid fails, and the error says so: Touch ID is unavailable, open the lid or use the recovery passphrase.
