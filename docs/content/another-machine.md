+++
title = "Another machine"
weight = 5
+++


A Linux box with no Secure Enclave can read a secret held by a Mac. The fingerprint happens on
the Mac; the client holds no store and no key, so a copy of it is worth nothing.

Verified from a Raspberry Pi on a LAN and a fly.io machine in another country, both over
Tailscale.

### On the Mac

The broker has to be **already running, in your login session**. One started by an incoming
connection cannot raise a Touch ID prompt: whoever calls `evaluatePolicy` has to be somewhere a
sensor is reachable. A LaunchAgent is how you get that.

`~/Library/LaunchAgents/com.you.passbox.broker.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.you.passbox.broker</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/passbox</string>
    <string>broker</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/tmp/passbox-broker.log</string>
</dict>
</plist>
```

`PATH` is not decoration. A LaunchAgent gets a minimal one, `tailscale` is not on it, and the
broker then starts with no tailnet listener and says nothing about why.

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.you.passbox.broker.plist
tailscale serve --bg --tcp 8787 tcp://127.0.0.1:8787
```

### Why `serve` rather than binding the tailnet address

The broker binds `127.0.0.1:8787` and Tailscale forwards to it. Binding the 100.x address
directly looks right and does not work: macOS runs Tailscale as a network extension, the socket
accepts the connection, and the first read fails with `ENOTCONN`. Measured 2026-09-27, and
reproduced with a plain Python server, so it is the platform rather than passbox.

Cost: loopback has none of the unix socket's `0600` protection, so any local user can reach that
port. It is the only inbound path macOS actually delivers.

### On the client

```bash
curl -fsSL -o passbox.tar.gz \
  https://github.com/gabrielkoerich/passbox/releases/latest/download/passbox-x86_64-unknown-linux-musl.tar.gz
tar -xzf passbox.tar.gz && sudo install passbox /usr/local/bin/

echo "100.x.y.z" > ~/.passbox/host      # the Mac's tailnet address, or its MagicDNS name
passbox get github/token
```

`PASSBOX_HOST` does the same for one run. A configured host wins over anything on the client's
own disk, so a machine with no store still asks the Mac rather than falling back to a passphrase
it does not have.

### In a container

[`examples/linux-client`](https://github.com/gabrielkoerich/passbox/tree/main/examples/linux-client) has a Dockerfile with Tailscale and the client,
and a fly.io deployment that was used to verify this.

```bash
fly launch --no-deploy --name passbox-poc
fly secrets set TS_AUTHKEY=tskey-auth-... PASSBOX_HOST=100.x.y.z
fly deploy --ha=false
fly ssh console -C "passbox get github/token"
```

Give the container a real tun device. `tailscaled --tun=userspace-networking` reaches the
tailnet only through a SOCKS proxy, so an ordinary `connect()` to a 100.x address times out with
no hint why. The entrypoint uses `/dev/net/tun` when the platform provides one.

### What this does not give you

**No listing.** `ls` needs the names, which needs the store key, which stays on the Mac. Ask for
a name you know.

**The caller is not identified.** The broker runs `tailscale whois` on the peer, which the
control plane authenticates, but traffic arriving through `serve` has a loopback peer address,
so it resolves to nothing and the prompt says `an unidentified tailnet peer`. `PASSBOX_AGENT` is
still whatever the caller claims.

**The Mac must be awake, unlocked, and its lid open.** Nothing can answer a prompt otherwise,
and a closed lid fails with `canEvaluatePolicy` false rather than anything clearer.

**Nobody is there at 3am.** A scheduled job wants injection or a
grant, not a prompt. See [Unattended](/unattended).

