#!/usr/bin/env bash
# Join the tailnet, point passbox at the Mac, then hand over.
set -euo pipefail

: "${PASSBOX_HOST:?set PASSBOX_HOST to the Mac tailnet name, such as m4 or m4.tailnet.ts.net}"

# A real tun where the platform allows it. Userspace networking reaches the tailnet only
# through a SOCKS proxy, so an ordinary connect() to a 100.x address times out.
if [ -c /dev/net/tun ]; then
    tailscaled --state=/var/lib/tailscale/state >/var/log/tailscaled.log 2>&1 &
else
    tailscaled --tun=userspace-networking --state=/var/lib/tailscale/state >/var/log/tailscaled.log 2>&1 &
fi
for _ in $(seq 30); do tailscale status >/dev/null 2>&1 && break; sleep 1; done

if [ -n "${TS_AUTHKEY:-}" ]; then
    tailscale up --authkey "$TS_AUTHKEY" --hostname "${TS_HOSTNAME:-passbox-client}"
else
    tailscale up --hostname "${TS_HOSTNAME:-passbox-client}"
fi

# A client keeps no store. `host` is the one line it needs, and PASSBOX_HOST would do as well.
mkdir -p /root/.passbox
echo "$PASSBOX_HOST" > /root/.passbox/host

cat <<'MSG'

Ready. This machine holds no secrets. Try:

    passbox get some/secret

A Touch ID prompt appears on the Mac naming this machine, and the value comes back here.

MSG
exec "$@"
