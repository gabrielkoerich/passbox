# A Linux client that asks a Mac for a secret.
#
# It holds no store and no key. `passbox get` here opens a TCP connection to the Mac's broker
# over the tailnet, a Touch ID prompt appears there naming this machine, and the value comes
# back. Nothing is unlocked on this side, so a copy of this container is worth nothing.
#
# Build and run:
#   docker build -t passbox-client examples/linux-client
#   docker run -it --rm --cap-add NET_ADMIN --device /dev/net/tun \
#     -e TS_AUTHKEY=tskey-auth-... -e PASSBOX_HOST=your-mac \
#     passbox-client
FROM --platform=linux/amd64 ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl iptables \
    && rm -rf /var/lib/apt/lists/*

# Tailscale, because the broker answers on the tailnet address and nowhere else
RUN curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg \
        > /usr/share/keyrings/tailscale-archive-keyring.gpg \
    && curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list \
        > /etc/apt/sources.list.d/tailscale.list \
    && apt-get update && apt-get install -y --no-install-recommends tailscale \
    && rm -rf /var/lib/apt/lists/*

# The client build: no Secure Enclave, no broker server, no sync.
# Only x86_64 Linux is released, so on an arm64 host build with
#   docker build --platform linux/amd64 ...
RUN set -eux; \
    curl -fsSL -o /tmp/passbox.tar.gz \
      https://github.com/gabrielkoerich/passbox/releases/latest/download/passbox-x86_64-unknown-linux-gnu.tar.gz; \
    tar -xzf /tmp/passbox.tar.gz -C /usr/local/bin passbox; \
    rm /tmp/passbox.tar.gz; \
    test -x /usr/local/bin/passbox

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
