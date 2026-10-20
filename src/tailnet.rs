/* Reaching the broker from another machine, without handing out a shell.

Remote Login grants a shell to anything holding a key, for a design that needs one socket. The
broker instead listens on loopback and `tailscale serve` forwards tailnet connections to it.

`tailscale whois` turns the peer address into a machine the control plane authenticated. Everywhere else in passbox the agent name is self declared; this is the first
caller identity that is verified, so the prompt can say who is really asking. */

/// This machine's tailnet address, or None when Tailscale is not up
pub fn address() -> Option<std::net::IpAddr> {
    let out = std::process::Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

/* The host behind a tailnet address, named by the control plane, as `legion (100.90.49.41)`.

`tailscale whois` prints `Machine:` and `User:` as headers with the values on indented lines
beneath, so the name is the first `Name:` under each header rather than the header's own text. */
pub fn whois(peer: std::net::IpAddr) -> Option<String> {
    let out = std::process::Command::new("tailscale")
        .args(["whois", &peer.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let name = parse(&String::from_utf8_lossy(&out.stdout))?;
    Some(format!("{name} ({peer})"))
}

/// Split out so the shape can be tested without a tailnet
fn parse(text: &str) -> Option<String> {
    let mut machine = None;
    let mut user = None;
    let mut section = "";
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Machine:") {
            section = "machine";
        } else if trimmed.starts_with("User:") {
            section = "user";
        } else if let Some(name) = trimmed.strip_prefix("Name:") {
            let name = name.trim().to_string();
            match section {
                "machine" if machine.is_none() => machine = Some(name),
                "user" if user.is_none() => user = Some(name),
                _ => {}
            }
        }
    }

    // The MagicDNS suffix is the same for every node, so the first label is what tells hosts apart
    machine
        .map(|m| m.split('.').next().unwrap_or(&m).to_string())
        .filter(|m| !m.is_empty())
        .or(user)
}

/* `tailscale serve` forwards to loopback, so the socket's peer is always 127.0.0.1. With
`--proxy-protocol 1` it opens every connection with `PROXY TCP4 <src> <dst> <sport> <dport>`,
and the source is the tailnet node. The header is required: if it were optional, a client could
send its own and name any host. Read a byte at a time so nothing past the header is consumed */
pub fn proxied_peer(stream: &mut impl std::io::Read) -> Option<std::net::IpAddr> {
    // A v1 header is at most 107 bytes with its CRLF
    let mut line = Vec::with_capacity(107);
    let mut byte = [0u8];
    while line.len() < 107 {
        stream.read_exact(&mut byte).ok()?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    proxy_source(std::str::from_utf8(&line).ok()?)
}

fn proxy_source(line: &str) -> Option<std::net::IpAddr> {
    let line = line.strip_suffix("\r\n")?;
    let mut fields = line.split(' ');
    if fields.next()? != "PROXY" || !matches!(fields.next()?, "TCP4" | "TCP6") {
        return None;
    }
    fields.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real shape of `tailscale whois`, which nests the name under a header
    const SAMPLE: &str = "Machine:\n  Name:          homeassistant.tail342cb6.ts.net\n  ID:            n81YALHkUi11CNTRL\n  Addresses:     [100.100.18.1/32]\nUser:\n  Name:     someone@example.com\n";

    #[test]
    fn a_peer_is_named_by_its_machine() {
        assert_eq!(parse(SAMPLE).as_deref(), Some("homeassistant"));
    }

    #[test]
    fn the_proxy_header_names_the_source() {
        let mut stream: &[u8] =
            b"PROXY TCP4 100.90.49.41 127.0.0.1 51234 8787\r\n{\"op\":\"list\"}\n";
        assert_eq!(
            proxied_peer(&mut stream),
            Some("100.90.49.41".parse().unwrap())
        );
        // The request after the header is left for the reader
        assert_eq!(stream, b"{\"op\":\"list\"}\n");
    }

    #[test]
    fn a_request_without_the_header_is_refused() {
        let mut stream: &[u8] = b"{\"op\":\"list\"}\n";
        assert!(proxied_peer(&mut stream).is_none());
        assert!(proxy_source("PROXY UNKNOWN\r\n").is_none());
        assert!(proxy_source("PROXY TCP4 legion 127.0.0.1 1 2\r\n").is_none());
    }

    #[test]
    fn nothing_useful_is_none() {
        assert!(parse("").is_none());
        assert!(parse("Machine:\n  ID: x\n").is_none());
    }
}
