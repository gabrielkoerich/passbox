/* Reaching the broker from another machine, without handing out a shell.

Remote Login grants a shell to anything holding a key, for a design that needs one socket. The
broker instead binds a second listener to this machine's tailnet address, so only tailnet peers
and this host can reach it. Loopback would be wrong: a TCP port there has none of the unix
socket's 0600 protection and any local user could connect.

`tailscale whois` turns the peer address into a machine and a user the control plane
authenticated. Everywhere else in passbox the agent name is self declared; this is the first
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

/* The machine and user behind a tailnet address, authenticated by the control plane.

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
    parse(&String::from_utf8_lossy(&out.stdout))
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

    match (machine, user) {
        (Some(m), Some(u)) => Some(format!("{m} ({u})")),
        (Some(m), None) => Some(m),
        (None, Some(u)) => Some(u),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real shape of `tailscale whois`, which nests the name under a header
    const SAMPLE: &str = "Machine:\n  Name:          homeassistant.tail342cb6.ts.net\n  ID:            n81YALHkUi11CNTRL\n  Addresses:     [100.100.18.1/32]\nUser:\n  Name:     someone@example.com\n";

    #[test]
    fn a_peer_is_named_by_machine_and_user() {
        let named = parse(SAMPLE).expect("a name");
        assert_eq!(
            named,
            "homeassistant.tail342cb6.ts.net (someone@example.com)"
        );
    }

    #[test]
    fn nothing_useful_is_none() {
        assert!(parse("").is_none());
        assert!(parse("Machine:\n  ID: x\n").is_none());
    }
}
