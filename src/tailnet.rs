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

/// The machine and user behind a tailnet address, authenticated by the control plane
pub fn whois(peer: std::net::IpAddr) -> Option<String> {
    let out = std::process::Command::new("tailscale")
        .args(["whois", &peer.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key))
            .map(|v| v.trim().to_string())
    };
    match (field("Machine:"), field("User:")) {
        (Some(m), Some(u)) => Some(format!("{m} ({u})")),
        (Some(m), None) => Some(m),
        _ => None,
    }
}
