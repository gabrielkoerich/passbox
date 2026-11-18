/* Reaching the broker from another machine, without handing out a shell.

Remote Login grants a shell to anything holding a key, for a design that needs one socket. The
broker instead listens on loopback and `tailscale serve` forwards tailnet connections to it.

`tailscale whois` turns the peer address into a machine the control plane authenticated. Everywhere else in passbox the agent name is self declared; this is the first
caller identity that is verified, so the prompt can say who is really asking. */

/// The Mac app's own binary, which answers as the CLI when it is run with arguments
const APP_CLI: &str = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";

/// `tailscale` on PATH, or else the app's binary, so a Mac with only the app works, and so does
/// a broker under launchd, whose PATH has no `/usr/local/bin`
pub(crate) fn cli() -> std::path::PathBuf {
    pick(
        std::env::var_os("PATH").as_deref(),
        std::path::Path::new(APP_CLI),
    )
}

fn pick(path: Option<&std::ffi::OsStr>, app: &std::path::Path) -> std::path::PathBuf {
    let on_path =
        path.is_some_and(|p| std::env::split_paths(p).any(|d| d.join("tailscale").is_file()));
    if on_path || !app.is_file() {
        return std::path::PathBuf::from("tailscale");
    }
    app.to_path_buf()
}

/// The one command that exposes the broker to the tailnet, with the PROXY header it requires
pub(crate) fn serve_command() -> String {
    format!(
        "{} serve --bg --proxy-protocol 1 --tcp 8787 tcp://127.0.0.1:8787",
        cli().display()
    )
}

/// This machine's tailnet address, or None when Tailscale is not up
pub(crate) fn address() -> Option<std::net::IpAddr> {
    let out = std::process::Command::new(cli())
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

/* The host behind a tailnet address, named by the control plane, as `server (someone@example.com, 100.64.0.7)`.

`tailscale whois` prints `Machine:` and `User:` as headers with the values on indented lines
beneath, so the name is the first `Name:` under each header rather than the header's own text. */
pub(crate) fn whois(peer: std::net::IpAddr) -> Option<String> {
    let out = std::process::Command::new(cli())
        .args(["whois", &peer.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let (name, owner) = parse(&String::from_utf8_lossy(&out.stdout))?;
    Some(label(&name, owner.as_deref(), peer))
}

// The owner stays in, so a node shared in from another tailnet does not pass for one of ours
fn label(name: &str, owner: Option<&str>, peer: std::net::IpAddr) -> String {
    match owner {
        Some(owner) => format!("{name} ({owner}, {peer})"),
        None => format!("{name} ({peer})"),
    }
}

/// The machine's short name and its owner, split out so the shape can be tested without a tailnet
fn parse(text: &str) -> Option<(String, Option<String>)> {
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
    let machine = machine
        .map(|m| m.split('.').next().unwrap_or(&m).to_string())
        .filter(|m| !m.is_empty());
    match (machine, user) {
        (Some(m), user) => Some((m, user)),
        (None, Some(u)) => Some((u, None)),
        (None, None) => None,
    }
}

/* `tailscale serve` forwards to loopback, so the socket's peer is always 127.0.0.1. With
`--proxy-protocol 1` it opens every connection with `PROXY TCP4 <src> <dst> <sport> <dport>`,
and the source is the tailnet node. The header is required: if it were optional, a client could
send its own and name any host. Read a byte at a time so nothing past the header is consumed */
pub(crate) fn proxied_peer(stream: &mut impl std::io::Read) -> Option<std::net::IpAddr> {
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

    #[test]
    fn the_cli_on_path_wins_and_the_apps_binary_stands_in_for_it() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let app = tmp.path().join("Tailscale");
        let path = std::env::join_paths([&bin]).unwrap();

        // Neither: the bare name, so the failure names the command that is missing
        assert_eq!(
            pick(Some(&path), &app),
            std::path::PathBuf::from("tailscale")
        );
        std::fs::write(&app, "").unwrap();
        assert_eq!(pick(Some(&path), &app), app);
        assert_eq!(pick(None, &app), app);
        std::fs::write(bin.join("tailscale"), "").unwrap();
        assert_eq!(
            pick(Some(&path), &app),
            std::path::PathBuf::from("tailscale")
        );
    }

    /// The real shape of `tailscale whois`, which nests the name under a header
    const SAMPLE: &str = "Machine:\n  Name:          server.example.ts.net\n  ID:            nExampleCNTRL\n  Addresses:     [100.64.0.7/32]\nUser:\n  Name:     someone@example.com\n";

    #[test]
    fn a_peer_is_named_by_its_machine_and_owner() {
        let (name, owner) = parse(SAMPLE).expect("a name");
        let peer = "100.64.0.7".parse().unwrap();
        assert_eq!(
            label(&name, owner.as_deref(), peer),
            "server (someone@example.com, 100.64.0.7)"
        );
        assert_eq!(label("server", None, peer), "server (100.64.0.7)");
    }

    #[test]
    fn a_node_with_no_machine_name_is_named_by_its_owner() {
        let text = "User:\n  Name:     someone@example.com\n";
        assert_eq!(parse(text), Some(("someone@example.com".into(), None)));
    }

    #[test]
    fn the_proxy_header_names_the_source() {
        let mut stream: &[u8] =
            b"PROXY TCP4 100.64.0.7 127.0.0.1 51234 8787\r\n{\"op\":\"list\"}\n";
        assert_eq!(
            proxied_peer(&mut stream),
            Some("100.64.0.7".parse().unwrap())
        );
        // The request after the header is left for the reader
        assert_eq!(stream, b"{\"op\":\"list\"}\n");

        let mut stream: &[u8] = b"PROXY TCP6 fd7a:115c:a1e0::7 ::1 51234 8787\r\n";
        assert_eq!(
            proxied_peer(&mut stream),
            Some("fd7a:115c:a1e0::7".parse().unwrap())
        );
    }

    #[test]
    fn a_request_without_a_valid_header_is_refused() {
        let refused: [&[u8]; 7] = [
            b"{\"op\":\"list\"}\n",
            b"PROXY TCP4 100.64.0.7 127.0.0.1 1 2\n",
            b"PROXY TCP4 100.64.0.7 127.0.0.1",
            b"PROXY UDP4 100.64.0.7 127.0.0.1 1 2\r\n",
            b"proxy TCP4 100.64.0.7 127.0.0.1 1 2\r\n",
            b"PROXY TCP4 server 127.0.0.1 1 2\r\n",
            b"",
        ];
        for bytes in refused {
            let mut stream = bytes;
            assert!(
                proxied_peer(&mut stream).is_none(),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
        assert!(proxy_source("PROXY UNKNOWN\r\n").is_none());
    }

    #[test]
    fn a_header_too_long_for_v1_is_refused_without_reading_past_it() {
        let long = format!("PROXY TCP4 {}\r\nrest", "1".repeat(200));
        let mut stream = long.as_bytes();
        assert!(proxied_peer(&mut stream).is_none());
        assert_eq!(stream.len(), long.len() - 107);
    }

    #[test]
    fn nothing_useful_is_none() {
        assert!(parse("").is_none());
        assert!(parse("Machine:\n  ID: x\n").is_none());
    }
}
