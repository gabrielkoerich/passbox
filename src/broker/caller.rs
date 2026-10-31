//! Who is asking: the process chain behind a request, and the agent name a prompt shows.

#[cfg(feature = "host")]
use std::os::unix::net::UnixStream;

#[cfg(feature = "host")]
const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "fish", "dash", "ksh"];

// Programs that only run another one, so the prompt names whoever ran them, never `timeout`
#[cfg(feature = "host")]
const WRAPPERS: [&str; 15] = [
    "timeout",
    "gtimeout",
    "nohup",
    "env",
    "nice",
    "time",
    "caffeinate",
    "stdbuf",
    "xargs",
    "sudo",
    "flock",
    "script",
    "setsid",
    "taskpolicy",
    "arch",
];

/* The client names the agent and the control plane names the host, so a remote prompt shows both.
The client's part loses control characters and is capped, so it cannot start a new line or pass a
second host off as the real one, which always comes last */
#[cfg(feature = "host")]
pub(super) fn remote_agent(agent: &str, host: &str) -> String {
    let agent: String = agent.chars().filter(|c| !c.is_control()).take(64).collect();
    format!("{} on {host}", agent.trim())
}

/// The program names in a process chain, nearest first, without their paths or login dashes
#[cfg(feature = "host")]
fn programs(chain: &str) -> impl Iterator<Item = &str> {
    chain.split(" < ").map(|comm| {
        comm.trim()
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_start_matches('-')
    })
}

#[cfg(feature = "host")]
/// The caller's process chain names the agent when none was given: the first ancestor that is
/// not passbox, a shell or a wrapper, such as claude or codex, or passbox when the chain has none
pub(super) fn prompt_agent(chain: &str) -> String {
    for name in programs(chain) {
        if name.is_empty()
            || name == "unknown"
            || name == "passbox"
            || SHELLS.contains(&name)
            || WRAPPERS.contains(&name)
        {
            continue;
        }
        return name.to_string();
    }
    "passbox".to_string()
}

/// The peer names the request, except that ssh gives way to a program that ran it, such as git
#[cfg(feature = "host")]
pub(super) fn ssh_requester(chain: &str) -> String {
    let mut names = programs(chain);
    match (names.next(), names.next()) {
        (Some("ssh"), Some(parent)) if !parent.is_empty() && !SHELLS.contains(&parent) => {
            parent.to_string()
        }
        (Some(peer), _) if !peer.is_empty() && peer != "unknown" => peer.to_string(),
        _ => "ssh".to_string(),
    }
}

/// The peer pid comes from the kernel, so the caller cannot fake its own path
#[cfg(all(feature = "host", target_os = "macos"))]
pub(super) fn peer_pid(stream: &UnixStream) -> Option<libc::pid_t> {
    use std::os::unix::io::AsRawFd;
    // SOL_LOCAL and LOCAL_PEERPID, which libc does not expose on every release
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;

    let mut pid: libc::pid_t = 0;
    let mut len =
        libc::socklen_t::try_from(size_of::<libc::pid_t>()).expect("a pid fits a socklen_t");
    // SAFETY: pid and len are live locals, and len holds pid's size
    let got = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };
    (got == 0 && pid > 0).then_some(pid)
}

// Linux runs the host build only in CI, where the tests need a real caller pid
#[cfg(all(feature = "host", not(target_os = "macos")))]
pub(super) fn peer_pid(stream: &UnixStream) -> Option<libc::pid_t> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len =
        libc::socklen_t::try_from(size_of::<libc::ucred>()).expect("a ucred fits a socklen_t");
    // SAFETY: cred and len are live locals, and len holds cred's size
    let got = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    (got == 0 && cred.pid > 0).then_some(cred.pid)
}

/* The project a grant belongs to is the caller's working directory, read from the kernel rather
than taken from the request. A caller that could name its own directory could point at a manifest
it wrote and approved somewhere else. */
#[cfg(all(feature = "host", target_os = "macos"))]
pub(super) fn caller_cwd(pid: libc::pid_t) -> Option<std::path::PathBuf> {
    let out = std::process::Command::new("lsof")
        .args(["-a", "-d", "cwd", "-Fn", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('n'))
        .map(std::path::PathBuf::from)
}

#[cfg(all(feature = "host", not(target_os = "macos")))]
pub(super) fn caller_cwd(pid: libc::pid_t) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// The chain for this process, for a read that opens the store here instead of in the broker
pub(crate) fn own_ancestry() -> String {
    libc::pid_t::try_from(std::process::id()).map_or_else(|_| "unknown".to_string(), ancestry)
}

/// Walk up the process tree, because the caller is `passbox` and the agent is somewhere above it
pub(crate) fn ancestry(pid: libc::pid_t) -> String {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..6 {
        let out = std::process::Command::new("ps")
            .args(["-o", "ppid=,comm=", "-p", &current.to_string()])
            .output();
        let Ok(out) = out else { break };
        let text = String::from_utf8_lossy(&out.stdout);
        let Some((parent, comm)) = text.trim().split_once(char::is_whitespace) else {
            break;
        };
        chain.push(comm.trim().to_string());
        match parent.trim().parse::<libc::pid_t>() {
            Ok(next) if next > 1 => current = next,
            _ => break,
        }
    }
    if chain.is_empty() {
        return "unknown".to_string();
    }
    chain.join(" < ")
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;

    #[test]
    fn a_remote_agent_cannot_forge_a_line_or_a_second_host() {
        let host = "server (someone@example.com, 100.64.0.7)";
        assert_eq!(remote_agent("timeout", host), format!("timeout on {host}"));
        let forged = remote_agent("job\nrelease all to\r\u{1b}[2K", host);
        assert!(!forged.chars().any(char::is_control), "{forged}");
        assert!(forged.ends_with(&format!(" on {host}")));
        let long = remote_agent(&"a".repeat(500), host);
        assert_eq!(long, format!("{} on {host}", "a".repeat(64)));
    }

    #[test]
    fn the_prompt_name_comes_from_the_first_real_ancestor() {
        assert_eq!(prompt_agent("passbox < zsh < claude < login"), "claude");
        assert_eq!(prompt_agent("passbox < -zsh < codex"), "codex");
        assert_eq!(prompt_agent("passbox < /bin/bash < node"), "node");
        // Only passbox and a shell means there is no better name than passbox
        assert_eq!(prompt_agent("passbox < zsh"), "passbox");
        assert_eq!(prompt_agent("unknown"), "passbox");
        // A wrapper only ran the command, so the name goes to whoever ran the wrapper
        assert_eq!(prompt_agent("passbox < timeout < zsh < claude"), "claude");
        assert_eq!(
            prompt_agent("passbox < /usr/bin/timeout < nohup < env < codex"),
            "codex"
        );
        assert_eq!(prompt_agent("passbox < timeout < zsh"), "passbox");
    }

    #[test]
    fn an_ssh_request_is_named_by_the_program_that_ran_ssh() {
        assert_eq!(ssh_requester("ssh < git < zsh < login"), "git");
        assert_eq!(ssh_requester("/usr/bin/ssh < -zsh < login"), "ssh");
        assert_eq!(ssh_requester("ssh"), "ssh");
        assert_eq!(ssh_requester("unknown"), "ssh");
        // A peer that speaks the protocol itself is named, never hidden behind its parent
        assert_eq!(ssh_requester("evil < node < zsh"), "evil");
    }
}
