//! The client side: one request to the broker on this Mac, or to a host over the tailnet.

use super::{Op, Request, Response, TAILNET_PORT};
use crate::store::Store;
use anyhow::{Context, Result, anyhow, bail};
#[cfg(feature = "host")]
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

pub(crate) fn request(store: &Store, name: &str, agent: &str) -> Result<String> {
    request_token(store, name, agent, crate::held_token().unwrap_or_default())
}

/// A read carrying a token the caller already holds, such as the one exec mints for its batch
pub(crate) fn request_token(store: &Store, name: &str, agent: &str, token: &str) -> Result<String> {
    ask_broker(
        store,
        &Request {
            name: name.to_string(),
            agent: agent.to_string(),
            op: Op::Get,
            token: token.to_string(),
            ttl: 0,
            names: Vec::new(),
            action: String::new(),
            params: Vec::new(),
            run: false,
        },
    )
}

/// Names come back one per line, so the broker keeps the key and the caller never sees it.
pub(crate) fn list(store: &Store, agent: &str) -> Result<Vec<String>> {
    let names = ask_broker(
        store,
        &Request {
            name: String::new(),
            agent: agent.to_string(),
            op: Op::List,
            token: String::new(),
            ttl: 0,
            names: Vec::new(),
            action: String::new(),
            params: Vec::new(),
            run: false,
        },
    )?;
    Ok(names.lines().map(str::to_string).collect())
}

/// Approve once and get a token back, with the names it covers listed after it
pub(crate) fn grant(store: &Store, names: &[String], agent: &str, ttl: u64) -> Result<String> {
    ask_broker(
        store,
        &Request {
            name: String::new(),
            agent: agent.to_string(),
            op: Op::Grant,
            token: crate::held_token().unwrap_or_default().to_string(),
            ttl,
            names: names.to_vec(),
            action: String::new(),
            params: Vec::new(),
            run: false,
        },
    )
}

/// Ask the broker to approve one plugin call. The caller runs the command built from these
/// `params` once this returns ok
#[cfg(feature = "host")]
pub(crate) fn plugin_approve(
    store: &Store,
    name: &str,
    action: &str,
    params: &HashMap<String, String>,
    agent: &str,
) -> Result<()> {
    ask_broker(
        store,
        &Request {
            name: name.to_string(),
            agent: agent.to_string(),
            op: Op::Plugin,
            token: String::new(),
            ttl: 0,
            names: Vec::new(),
            action: action.to_string(),
            params: params.clone().into_iter().collect(),
            run: false,
        },
    )
    .map(|_| ())
}

/// Ask the broker to run a plugin tool and return its output, for a client with no local app or a
/// plugin with `stdin`, whose secret stays in the broker
pub(crate) fn plugin_run_remote(
    store: &Store,
    name: &str,
    action: &str,
    params: &[(String, String)],
    agent: &str,
) -> Result<String> {
    ask_broker(
        store,
        &Request {
            name: name.to_string(),
            agent: agent.to_string(),
            op: Op::Plugin,
            token: String::new(),
            ttl: 0,
            names: Vec::new(),
            action: action.to_string(),
            params: params.to_vec(),
            run: true,
        },
    )
}

/// Ask a running broker, starting one if the socket is dead.
fn ask_broker(store: &Store, request: &Request) -> Result<String> {
    /* A configured host means this machine has no store of its own worth unlocking, so the
    request goes over the tailnet to one that has. The reply is the value, and the finger that
    released it was somewhere else. */
    if let Some(host) = store.host() {
        let target = if host.contains(':') {
            host
        } else {
            format!("{host}:{TAILNET_PORT}")
        };
        let mut stream = std::net::TcpStream::connect(&target)
            .with_context(|| format!("no passbox host at {target}"))?;
        writeln!(stream, "{}", serde_json::to_string(request)?)?;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        return unwrap_response(&line);
    }

    let socket = store.socket_path();
    #[cfg(feature = "host")]
    let mut stream = if let Ok(stream) = UnixStream::connect(&socket) {
        stream
    } else {
        spawn(store)?;
        UnixStream::connect(&socket).context("the broker did not come up")?
    };
    #[cfg(not(feature = "host"))]
    let Ok(mut stream) = UnixStream::connect(&socket) else {
        bail!(
            "no broker at {}, and a client cannot start one",
            socket.display()
        );
    };

    writeln!(stream, "{}", serde_json::to_string(request)?)?;

    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    unwrap_response(&line)
}

/// The same reply shape whether it arrived over a socket or the tailnet
fn unwrap_response(line: &str) -> Result<String> {
    let response: Response = serde_json::from_str(line).context("broker sent nonsense")?;
    if !response.ok {
        bail!(
            "{}",
            response.error.unwrap_or_else(|| "refused".to_string())
        );
    }
    response
        .value
        .ok_or_else(|| anyhow!("broker sent no value"))
}

#[cfg(feature = "host")]
fn spawn(store: &Store) -> Result<()> {
    std::process::Command::new(std::env::current_exe()?)
        .arg("broker")
        .env("PASSBOX_DIR", &store.dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        // It outlives the caller, so it must not hold the caller's stderr or write into its transcript
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("could not start the broker")?;

    // The socket appears a moment after the fork, so give it a few tries rather than one
    for _ in 0..50 {
        if store.socket_path().exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    bail!("the broker never opened its socket")
}
