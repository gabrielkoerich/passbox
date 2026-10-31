//! The broker process: its sockets, one thread per connection, and the watchdog that ends it.

use super::audit::{Entry, append_audit_to};
use super::caller::{ancestry, caller_cwd, peer_pid, prompt_agent, remote_agent, ssh_requester};
use super::tokens::{Tokens, mint_child, token_value};
use super::{Broker, KEY_TTL_SECS, MAX_GRANT_SECS, Op, Request, Response, TAILNET_PORT};
use crate::store::{self, Store};
use crate::{ssh, tailnet};
use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};

static LAST_SEEN: AtomicU64 = AtomicU64::new(0);

/// Connections being answered, token reads included, so an upgrade restart never cuts one off
static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Where a request came from, which names its agent and scopes its plugin windows
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// This Mac's socket, where every caller shares one window scope
    Local,
    /// Another machine through `tailscale serve`, named by whois
    Tailnet,
}

/// The PROXY header is how the broker learns which host connected, so the listener requires it
const SERVE: &str = "tailscale serve --bg --proxy-protocol 1 --tcp 8787 tcp://127.0.0.1:8787";

/// One loop per connection, since ssh sends several requests on one, and only signing takes the lock
fn serve_ssh(listener: &UnixListener, shared: &std::sync::Arc<Shared>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let shared = std::sync::Arc::clone(shared);
        std::thread::spawn(move || {
            let pid = peer_pid(&stream);
            let mut connection = ssh::Connection::default();
            while let Ok(Some(request)) = ssh::read_message(&mut stream) {
                IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
                let offered = ssh::offered(&shared.store);
                let reply = ssh::answer(&request, &offered, &mut connection, |key, data, host| {
                    let caller = pid.map_or_else(|| "unknown".to_string(), ancestry);
                    let agent = ssh_requester(&caller);
                    shared
                        .broker
                        .lock()
                        .expect("broker")
                        .sign(key, data, host, &agent, &caller)
                });
                LAST_SEEN.store(store::now(), Ordering::Relaxed);
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                if ssh::write_message(&mut stream, &reply).is_err() {
                    break;
                }
            }
        });
    }
}

/// What every connection thread shares. The token map is reachable without the broker's lock
pub(super) struct Shared {
    broker: std::sync::Mutex<Broker>,
    pub(super) tokens: Tokens,
    pub(super) store: Store,
}

fn reply<S: std::io::Read + Write>(
    shared: &Shared,
    stream: &mut S,
    caller: &str,
    cwd: Option<&std::path::Path>,
    origin: Origin,
) -> Result<()> {
    let mut line = String::new();
    let mut reader = BufReader::new(&mut *stream);
    if let Err(e) = reader.read_line(&mut line) {
        eprintln!("could not read the request: {e}");
        return Ok(());
    }
    eprintln!("{} read {} bytes of request", clock(), line.len());
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(mut request) => {
            // An unset agent is named from the caller's own process chain, so the prompt says who
            if request.agent.is_empty() {
                request.agent = match origin {
                    Origin::Local => prompt_agent(caller),
                    Origin::Tailnet => "passbox".to_string(),
                };
            }

            if origin == Origin::Tailnet {
                request.agent = remote_agent(&request.agent, caller);
            }
            // A token read or a child grant needs no key and no prompt, so it never waits behind one
            let by_token = (request.op == Op::Get && !request.token.is_empty())
                .then(|| token_value(&shared.tokens, &shared.store, &request.token, &request.name))
                .flatten();
            let child = (request.op == Op::Grant && !request.token.is_empty())
                .then(|| mint_child(shared, &request, caller))
                .flatten();
            let answer = match (by_token, child) {
                (Some((value, grant)), _) => shared
                    .store
                    .recipient()
                    .and_then(|to| {
                        append_audit_to(
                            &shared.store,
                            &to,
                            &Entry {
                                agent: &request.agent,
                                secret: &request.name,
                                decision: "by token",
                                caller,
                                grant: &grant,
                                ..Entry::default()
                            },
                        )
                    })
                    .map(|()| value),
                (None, Some(answer)) => answer,
                (None, None) => shared
                    .broker
                    .lock()
                    .expect("broker")
                    .handle(&request, caller, cwd, origin),
            };
            match answer {
                Ok(value) => Response {
                    ok: true,
                    value: Some(value),
                    error: None,
                },
                Err(e) => Response {
                    ok: false,
                    value: None,
                    error: Some(format!("{e:#}")),
                },
            }
        }
        Err(e) => Response {
            ok: false,
            value: None,
            error: Some(format!("bad request: {e}")),
        },
    };
    writeln!(stream, "{}", serde_json::to_string(&response)?)?;
    Ok(())
}

/* Another machine asks here, through `tailscale serve` on loopback. The PROXY header carries the
node's address and `tailscale whois` names it. Unlike the agent string a caller sends, the
control plane authenticated that name, so it is the one caller identity that is not self declared */
fn serve_tailnet(listener: &std::net::TcpListener, shared: &std::sync::Arc<Shared>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
        let shared = std::sync::Arc::clone(shared);
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let Some(peer) = tailnet::proxied_peer(&mut stream) else {
                eprintln!("tailnet request refused: no PROXY header, see `tailscale serve` below");
                let refusal = Response {
                    ok: false,
                    value: None,
                    error: Some(format!(
                        "the broker cannot tell which host asked, run on the Mac:\n  {SERVE}"
                    )),
                };
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::to_string(&refusal).unwrap_or_default()
                );
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                return;
            };
            let caller =
                tailnet::whois(peer).unwrap_or_else(|| format!("an unknown tailnet host ({peer})"));
            eprintln!("tailnet request from {caller}");
            if let Err(e) = reply(&shared, &mut stream, &caller, None, Origin::Tailnet) {
                eprintln!("tailnet request failed: {e:#}");
            }
            LAST_SEEN.store(store::now(), Ordering::Relaxed);
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/* The broker holds the store key for minutes at a time, so a debugger attaching as the same user
could read it out. PT_DENY_ATTACH refuses that attach, and a zero core limit stops a crash from
writing the key to disk. Root can still get past both. */
#[cfg(all(feature = "host", target_os = "macos"))]
fn harden() {
    // SAFETY: PT_DENY_ATTACH takes no address or data, it only flags this process
    unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the rlimit it is given
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const none) };
}

/// A socket only this user can reach, replacing one a previous broker left behind
fn bind_private(path: &std::path::Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(listener)
}

pub(crate) fn serve(store: Store) -> Result<()> {
    #[cfg(target_os = "macos")]
    harden();
    let socket = store.socket_path();
    store::private_dir(&store.dir)?;
    let listener = bind_private(&socket)?;
    let agent = bind_private(&store.ssh_agent_path())?;

    LAST_SEEN.store(store::now(), Ordering::Relaxed);
    let tokens = Tokens::default();
    let shared = std::sync::Arc::new(Shared {
        broker: std::sync::Mutex::new(Broker::new(store.clone(), std::sync::Arc::clone(&tokens))),
        tokens,
        store,
    });
    watchdog(socket, std::sync::Arc::clone(&shared));
    let for_agent = std::sync::Arc::clone(&shared);
    std::thread::spawn(move || serve_ssh(&agent, &for_agent));

    /* Loopback, exposed to the tailnet by `tailscale serve`, rather than bound to the tailnet
    address directly. Measured 2026-09-27: macOS runs Tailscale as a network extension, and a
    socket bound to the 100.x address accepts a connection and then fails the first read with
    ENOTCONN. `serve` forwards to loopback and works. A plain python server fails the same way,
    so this is the platform, not us.

    Loopback has none of the unix socket's 0600 protection, so any local user can reach this
    port. That is the cost of the only inbound path macOS actually delivers. */
    if tailnet::address().is_some() {
        match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, TAILNET_PORT)) {
            Ok(tcp) => {
                eprintln!("listening on 127.0.0.1:{TAILNET_PORT}; expose it with\n  {SERVE}");
                let shared = std::sync::Arc::clone(&shared);
                std::thread::spawn(move || serve_tailnet(&tcp, &shared));
            }
            Err(e) => eprintln!("not listening for tailnet peers: {e}"),
        }
    }

    // A daemon that prints nothing looks like a hang, so say plainly that it is working
    eprintln!(
        "{} broker ready, waiting for requests. Ctrl+C to stop",
        clock()
    );

    // A thread per connection, so a prompt left open does not stop the next request being read.
    // Prompts still take the broker's lock, so only one is ever on screen
    for stream in listener.incoming() {
        let mut stream = stream?;
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
        let shared = std::sync::Arc::clone(&shared);
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let pid = peer_pid(&stream);
            let caller = pid.map_or_else(|| "unknown".to_string(), ancestry);
            let cwd = pid.and_then(caller_cwd);
            let _ = reply(&shared, &mut stream, &caller, cwd.as_deref(), Origin::Local);
            LAST_SEEN.store(store::now(), Ordering::Relaxed);
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// The file a path names, followed through symlinks, so a repointed `bin/passbox` reads as a change
fn file_id(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/* The path this broker was started as, and the file it is running from. launchd starts
`/opt/homebrew/bin/passbox`, which an upgrade repoints, and the cleanup after it deletes the old
file. Either way the next start would run a different file, which is the signal to restart. */
struct Binary {
    launch: std::path::PathBuf,
    running: Option<(u64, u64)>,
}

impl Binary {
    fn current() -> Self {
        let exe = std::env::current_exe().ok();
        let launch = std::env::args_os()
            .next()
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| exe.clone())
            .unwrap_or_default();
        let running = exe
            .and_then(|e| std::fs::canonicalize(e).ok())
            .and_then(|e| file_id(&e));
        Binary { launch, running }
    }

    fn replaced(&self) -> bool {
        self.running.is_some() && file_id(&self.launch) != self.running
    }
}

/// Drops the key when idle. Exits only for an upgrade or a deleted store, since ssh needs the socket
fn watchdog(socket: std::path::PathBuf, shared: std::sync::Arc<Shared>) {
    let binary = Binary::current();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            // A broker whose socket is gone, with its store deleted, can never be reached again
            if !socket.exists() {
                eprintln!("{} socket is gone, exiting", clock());
                std::process::exit(0);
            }
            /* After an upgrade the old file may already be deleted, and macOS kills a process
            whose code it can no longer page in. Exiting between requests lets launchd start the
            new one. Live grants end with it, since they are held only in memory */
            if binary.replaced()
                && IN_FLIGHT.load(Ordering::SeqCst) == 0
                && let Ok(_quiet) = shared.broker.try_lock()
            {
                eprintln!(
                    "{} {} was replaced, exiting so the new version starts",
                    clock(),
                    binary.launch.display()
                );
                let _ = std::fs::remove_file(&socket);
                std::process::exit(0);
            }
            let idle = store::now().saturating_sub(LAST_SEEN.load(Ordering::Relaxed));
            // A held lock is a request in flight, often waiting on a prompt, so try again later
            let mut broker = match shared.broker.try_lock() {
                Ok(broker) => broker,
                Err(std::sync::TryLockError::WouldBlock) => continue,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    eprintln!("{} a request panicked, exiting", clock());
                    let _ = std::fs::remove_file(&socket);
                    std::process::exit(1);
                }
            };
            broker.sweep(idle);
        }
    });
}

/// Local time for the broker log, which launchd writes without one
pub(super) fn clock() -> String {
    let t = libc::time_t::try_from(store::now()).unwrap_or_default();
    // SAFETY: tm holds plain integers and a nullable pointer, so all zero is a valid value
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r reads t and writes only the tm it is given
    unsafe { libc::localtime_r(&raw const t, &raw mut tm) };
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

impl Broker {
    // Called by the watchdog. Tokens hold their values only here, so the broker keeps running and
    // only the key goes, which also keeps `SSH_AUTH_SOCK` pointing at a live socket
    fn sweep(&mut self, idle: u64) {
        if idle < KEY_TTL_SECS {
            return;
        }
        let now = store::now();
        self.tokens
            .lock()
            .expect("tokens")
            .retain(|_, g| now < g.expires);
        self.windows
            .retain(|_, w| now < w.opened.saturating_add(MAX_GRANT_SECS));
        self.ssh_windows
            .retain(|_, w| now < w.opened.saturating_add(MAX_GRANT_SECS));
        if self.key.take().is_some() {
            eprintln!("{} idle {idle}s, dropped the key", clock());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::tokens::TokenGrant;
    use age::x25519;
    use std::collections::HashMap;

    #[test]
    fn a_repointed_or_deleted_binary_reads_as_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join("passbox-old");
        let new = tmp.path().join("passbox-new");
        let launch = tmp.path().join("passbox");
        std::fs::write(&old, "old").unwrap();
        std::fs::write(&new, "new").unwrap();
        std::os::unix::fs::symlink(&old, &launch).unwrap();
        let binary = Binary {
            launch: launch.clone(),
            running: file_id(&old),
        };
        assert!(!binary.replaced());

        // What `brew upgrade` does to bin/passbox
        std::fs::remove_file(&launch).unwrap();
        std::os::unix::fs::symlink(&new, &launch).unwrap();
        assert!(binary.replaced());

        // And the cleanup, with the broker started from the file itself
        let direct = Binary {
            launch: old.clone(),
            running: file_id(&old),
        };
        assert!(!direct.replaced());
        std::fs::remove_file(&old).unwrap();
        assert!(direct.replaced());
    }

    #[test]
    fn an_idle_broker_drops_the_key_and_keeps_live_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let mut broker = Broker::new(
            Store {
                dir: tmp.path().to_path_buf(),
            },
            Tokens::default(),
        );
        broker.key = Some(Box::new(x25519::Identity::generate()));
        broker.tokens.lock().unwrap().insert(
            "t".into(),
            TokenGrant {
                values: HashMap::from([("a/b".into(), "v".into())]),
                stamps: HashMap::new(),
                expires: store::now() + 43_200,
                grant: "g".into(),
            },
        );

        broker.sweep(KEY_TTL_SECS - 1);
        assert!(broker.key.is_some());

        broker.sweep(KEY_TTL_SECS);
        assert!(broker.key.is_none());
        assert_eq!(
            broker.value_for_token("t", "a/b"),
            Some(("v".into(), "g".into()))
        );

        broker.tokens.lock().unwrap().get_mut("t").unwrap().expires = store::now();
        broker.sweep(KEY_TTL_SECS);
        assert!(broker.tokens.lock().unwrap().is_empty());
    }
}
