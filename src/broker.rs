//! Decides who may open a secret, holds the approval windows, and writes the audit log.

use crate::crypto;
use crate::project::{self, Grant};
use crate::store::{self, DEFAULT_WINDOW_SECS, Mode, Store};
use age::x25519;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};

/// The store key leaves memory after this long with no traffic
const KEY_TTL_SECS: u64 = 300;
static LAST_SEEN: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    #[default]
    Get,
    List,
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub name: String,
    pub agent: String,
    #[serde(default)]
    pub op: Op,
}

/// Listing gets its own approval slot. A name cannot hold a NUL, so nothing collides with it.
const LIST_SLOT: &str = "\u{0}list";

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[derive(PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Prompt,
    Deny,
}

/// The one piece of logic that must not be wrong, so it stays pure and tested
pub fn decide(mode: Mode, window_secs: u64, approved_at: Option<u64>, now: u64) -> Decision {
    match mode {
        Mode::Open => Decision::Allow,
        Mode::Never => Decision::Deny,
        Mode::Always => Decision::Prompt,
        // An approval stamped in the future means the clock moved, so make them ask again
        Mode::Window => match approved_at {
            Some(at) if at <= now && now - at < window_secs => Decision::Allow,
            _ => Decision::Prompt,
        },
    }
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    at: u64,
    agent: &'a str,
    secret: &'a str,
    decision: &'a str,
    caller: &'a str,
}

struct Broker {
    store: Store,
    key: Option<x25519::Identity>,
    key_at: u64,
    approvals: HashMap<(String, String), u64>,
    grants: Vec<Grant>,
}

impl Broker {
    fn new(store: Store) -> Self {
        Broker {
            store,
            key: None,
            key_at: 0,
            approvals: HashMap::new(),
            grants: Vec::new(),
        }
    }

    /// A cached key past its life is the same as no key
    fn cached_key(&mut self) -> Option<&x25519::Identity> {
        if store::now().saturating_sub(self.key_at) >= KEY_TTL_SECS {
            self.key = None;
        }
        self.key.as_ref()
    }

    /// The Touch ID prompt is the approval, so a prompt and an unlock are the same act
    fn prompt(&mut self, agent: &str, secret: &str) -> Result<()> {
        self.ask(&format!("release the password for {secret} to {agent}"))
    }

    fn ask(&mut self, reason: &str) -> Result<()> {
        let key = self.store.unlock_with_se(reason)?;
        self.grants = project::load(&self.store, &key);
        self.key = Some(key);
        self.key_at = store::now();
        Ok(())
    }

    fn granted(&self, secret: &str, cwd: Option<&std::path::Path>) -> bool {
        let Some(manifest) = cwd.and_then(project::find) else {
            return false;
        };
        let now = store::now();
        self.grants.iter().any(|g| g.covers(&manifest, secret, now))
    }

    /// One prompt covers the whole manifest, which is the point of declaring it up front
    fn grant_manifest(&mut self, request: &Request, cwd: Option<&std::path::Path>) -> Result<bool> {
        let Some(manifest) = cwd.and_then(project::find) else {
            return Ok(false);
        };
        if !manifest.secrets.iter().any(|s| s == &request.name) {
            return Ok(false);
        }

        self.ask(&format!(
            "give {} access to {} secrets declared by {} for {} minutes",
            request.agent,
            manifest.secrets.len(),
            manifest.dir.display(),
            manifest.window_secs / 60
        ))?;

        self.grants.push(Grant {
            dir: manifest.dir.to_string_lossy().to_string(),
            hash: manifest.hash,
            secrets: manifest.secrets,
            until: store::now() + manifest.window_secs,
        });
        project::save(&self.store, &self.grants)?;
        Ok(true)
    }

    fn handle(
        &mut self,
        request: &Request,
        caller: &str,
        cwd: Option<&std::path::Path>,
    ) -> Result<String> {
        match request.op {
            Op::Get => self.handle_get(request, caller, cwd),
            Op::List => self.handle_list(request, caller),
        }
    }

    /// Names are inside the ciphertext, so listing needs the key and therefore a prompt.
    /// It gets its own window: riding a `get` approval would turn one secret into all of them.
    fn handle_list(&mut self, request: &Request, caller: &str) -> Result<String> {
        let slot = (request.agent.clone(), LIST_SLOT.to_string());
        let approved = self.approvals.get(&slot).copied();
        let reason = format!("list your secret names for {}", request.agent);

        let mut asked = false;
        if self.cached_key().is_none() {
            self.ask(&reason)?;
            asked = true;
        }
        if !asked
            && decide(Mode::Window, DEFAULT_WINDOW_SECS, approved, store::now()) == Decision::Prompt
        {
            self.ask(&reason)?;
            asked = true;
        }
        if asked {
            self.approvals.insert(slot, store::now());
        }

        let key = self.key.clone().expect("just unlocked");
        let outcome = if asked { "approved" } else { "within window" };
        self.audit(&key, &request.agent, "<list>", outcome, caller)?;
        Ok(self.store.names(&key)?.join("\n"))
    }

    fn handle_get(
        &mut self,
        request: &Request,
        caller: &str,
        cwd: Option<&std::path::Path>,
    ) -> Result<String> {
        let approved = self
            .approvals
            .get(&(request.agent.clone(), request.name.clone()))
            .copied();

        // Reading the policy needs the key, so a cold broker asks before it can decide
        let mut asked = false;
        if self.cached_key().is_none() {
            self.prompt(&request.agent, &request.name)?;
            asked = true;
        }
        let key = self.key.clone().expect("just unlocked");

        let found = self.store.find(&request.name, &key)?;
        let Some((_, secret)) = found else {
            self.audit(&key, &request.agent, &request.name, "unknown", caller)?;
            bail!("no secret named {}", request.name);
        };

        let outcome = match decide(secret.mode, secret.window_secs, approved, store::now()) {
            // A manifest never covers `never`, because Deny is not reached from here
            Decision::Deny => {
                self.audit(&key, &request.agent, &request.name, "denied", caller)?;
                bail!("{} is marked never, refusing", request.name);
            }
            Decision::Prompt if self.granted(&request.name, cwd) => "project grant",
            Decision::Prompt => {
                // The unlock a moment ago was itself the prompt, so do not ask twice for one read
                if !asked {
                    if self.grant_manifest(request, cwd)? {
                        "project grant"
                    } else {
                        self.prompt(&request.agent, &request.name)?;
                        self.stamp(request);
                        "approved"
                    }
                } else {
                    self.stamp(request);
                    "approved"
                }
            }
            Decision::Allow if asked => {
                self.stamp(request);
                "approved"
            }
            // The window runs from the prompt, so a busy agent still asks again when it expires
            Decision::Allow => "within window",
        };
        self.audit(&key, &request.agent, &request.name, outcome, caller)?;
        Ok(secret.value.clone())
    }

    fn stamp(&mut self, request: &Request) {
        self.approvals
            .insert((request.agent.clone(), request.name.clone()), store::now());
    }

    fn audit(
        &self,
        key: &x25519::Identity,
        agent: &str,
        secret: &str,
        decision: &str,
        caller: &str,
    ) -> Result<()> {
        let record = AuditRecord {
            at: store::now(),
            agent,
            secret,
            decision,
            caller,
        };
        let line = crypto::encrypt_line(&serde_json::to_vec(&record)?, &key.to_public())?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.store.audit_path())?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

pub fn serve(store: Store) -> Result<()> {
    let socket = store.socket_path();
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    store::private_dir(&store.dir)?;
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    LAST_SEEN.store(store::now(), Ordering::Relaxed);
    watchdog(socket.clone());

    let mut broker = Broker::new(store);
    for stream in listener.incoming() {
        let mut stream = stream?;
        LAST_SEEN.store(store::now(), Ordering::Relaxed);

        let pid = peer_pid(&stream);
        let caller = pid.map_or_else(|| "unknown".to_string(), ancestry);
        let cwd = pid.and_then(caller_cwd);
        let mut line = String::new();
        if BufReader::new(stream.try_clone()?)
            .read_line(&mut line)
            .is_err()
        {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => match broker.handle(&request, &caller, cwd.as_deref()) {
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
            },
            Err(e) => Response {
                ok: false,
                value: None,
                error: Some(format!("bad request: {e}")),
            },
        };
        let _ = writeln!(stream, "{}", serde_json::to_string(&response)?);
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
    }
    Ok(())
}

/// Exiting is how the key is dropped, which is blunter and surer than clearing it in place
fn watchdog(socket: std::path::PathBuf) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if store::now().saturating_sub(LAST_SEEN.load(Ordering::Relaxed)) >= KEY_TTL_SECS {
                let _ = std::fs::remove_file(&socket);
                std::process::exit(0);
            }
        }
    });
}

/// The peer pid comes from the kernel, so the caller cannot fake its own path
fn peer_pid(stream: &UnixStream) -> Option<libc::pid_t> {
    use std::os::unix::io::AsRawFd;
    // SOL_LOCAL and LOCAL_PEERPID, which libc does not expose on every release
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;

    let mut pid: libc::pid_t = 0;
    let mut len = size_of::<libc::pid_t>() as libc::socklen_t;
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

/* The project a grant belongs to is the caller's working directory, read from the kernel rather
than taken from the request. A caller that could name its own directory could point at a manifest
it wrote and approved somewhere else. */
fn caller_cwd(pid: libc::pid_t) -> Option<std::path::PathBuf> {
    let out = std::process::Command::new("lsof")
        .args(["-a", "-d", "cwd", "-Fn", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('n'))
        .map(std::path::PathBuf::from)
}

/// Walk up the process tree, because the caller is `passbox` and the agent is somewhere above it
fn ancestry(pid: libc::pid_t) -> String {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..6 {
        let out = std::process::Command::new("ps")
            .args(["-o", "ppid=,comm=", "-p", &current.to_string()])
            .output();
        let Ok(out) = out else { break };
        let text = String::from_utf8_lossy(&out.stdout);
        let Some((ppid, comm)) = text.trim().split_once(char::is_whitespace) else {
            break;
        };
        chain.push(comm.trim().to_string());
        match ppid.trim().parse::<libc::pid_t>() {
            Ok(next) if next > 1 => current = next,
            _ => break,
        }
    }
    if chain.is_empty() {
        return "unknown".to_string();
    }
    chain.join(" < ")
}

pub fn request(store: &Store, name: &str, agent: &str) -> Result<String> {
    ask_broker(
        store,
        Request {
            name: name.to_string(),
            agent: agent.to_string(),
            op: Op::Get,
        },
    )
}

/// Names come back one per line, so the broker keeps the key and the caller never sees it.
pub fn list(store: &Store, agent: &str) -> Result<Vec<String>> {
    let names = ask_broker(
        store,
        Request {
            name: String::new(),
            agent: agent.to_string(),
            op: Op::List,
        },
    )?;
    Ok(names.lines().map(str::to_string).collect())
}

/// Ask a running broker, starting one if the socket is dead.
fn ask_broker(store: &Store, request: Request) -> Result<String> {
    let socket = store.socket_path();
    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(_) => {
            spawn(store)?;
            UnixStream::connect(&socket).context("the broker did not come up")?
        }
    };

    writeln!(stream, "{}", serde_json::to_string(&request)?)?;

    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let response: Response = serde_json::from_str(&line).context("broker sent nonsense")?;
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

fn spawn(store: &Store) -> Result<()> {
    std::process::Command::new(std::env::current_exe()?)
        .arg("broker")
        .env("PASSBOX_DIR", &store.dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
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

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: u64 = 300;

    #[test]
    fn open_never_asks() {
        assert_eq!(decide(Mode::Open, WINDOW, None, 1000), Decision::Allow);
    }

    #[test]
    fn never_is_always_refused() {
        assert_eq!(decide(Mode::Never, WINDOW, None, 1000), Decision::Deny);
        assert_eq!(decide(Mode::Never, WINDOW, Some(999), 1000), Decision::Deny);
    }

    #[test]
    fn always_asks_even_inside_a_window() {
        assert_eq!(
            decide(Mode::Always, WINDOW, Some(999), 1000),
            Decision::Prompt
        );
    }

    #[test]
    fn a_window_holds_until_it_expires() {
        assert_eq!(decide(Mode::Window, WINDOW, None, 1000), Decision::Prompt);
        assert_eq!(
            decide(Mode::Window, WINDOW, Some(1000), 1000),
            Decision::Allow
        );
        assert_eq!(
            decide(Mode::Window, WINDOW, Some(1000), 1299),
            Decision::Allow
        );
        assert_eq!(
            decide(Mode::Window, WINDOW, Some(1000), 1300),
            Decision::Prompt
        );
        assert_eq!(
            decide(Mode::Window, WINDOW, Some(1000), 9999),
            Decision::Prompt
        );
    }

    /// Listing rides its own slot, so a `get` approval cannot be spent on enumerating everything
    #[test]
    fn the_list_slot_cannot_hold_a_real_name() {
        assert!(LIST_SLOT.contains('\u{0}'));
        assert_eq!(Op::default(), Op::Get);
    }

    #[test]
    fn a_zero_window_asks_every_time() {
        assert_eq!(decide(Mode::Window, 0, Some(1000), 1000), Decision::Prompt);
    }

    #[test]
    fn an_approval_from_the_future_is_not_trusted() {
        assert_eq!(
            decide(Mode::Window, WINDOW, Some(2000), 1000),
            Decision::Prompt
        );
        assert_eq!(
            decide(Mode::Never, WINDOW, Some(2000), 1000),
            Decision::Deny
        );
    }
}
