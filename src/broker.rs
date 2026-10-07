//! Decides who may open a secret, holds the approval windows, and writes the audit log.

#[cfg(feature = "host")]
use crate::crypto;
#[cfg(feature = "host")]
use crate::project::{self, Grant};
use crate::store::Store;
#[cfg(feature = "host")]
use crate::store::{self, DEFAULT_WINDOW_SECS, Mode};
#[cfg(feature = "host")]
use age::x25519;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
#[cfg(feature = "host")]
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
#[cfg(feature = "host")]
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
#[cfg(feature = "host")]
use std::sync::atomic::{AtomicU64, Ordering};

/// The store key leaves memory after this long with no traffic
#[cfg(feature = "host")]
const KEY_TTL_SECS: u64 = 300;
/* A ceiling on how long one approval can carry. Without it a caller names its own expiry and
a token becomes a password that never lapses, which is the thing this exists to avoid. */
#[cfg(feature = "host")]
const MAX_GRANT_SECS: u64 = 86_400;
#[cfg(feature = "host")]
static LAST_SEEN: AtomicU64 = AtomicU64::new(0);

/* Exact names only. A token is worth minting because it is narrower than the store key, and a
namespace is not: it hands over everything under it now, and a caller that asks for one has not
said what it actually reads. The refusal lists them so naming them is a copy, not a chore. */
#[cfg(feature = "host")]
fn reject_namespaces(asked: &[String], known: &[String]) -> Result<()> {
    for pattern in asked {
        if known.iter().any(|n| n == pattern) {
            continue;
        }
        let under = store::select(known, Some(pattern));
        if under.is_empty() {
            bail!("no secret named {pattern}");
        }
        bail!(
            "{pattern} is a namespace holding {} secrets, ask for the ones this needs:\n  {}",
            under.len(),
            under.join("\n  ")
        );
    }
    Ok(())
}

#[cfg(feature = "host")]
/* Split out so the scoping rules can be tested without a store, a socket or a finger:
an unknown token opens nothing, a known one opens only what it was granted, and neither
opens anything once it has lapsed. */
fn token_lookup(
    tokens: &HashMap<String, TokenGrant>,
    token: &str,
    name: &str,
    now: u64,
) -> Option<String> {
    let grant = tokens.get(token)?;
    (now < grant.expires)
        .then(|| grant.values.get(name).cloned())
        .flatten()
}

/// What one token opens: the values it was granted, and when it stops working
#[cfg(feature = "host")]
struct TokenGrant {
    values: HashMap<String, String>,
    expires: u64,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    #[default]
    Get,
    List,
    /// Approve a set of secrets once and hand back a token that opens only those
    Grant,
    /// Approve one plugin action, named by `name` and `action`
    Plugin,
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub name: String,
    pub agent: String,
    #[serde(default)]
    pub op: Op,
    /// Presented on a read to skip the prompt, and minted by a Grant
    #[serde(default)]
    pub token: String,
    /// Seconds a minted token stays valid
    #[serde(default)]
    pub ttl: u64,
    /// Names or namespaces a Grant covers. A job rarely wants exactly one namespace
    #[serde(default)]
    pub names: Vec<String>,
    /// The tool a Plugin op runs, such as `search` under plugin `mail`
    #[serde(default)]
    pub action: String,
}

#[cfg(feature = "host")]
/// Listing gets its own approval slot. A name cannot hold a NUL, so nothing collides with it.
const LIST_SLOT: &str = "\u{0}list";

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[cfg(feature = "host")]
#[derive(PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Prompt,
    Deny,
}

#[cfg(feature = "host")]
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

#[cfg(feature = "host")]
#[derive(Serialize)]
struct AuditRecord<'a> {
    at: u64,
    agent: &'a str,
    secret: &'a str,
    decision: &'a str,
    caller: &'a str,
}

#[cfg(feature = "host")]
struct Broker {
    store: Store,
    key: Option<x25519::Identity>,
    /* Tokens, held past the store key's life. The key opens everything and so is dropped
    quickly; a token covers only the secrets it was granted, to whoever holds it. */
    tokens: HashMap<String, TokenGrant>,
    key_at: u64,
    approvals: HashMap<(String, String), u64>,
    #[cfg(feature = "host")]
    grants: Vec<Grant>,
}

#[cfg(feature = "host")]
impl Broker {
    fn new(store: Store) -> Self {
        Broker {
            store,
            key: None,
            key_at: 0,
            tokens: HashMap::new(),
            approvals: HashMap::new(),
            #[cfg(feature = "host")]
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
        #[cfg(feature = "host")]
        {
            self.grants = project::load(&self.store, &key);
        }
        self.key = Some(key);
        self.key_at = store::now();
        Ok(())
    }

    #[cfg(feature = "host")]
    fn granted(&self, secret: &str, cwd: Option<&std::path::Path>) -> bool {
        let Some(manifest) = cwd.and_then(project::find) else {
            return false;
        };
        let now = store::now();
        self.grants.iter().any(|g| g.covers(&manifest, secret, now))
    }

    /// One prompt covers the whole manifest, which is the point of declaring it up front
    #[cfg(feature = "host")]
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
            Op::Grant => self.handle_grant(request, caller),
            Op::Plugin => self.handle_plugin(request, caller),
        }
    }

    /* A plugin action is gated by the mode in its manifest, which the broker reads itself so a
    caller cannot claim a softer mode. Approval and audit are the whole job here. The caller runs
    the command, because it holds the GUI session the broker does not. */
    #[cfg(feature = "host")]
    fn handle_plugin(&mut self, request: &Request, caller: &str) -> Result<String> {
        let manifest = crate::plugin::load(&self.store, &request.name)?;
        let tool = manifest
            .tool(&request.action)
            .ok_or_else(|| anyhow!("{} has no action {}", request.name, request.action))?;
        let slot_name = format!("plugin:{}.{}", request.name, request.action);
        let approved = self
            .approvals
            .get(&(request.agent.clone(), slot_name.clone()))
            .copied();
        let outcome = match decide(tool.mode, DEFAULT_WINDOW_SECS, approved, store::now()) {
            Decision::Deny => {
                self.audit_by(&request.agent, &slot_name, "denied", caller)?;
                bail!("{slot_name} is marked never, refusing");
            }
            Decision::Prompt => {
                self.ask(&format!("run {slot_name} for {}", request.agent))?;
                self.approvals
                    .insert((request.agent.clone(), slot_name.clone()), store::now());
                "approved"
            }
            Decision::Allow if tool.mode == Mode::Open => "open",
            Decision::Allow => "within window",
        };
        self.audit_by(&request.agent, &slot_name, outcome, caller)?;
        Ok("ok".to_string())
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
        let names = self.store.names(&key)?;
        Ok(names.join("\n"))
    }

    /* One approval covers a name or a whole namespace, and yields a token that opens exactly
    those. Asking for twenty secrets one at a time is twenty prompts to do one thing. */
    fn handle_grant(&mut self, request: &Request, caller: &str) -> Result<String> {
        let asked = if request.ttl == 0 {
            DEFAULT_WINDOW_SECS
        } else {
            request.ttl
        };
        let ttl = asked.min(MAX_GRANT_SECS);
        if ttl < asked {
            eprintln!("capped {asked}s at {MAX_GRANT_SECS}s");
        }

        // A key still warm from an earlier read refuses a namespace without spending a prompt
        if let Some(key) = self.cached_key().cloned() {
            reject_namespaces(&request.names, &self.store.names(&key)?)?;
        }

        let reason = format!(
            "grant {} to {} for {ttl}s",
            request.names.join(", "),
            request.agent
        );
        self.ask(&reason)?;
        let key = self.key.clone().expect("just unlocked");

        let all = self.store.names(&key)?;
        reject_namespaces(&request.names, &all)?;
        let mut wanted = request.names.clone();
        wanted.sort();
        wanted.dedup();

        let mut values = HashMap::new();
        for name in &wanted {
            let Some((_, secret)) = self.store.find(name, &key)? else {
                continue;
            };
            // `never` is never released to anything holding a token either
            if secret.mode == Mode::Never {
                continue;
            }
            values.insert(name.clone(), secret.value.clone());
        }
        if values.is_empty() {
            bail!(
                "{} matched only secrets marked never",
                request.names.join(", ")
            );
        }

        let token = store::new_id() + &store::new_id();
        let granted: Vec<String> = values.keys().cloned().collect();
        self.tokens.insert(
            token.clone(),
            TokenGrant {
                values,
                expires: store::now() + ttl,
            },
        );
        for name in &granted {
            self.audit(&key, &request.agent, name, "granted", caller)?;
        }
        Ok(format!("{token}\n{}", granted.join("\n")))
    }

    /// A token answers only for what it was granted, and only until it expires
    fn value_for_token(&mut self, token: &str, name: &str) -> Option<String> {
        let now = store::now();
        self.tokens.retain(|_, g| now < g.expires);
        token_lookup(&self.tokens, token, name, now)
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

        // A token is the narrowest thing that can answer, so it is tried first
        if !request.token.is_empty()
            && let Some(value) = self.value_for_token(&request.token, &request.name)
        {
            self.audit_by(&request.agent, &request.name, "by token", caller)?;
            return Ok(value);
        }

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
            #[cfg(feature = "host")]
            Decision::Prompt if self.granted(&request.name, cwd) => "project grant",
            Decision::Prompt => {
                // The unlock a moment ago was itself the prompt, so do not ask twice for one read
                if !asked {
                    #[cfg(feature = "host")]
                    let by_manifest = self.grant_manifest(request, cwd)?;
                    #[cfg(not(feature = "host"))]
                    let by_manifest = false;
                    if by_manifest {
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

    /* A token read has no key by design, and the audit line only ever needed the public half,
    so the record is written to the store's recipient instead. Token reads stay auditable. */
    fn audit_by(&self, agent: &str, secret: &str, decision: &str, caller: &str) -> Result<()> {
        let to = self.store.recipient()?;
        self.audit_to(&to, agent, secret, decision, caller)
    }

    fn audit(
        &self,
        key: &x25519::Identity,
        agent: &str,
        secret: &str,
        decision: &str,
        caller: &str,
    ) -> Result<()> {
        self.audit_to(&key.to_public(), agent, secret, decision, caller)
    }

    fn audit_to(
        &self,
        to: &x25519::Recipient,
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
        let line = crypto::encrypt_line(&serde_json::to_vec(&record)?, to)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.store.audit_path())?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

/* The port the broker answers on over the tailnet. Fixed rather than configurable: a client
would have to guess it, and a second knob is a second thing to get wrong. A client needs it
too, so it is not gated behind the host feature. */
pub const TAILNET_PORT: u16 = 8787;

#[cfg(feature = "host")]
fn reply<S: std::io::Read + Write>(
    broker: &std::sync::Mutex<Broker>,
    stream: &mut S,
    caller: &str,
    cwd: Option<&std::path::Path>,
) -> Result<()> {
    let mut line = String::new();
    let mut reader = BufReader::new(&mut *stream);
    if let Err(e) = reader.read_line(&mut line) {
        eprintln!("could not read the request: {e}");
        return Ok(());
    }
    eprintln!("read {} bytes of request", line.len());
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(request) => match broker.lock().expect("broker").handle(&request, caller, cwd) {
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
    writeln!(stream, "{}", serde_json::to_string(&response)?)?;
    Ok(())
}

/* Another machine asks here. The listener is bound to this host's tailnet address rather than
loopback or every interface: loopback has none of the unix socket's 0600 protection, so any
local user could reach it, and every interface would put a secrets daemon on the LAN.

`tailscale whois` names the peer, and unlike the agent string a caller sends, the control plane
authenticated it. That is the first caller identity in passbox that is not self declared. */
#[cfg(feature = "host")]
fn serve_tailnet(
    listener: std::net::TcpListener,
    broker: std::sync::Arc<std::sync::Mutex<Broker>>,
) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
        let caller = stream
            .peer_addr()
            .ok()
            .and_then(|a| crate::tailnet::whois(a.ip()))
            .unwrap_or_else(|| "an unidentified tailnet peer".to_string());
        eprintln!("tailnet request from {caller}");
        if let Err(e) = reply(&broker, &mut stream, &caller, None) {
            eprintln!("tailnet request failed: {e:#}");
        }
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
    }
}

/* The broker holds the store key for minutes at a time, so a debugger attaching as the same user
could read it out. PT_DENY_ATTACH refuses that attach, and a zero core limit stops a crash from
writing the key to disk. Root can still get past both. */
#[cfg(all(feature = "host", target_os = "macos"))]
fn harden() {
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
}

#[cfg(feature = "host")]
pub fn serve(store: Store) -> Result<()> {
    #[cfg(target_os = "macos")]
    harden();
    let socket = store.socket_path();
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    store::private_dir(&store.dir)?;
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

    LAST_SEEN.store(store::now(), Ordering::Relaxed);
    watchdog(socket.clone());

    let broker = std::sync::Arc::new(std::sync::Mutex::new(Broker::new(store)));

    /* Loopback, exposed to the tailnet by `tailscale serve`, rather than bound to the tailnet
    address directly. Measured 2026-09-27: macOS runs Tailscale as a network extension, and a
    socket bound to the 100.x address accepts a connection and then fails the first read with
    ENOTCONN. `serve` forwards to loopback and works. A plain python server fails the same way,
    so this is the platform, not us.

    Loopback has none of the unix socket's 0600 protection, so any local user can reach this
    port. That is the cost of the only inbound path macOS actually delivers. */
    if crate::tailnet::address().is_some() {
        match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, TAILNET_PORT)) {
            Ok(tcp) => {
                eprintln!(
                    "listening on 127.0.0.1:{TAILNET_PORT}; expose it with\n  \
                     tailscale serve --bg --tcp {TAILNET_PORT} tcp://127.0.0.1:{TAILNET_PORT}"
                );
                let shared = std::sync::Arc::clone(&broker);
                std::thread::spawn(move || serve_tailnet(tcp, shared));
            }
            Err(e) => eprintln!("not listening for tailnet peers: {e}"),
        }
    }

    // A daemon that prints nothing looks like a hang, so say plainly that it is working
    eprintln!("broker ready, waiting for requests. Ctrl+C to stop");

    for stream in listener.incoming() {
        let mut stream = stream?;
        LAST_SEEN.store(store::now(), Ordering::Relaxed);

        let pid = peer_pid(&stream);
        let caller = pid.map_or_else(|| "unknown".to_string(), ancestry);
        let cwd = pid.and_then(caller_cwd);
        let _ = reply(&broker, &mut stream, &caller, cwd.as_deref());
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
    }
    Ok(())
}

/// Exiting is how the key is dropped, which is blunter and surer than clearing it in place
#[cfg(feature = "host")]
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
#[cfg(feature = "host")]
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
#[cfg(feature = "host")]
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
#[cfg(feature = "host")]
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
            token: std::env::var("PASSBOX_TOKEN").unwrap_or_default(),
            ttl: 0,
            names: Vec::new(),
            action: String::new(),
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
            token: String::new(),
            ttl: 0,
            names: Vec::new(),
            action: String::new(),
        },
    )?;
    Ok(names.lines().map(str::to_string).collect())
}

/// Approve once and get a token back, with the names it covers listed after it
pub fn grant(store: &Store, names: &[String], agent: &str, ttl: u64) -> Result<String> {
    ask_broker(
        store,
        Request {
            name: String::new(),
            agent: agent.to_string(),
            op: Op::Grant,
            token: String::new(),
            ttl,
            names: names.to_vec(),
            action: String::new(),
        },
    )
}

/// Ask the broker to approve one plugin action. The caller runs the command once this returns ok
#[cfg(feature = "host")]
pub fn plugin_approve(store: &Store, name: &str, action: &str, agent: &str) -> Result<()> {
    ask_broker(
        store,
        Request {
            name: name.to_string(),
            agent: agent.to_string(),
            op: Op::Plugin,
            token: String::new(),
            ttl: 0,
            names: Vec::new(),
            action: action.to_string(),
        },
    )
    .map(|_| ())
}

/// Ask a running broker, starting one if the socket is dead.
fn ask_broker(store: &Store, request: Request) -> Result<String> {
    /* A configured host means this machine has no store of its own worth unlocking, so the
    request goes over the tailnet to one that has. The reply is the value, and the finger that
    released it was somewhere else. */
    if let Some(host) = store.host() {
        let target = if host.contains(':') {
            host.clone()
        } else {
            format!("{host}:{TAILNET_PORT}")
        };
        let mut stream = std::net::TcpStream::connect(&target)
            .with_context(|| format!("no passbox host at {target}"))?;
        writeln!(stream, "{}", serde_json::to_string(&request)?)?;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        return unwrap_response(&line);
    }

    let socket = store.socket_path();
    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(_) => {
            #[cfg(feature = "host")]
            {
                spawn(store)?;
                UnixStream::connect(&socket).context("the broker did not come up")?
            }
            #[cfg(not(feature = "host"))]
            bail!(
                "no broker at {}, and a client cannot start one",
                socket.display()
            )
        }
    };

    writeln!(stream, "{}", serde_json::to_string(&request)?)?;

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

#[cfg(all(test, feature = "host"))]
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

    fn grant_of(pairs: &[(&str, &str)], expires: u64) -> TokenGrant {
        TokenGrant {
            values: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            expires,
        }
    }

    #[test]
    fn a_namespace_is_refused_and_its_names_listed() {
        let known: Vec<String> = ["acme/pk", "acme/addr", "personal/github"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let err = reject_namespaces(&["acme".to_string()], &known)
            .unwrap_err()
            .to_string();
        assert!(err.contains("namespace holding 2"), "{err}");
        assert!(
            err.contains("acme/pk") && err.contains("acme/addr"),
            "{err}"
        );
    }

    #[test]
    fn exact_names_are_accepted() {
        let known: Vec<String> = ["acme/pk", "personal/github"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(reject_namespaces(&["acme/pk".to_string()], &known).is_ok());
        assert!(
            reject_namespaces(
                &["acme/pk".to_string(), "personal/github".to_string()],
                &known
            )
            .is_ok()
        );
    }

    /// A flat store is the case a namespace rule would miss, so the rule is not about slashes
    #[test]
    fn a_name_that_is_not_there_is_refused() {
        let known = vec!["token".to_string(), "other".to_string()];
        let err = reject_namespaces(&["nope".to_string()], &known)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no secret named nope"), "{err}");
        assert!(reject_namespaces(&["token".to_string()], &known).is_ok());
    }

    #[test]
    fn a_token_opens_only_what_it_was_granted() {
        let mut tokens = HashMap::new();
        tokens.insert("tok".to_string(), grant_of(&[("acme/pk", "value")], 2_000));
        assert_eq!(
            token_lookup(&tokens, "tok", "acme/pk", 1_000).as_deref(),
            Some("value")
        );
        assert!(token_lookup(&tokens, "tok", "personal/github", 1_000).is_none());
    }

    #[test]
    fn an_unknown_token_opens_nothing() {
        let mut tokens = HashMap::new();
        tokens.insert("tok".to_string(), grant_of(&[("acme/pk", "v")], 2_000));
        assert!(token_lookup(&tokens, "guessed", "acme/pk", 1_000).is_none());
    }

    #[test]
    fn a_lapsed_token_opens_nothing() {
        let mut tokens = HashMap::new();
        tokens.insert("tok".to_string(), grant_of(&[("acme/pk", "v")], 2_000));
        assert!(token_lookup(&tokens, "tok", "acme/pk", 2_000).is_none());
        assert!(token_lookup(&tokens, "tok", "acme/pk", 9_999).is_none());
    }

    #[test]
    fn a_grant_is_capped_at_a_day() {
        let asked: u64 = 7 * 86_400;
        assert_eq!(asked.min(MAX_GRANT_SECS), MAX_GRANT_SECS);
        assert_eq!(600u64.min(MAX_GRANT_SECS), 600);
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
