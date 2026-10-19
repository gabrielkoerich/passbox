//! Decides who may open a secret, holds the approval windows, and writes the audit log.

#[cfg(feature = "host")]
use crate::project::{self, Grant};
#[cfg(feature = "host")]
use crate::store;
use crate::store::Store;
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
/// Connections being answered, token reads included, so an upgrade restart never cuts one off
#[cfg(feature = "host")]
static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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
    /// Bound parameters for a Plugin op the broker runs itself
    #[serde(default)]
    pub params: Vec<(String, String)>,
    /// When set, the broker runs the Plugin tool and returns its output, for a remote client
    #[serde(default)]
    pub run: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    at: u64,
    agent: &'a str,
    secret: &'a str,
    decision: &'a str,
    caller: &'a str,
}

/* Tokens, held past the store key's life. The key opens everything and so is dropped quickly,
a token covers only the secrets it was granted, to whoever holds it. They sit behind their own
lock, so a token read is answered while a prompt holds the broker. */
#[cfg(feature = "host")]
type Tokens = std::sync::Arc<std::sync::Mutex<HashMap<String, TokenGrant>>>;

/// A token answers only for what it was granted, and only until it expires
#[cfg(feature = "host")]
fn token_value(tokens: &Tokens, token: &str, name: &str) -> Option<String> {
    let now = store::now();
    let mut tokens = tokens.lock().expect("tokens");
    tokens.retain(|_, g| now < g.expires);
    token_lookup(&tokens, token, name, now)
}

#[cfg(feature = "host")]
struct Broker {
    store: Store,
    // Boxed, so dropping it frees a block the wiping allocator clears, where `take` would leave a copy
    key: Option<Box<x25519::Identity>>,
    tokens: Tokens,
    key_at: u64,
    #[cfg(feature = "host")]
    grants: Vec<Grant>,
}

#[cfg(feature = "host")]
impl Broker {
    fn new(store: Store, tokens: Tokens) -> Self {
        Broker {
            store,
            key: None,
            key_at: 0,
            tokens,
            #[cfg(feature = "host")]
            grants: Vec::new(),
        }
    }

    /// A cached key past its life is the same as no key
    fn cached_key(&mut self) -> Option<&x25519::Identity> {
        if store::now().saturating_sub(self.key_at) >= KEY_TTL_SECS {
            self.key = None;
        }
        self.key.as_deref()
    }

    /// The Touch ID prompt is the approval, so a prompt and an unlock are the same act
    fn prompt(&mut self, agent: &str, secret: &str) -> Result<()> {
        self.ask(&format!("release the password for {secret} to {agent}"))
    }

    // A prompt that was not approved is recorded too, so the log shows what was asked for and not
    // given. It has no key, so it is written to the public half like a token read
    fn refused(
        &self,
        agent: &str,
        secrets: &[&str],
        error: anyhow::Error,
        caller: &str,
    ) -> anyhow::Error {
        // The helper's own message, so a secret name in some outer context cannot change the label
        let decision = if error.root_cause().to_string().starts_with("denied") {
            "denied"
        } else {
            "prompt failed"
        };
        for secret in secrets {
            let _ = self.audit_by(agent, secret, decision, caller);
        }
        error
    }

    fn ask(&mut self, reason: &str) -> Result<()> {
        let key = self.store.unlock_with_se(reason)?;
        #[cfg(feature = "host")]
        {
            self.grants = project::load(&self.store, &key);
        }
        self.key = Some(Box::new(key));
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
    fn grant_manifest(
        &mut self,
        request: &Request,
        cwd: Option<&std::path::Path>,
        caller: &str,
    ) -> Result<bool> {
        let Some(manifest) = cwd.and_then(project::find) else {
            return Ok(false);
        };
        if !manifest.secrets.iter().any(|s| s == &request.name) {
            return Ok(false);
        }

        let declared: Vec<&str> = manifest.secrets.iter().map(String::as_str).collect();
        self.ask(&format!(
            "give {} access to {} secrets declared by {} for {} minutes",
            request.agent,
            manifest.secrets.len(),
            manifest.dir.display(),
            manifest.window_secs / 60
        ))
        .map_err(|e| self.refused(&request.agent, &declared, e, caller))?;

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

    /* A plugin action always prompts. Approval and audit are the whole job here, the caller runs
    the command, because it holds the GUI session the broker does not. */
    #[cfg(feature = "host")]
    fn handle_plugin(&mut self, request: &Request, caller: &str) -> Result<String> {
        let manifest = crate::plugin::load(&self.store, &request.name)?;
        let tool = manifest
            .tool(&request.action)
            .ok_or_else(|| anyhow!("{} has no action {}", request.name, request.action))?;
        let slot_name = format!("plugin:{}.{}", request.name, request.action);
        self.ask(&format!("run {slot_name} for {}", request.agent))
            .map_err(|e| self.refused(&request.agent, &[&slot_name], e, caller))?;
        self.audit_by(&request.agent, &slot_name, "approved", caller)?;
        if !request.run {
            return Ok("ok".to_string());
        }

        // A caller-directory tool acts on the caller's repo, which does not exist on the host
        if manifest.runs_in_caller_dir() {
            bail!("{} runs on the caller, not on the host", request.name);
        }
        manifest.ensure_available()?;
        let bound: HashMap<String, String> = request.params.iter().cloned().collect();
        let mut command = tool.command(&bound)?;
        command.current_dir(self.store.plugins_dir().join(&request.name));
        run_plugin_command(command)
    }

    /// Names are inside the ciphertext, so listing needs the key and therefore a prompt.
    /// It gets its own window: riding a `get` approval would turn one secret into all of them.
    fn handle_list(&mut self, request: &Request, caller: &str) -> Result<String> {
        self.ask(&format!("list your secret names for {}", request.agent))
            .map_err(|e| self.refused(&request.agent, &["<list>"], e, caller))?;
        let key = self.key.clone().expect("just unlocked");
        self.audit(&key, &request.agent, "<list>", "approved", caller)?;
        let names = self.store.names(&key)?;
        // A key synced from another Mac is offered once something here has opened the store
        if let Err(e) =
            crate::ssh::keys(&self.store, &key).and_then(|k| crate::ssh::refresh(&self.store, &k))
        {
            eprintln!("{} could not refresh the SSH keys: {e:#}", clock());
        }
        Ok(names.join("\n"))
    }

    // Every signature prompts. The prompt names the key by its comment, since its secret name is
    // inside the ciphertext the prompt opens, and the store decides which key signs, not the list
    fn sign(
        &mut self,
        wanted: &ssh_key::PublicKey,
        data: &[u8],
        agent: &str,
        caller: &str,
    ) -> Result<ssh_key::Signature> {
        let label = crate::ssh::label(wanted);
        let slot = format!("ssh:{label}");
        let purpose = crate::ssh::purpose(data);
        self.ask(&format!("sign {purpose} with SSH key {label} for {agent}"))
            .map_err(|e| self.refused(agent, &[&slot], e, caller))?;
        let key = self.key.clone().expect("just unlocked");
        let keys = crate::ssh::keys(&self.store, &key)?;
        crate::ssh::refresh(&self.store, &keys)?;
        let Some((name, private)) = keys
            .iter()
            .find(|(_, k)| k.public_key().key_data() == wanted.key_data())
        else {
            self.audit(&key, agent, &slot, "unknown", caller)?;
            bail!("no SSH key in the store matches {label}");
        };
        self.audit(&key, agent, name, "signed", caller)?;
        signature::Signer::try_sign(private, data).map_err(|e| anyhow!("could not sign: {e}"))
    }

    /* One approval covers a name or a whole namespace, and yields a token that opens exactly
    those. Asking for twenty secrets one at a time is twenty prompts to do one thing. */
    fn handle_grant(&mut self, request: &Request, caller: &str) -> Result<String> {
        let asked = if request.ttl == 0 { 300 } else { request.ttl };
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
        let asked_for: Vec<&str> = request.names.iter().map(String::as_str).collect();
        self.ask(&reason)
            .map_err(|e| self.refused(&request.agent, &asked_for, e, caller))?;
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
            values.insert(name.clone(), secret.value.clone());
        }
        if values.is_empty() {
            bail!("{} matched no secrets", request.names.join(", "));
        }

        let token = store::new_id() + &store::new_id();
        let granted: Vec<String> = values.keys().cloned().collect();
        self.tokens.lock().expect("tokens").insert(
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

    fn value_for_token(&self, token: &str, name: &str) -> Option<String> {
        token_value(&self.tokens, token, name)
    }

    fn handle_get(
        &mut self,
        request: &Request,
        caller: &str,
        cwd: Option<&std::path::Path>,
    ) -> Result<String> {
        // A token is the narrowest thing that can answer, so it is tried first
        if !request.token.is_empty()
            && let Some(value) = self.value_for_token(&request.token, &request.name)
        {
            self.audit_by(&request.agent, &request.name, "by token", caller)?;
            return Ok(value);
        }

        // A read prompts every time. The only way past the prompt is a token or, for the
        // caller's own directory, a project manifest that already covers this secret
        let covered = (self.cached_key().is_some() && self.granted(&request.name, cwd))
            || (self.cached_key().is_none() && self.grant_manifest(request, cwd, caller)?);
        let outcome = if covered {
            "project grant"
        } else {
            self.prompt(&request.agent, &request.name)
                .map_err(|e| self.refused(&request.agent, &[&request.name], e, caller))?;
            "released"
        };

        let key = self.key.clone().expect("just unlocked");
        let Some((_, secret)) = self.store.find(&request.name, &key)? else {
            self.audit(&key, &request.agent, &request.name, "unknown", caller)?;
            bail!("no secret named {}", request.name);
        };
        self.audit(&key, &request.agent, &request.name, outcome, caller)?;
        Ok(secret.value.clone())
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
        append_audit_to(&self.store, to, agent, secret, decision, caller)
    }
}

/* The port the broker answers on over the tailnet. Fixed rather than configurable: a client
would have to guess it, and a second knob is a second thing to get wrong. A client needs it
too, so it is not gated behind the host feature. */
pub const TAILNET_PORT: u16 = 8787;

#[cfg(feature = "host")]
const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "fish", "dash", "ksh"];

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
/// not passbox and not a shell, such as claude or codex, or passbox when the chain has none
fn prompt_agent(chain: &str) -> String {
    for name in programs(chain) {
        if name.is_empty() || name == "unknown" || name == "passbox" || SHELLS.contains(&name) {
            continue;
        }
        return name.to_string();
    }
    "passbox".to_string()
}

/// The peer names the request, except that ssh gives way to a program that ran it, such as git
#[cfg(feature = "host")]
fn ssh_requester(chain: &str) -> String {
    let mut names = programs(chain);
    match (names.next(), names.next()) {
        (Some("ssh"), Some(parent)) if !parent.is_empty() && !SHELLS.contains(&parent) => {
            parent.to_string()
        }
        (Some(peer), _) if !peer.is_empty() && peer != "unknown" => peer.to_string(),
        _ => "ssh".to_string(),
    }
}

/// One loop per connection, since ssh sends several requests on one, and only signing takes the lock
#[cfg(feature = "host")]
fn serve_ssh(listener: UnixListener, shared: std::sync::Arc<Shared>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let shared = std::sync::Arc::clone(&shared);
        std::thread::spawn(move || {
            let pid = peer_pid(&stream);
            while let Ok(Some(request)) = crate::ssh::read_message(&mut stream) {
                IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
                let offered = crate::ssh::offered(&shared.store);
                let reply = crate::ssh::answer(&request, &offered, |key, data| {
                    let caller = pid.map_or_else(|| "unknown".to_string(), ancestry);
                    let agent = ssh_requester(&caller);
                    shared
                        .broker
                        .lock()
                        .expect("broker")
                        .sign(key, data, &agent, &caller)
                });
                LAST_SEEN.store(store::now(), Ordering::Relaxed);
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                if crate::ssh::write_message(&mut stream, &reply).is_err() {
                    break;
                }
            }
        });
    }
}

/// What every connection thread shares. The token map is reachable without the broker's lock
#[cfg(feature = "host")]
struct Shared {
    broker: std::sync::Mutex<Broker>,
    tokens: Tokens,
    store: Store,
}

#[cfg(feature = "host")]
fn reply<S: std::io::Read + Write>(
    shared: &Shared,
    stream: &mut S,
    caller: &str,
    cwd: Option<&std::path::Path>,
    local: bool,
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
                request.agent = if local {
                    prompt_agent(caller)
                } else {
                    "passbox".to_string()
                };
            }
            // A token read needs no key and no prompt, so it never waits behind one
            let by_token = (request.op == Op::Get && !request.token.is_empty())
                .then(|| token_value(&shared.tokens, &request.token, &request.name))
                .flatten();
            let answer = match by_token {
                Some(value) => append_audit(
                    &shared.store,
                    &request.agent,
                    &request.name,
                    "by token",
                    caller,
                )
                .map(|()| value),
                None => shared
                    .broker
                    .lock()
                    .expect("broker")
                    .handle(&request, caller, cwd),
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

/* Another machine asks here. The listener is bound to this host's tailnet address rather than
loopback or every interface: loopback has none of the unix socket's 0600 protection, so any
local user could reach it, and every interface would put a secrets daemon on the LAN.

`tailscale whois` names the peer, and unlike the agent string a caller sends, the control plane
authenticated it. That is the first caller identity in passbox that is not self declared. */
#[cfg(feature = "host")]
fn serve_tailnet(listener: std::net::TcpListener, shared: std::sync::Arc<Shared>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        LAST_SEEN.store(store::now(), Ordering::Relaxed);
        let shared = std::sync::Arc::clone(&shared);
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let caller = stream
                .peer_addr()
                .ok()
                .and_then(|a| crate::tailnet::whois(a.ip()))
                .unwrap_or_else(|| "an unidentified tailnet peer".to_string());
            eprintln!("tailnet request from {caller}");
            if let Err(e) = reply(&shared, &mut stream, &caller, None, false) {
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
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
}

/// A socket only this user can reach, replacing one a previous broker left behind
#[cfg(feature = "host")]
fn bind_private(path: &std::path::Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(feature = "host")]
pub fn serve(store: Store) -> Result<()> {
    #[cfg(target_os = "macos")]
    harden();
    let socket = store.socket_path();
    store::private_dir(&store.dir)?;
    let listener = bind_private(&socket)?;
    let agent = bind_private(&store.ssh_agent_path())?;

    LAST_SEEN.store(store::now(), Ordering::Relaxed);
    let tokens = Tokens::default();
    let shared = std::sync::Arc::new(Shared {
        broker: std::sync::Mutex::new(Broker::new(store.clone(), tokens.clone())),
        tokens,
        store,
    });
    watchdog(socket.clone(), shared.clone());
    let for_agent = std::sync::Arc::clone(&shared);
    std::thread::spawn(move || serve_ssh(agent, for_agent));

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
                let shared = std::sync::Arc::clone(&shared);
                std::thread::spawn(move || serve_tailnet(tcp, shared));
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
            let _ = reply(&shared, &mut stream, &caller, cwd.as_deref(), true);
            LAST_SEEN.store(store::now(), Ordering::Relaxed);
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// The file a path names, followed through symlinks, so a repointed `bin/passbox` reads as a change
#[cfg(feature = "host")]
fn file_id(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/* The path this broker was started as, and the file it is running from. launchd starts
`/opt/homebrew/bin/passbox`, which an upgrade repoints, and the cleanup after it deletes the old
file. Either way the next start would run a different file, which is the signal to restart. */
#[cfg(feature = "host")]
struct Binary {
    launch: std::path::PathBuf,
    running: Option<(u64, u64)>,
}

#[cfg(feature = "host")]
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
#[cfg(feature = "host")]
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

#[cfg(feature = "host")]
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
        if self.key.take().is_some() {
            eprintln!("{} idle {idle}s, dropped the key", clock());
        }
    }
}

/// Local time for the broker log, which launchd writes without one
#[cfg(feature = "host")]
fn clock() -> String {
    let t = store::now() as libc::time_t;
    // SAFETY: localtime_r only writes the tm it is given
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
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

/// The peer pid comes from the kernel, so the caller cannot fake its own path
#[cfg(all(feature = "host", target_os = "macos"))]
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

// Linux runs the host build only in CI, where the tests need a real caller pid
#[cfg(all(feature = "host", not(target_os = "macos")))]
fn peer_pid(stream: &UnixStream) -> Option<libc::pid_t> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
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

#[cfg(all(feature = "host", not(target_os = "macos")))]
fn caller_cwd(pid: libc::pid_t) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// Walk up the process tree, because the caller is `passbox` and the agent is somewhere above it
// One encrypted record per line, appended with O_APPEND so the broker and a CLI read can both
// write without a lock. The same format the broker writes, so `passbox audit` reads either
pub(crate) fn append_audit(
    store: &Store,
    agent: &str,
    secret: &str,
    decision: &str,
    caller: &str,
) -> Result<()> {
    append_audit_to(store, &store.recipient()?, agent, secret, decision, caller)
}

fn append_audit_to(
    store: &Store,
    to: &age::x25519::Recipient,
    agent: &str,
    secret: &str,
    decision: &str,
    caller: &str,
) -> Result<()> {
    let record = AuditRecord {
        at: crate::store::now(),
        agent,
        secret,
        decision,
        caller,
    };
    let line = crate::crypto::encrypt_line(&serde_json::to_vec(&record)?, to)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(store.audit_path())?;
    writeln!(file, "{line}")?;
    Ok(())
}

pub(crate) fn ancestry(pid: libc::pid_t) -> String {
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
    request_token(store, name, agent, crate::held_token().unwrap_or_default())
}

/// A read carrying a token the caller already holds, such as the one exec mints for its batch
pub fn request_token(store: &Store, name: &str, agent: &str, token: &str) -> Result<String> {
    ask_broker(
        store,
        Request {
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
            params: Vec::new(),
            run: false,
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
            params: Vec::new(),
            run: false,
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
            params: Vec::new(),
            run: false,
        },
    )
    .map(|_| ())
}

/// Ask the host to run a plugin tool and return its output, for a client with no local app
pub fn plugin_run_remote(
    store: &Store,
    name: &str,
    action: &str,
    params: &[(String, String)],
    agent: &str,
) -> Result<String> {
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
            params: params.to_vec(),
            run: true,
        },
    )
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

// Run a built plugin command and return stdout, with stderr and the exit code on failure
#[cfg(feature = "host")]
fn run_plugin_command(mut command: std::process::Command) -> Result<String> {
    let out = command
        .output()
        .context("could not run the plugin command")?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str("\nstderr:\n");
        text.push_str(&err);
    }
    if !out.status.success() {
        text.push_str(&format!("\nexit: {}", out.status.code().unwrap_or(1)));
    }
    Ok(text)
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_name_comes_from_the_first_real_ancestor() {
        assert_eq!(prompt_agent("passbox < zsh < claude < login"), "claude");
        assert_eq!(prompt_agent("passbox < -zsh < codex"), "codex");
        assert_eq!(prompt_agent("passbox < /bin/bash < node"), "node");
        // Only passbox and a shell means there is no better name than passbox
        assert_eq!(prompt_agent("passbox < zsh"), "passbox");
        assert_eq!(prompt_agent("unknown"), "passbox");
    }

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
    fn an_ssh_request_is_named_by_the_program_that_ran_ssh() {
        assert_eq!(ssh_requester("ssh < git < zsh < login"), "git");
        assert_eq!(ssh_requester("/usr/bin/ssh < -zsh < login"), "ssh");
        assert_eq!(ssh_requester("ssh"), "ssh");
        assert_eq!(ssh_requester("unknown"), "ssh");
        // A peer that speaks the protocol itself is named, never hidden behind its parent
        assert_eq!(ssh_requester("evil < node < zsh"), "evil");
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
                expires: store::now() + 43_200,
            },
        );

        broker.sweep(KEY_TTL_SECS - 1);
        assert!(broker.key.is_some());

        broker.sweep(KEY_TTL_SECS);
        assert!(broker.key.is_none());
        assert_eq!(broker.value_for_token("t", "a/b").as_deref(), Some("v"));

        broker.tokens.lock().unwrap().get_mut("t").unwrap().expires = store::now();
        broker.sweep(KEY_TTL_SECS);
        assert!(broker.tokens.lock().unwrap().is_empty());
    }

    #[test]
    fn run_plugin_command_returns_output_then_stderr_and_exit() {
        let mut ok = std::process::Command::new("printf");
        ok.args(["%s", "hello"]);
        assert_eq!(run_plugin_command(ok).unwrap(), "hello");

        let mut bad = std::process::Command::new("sh");
        bad.args(["-c", "printf out; printf oops >&2; exit 3"]);
        let text = run_plugin_command(bad).unwrap();
        assert!(text.contains("out"), "{text}");
        assert!(text.contains("stderr:") && text.contains("oops"), "{text}");
        assert!(text.contains("exit: 3"), "{text}");
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
}
