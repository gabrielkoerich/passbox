//! Decides who may open a secret, holds the approval windows, and writes the audit log.

mod audit;
mod caller;
mod client;
#[cfg(feature = "host")]
mod plugins;
#[cfg(feature = "host")]
mod server;
#[cfg(feature = "host")]
mod sign;
#[cfg(feature = "host")]
mod tokens;
#[cfg(feature = "host")]
mod windows;

pub(crate) use audit::append_audit;
pub(crate) use caller::own_ancestry;
#[cfg(feature = "host")]
pub(crate) use client::plugin_approve;
pub(crate) use client::{grant, list, plugin_run_remote, request, request_token};
#[cfg(feature = "host")]
pub(crate) use server::serve;

#[cfg(feature = "host")]
use crate::project::{self, Grant};
#[cfg(feature = "host")]
use crate::ssh;
#[cfg(feature = "host")]
use crate::store::{self, Store};
#[cfg(feature = "host")]
use age::x25519;
#[cfg(feature = "host")]
use anyhow::{Result, bail};
#[cfg(feature = "host")]
use audit::append_audit_to;
use serde::{Deserialize, Serialize};
#[cfg(feature = "host")]
use server::{Origin, clock};
#[cfg(feature = "host")]
use std::collections::HashMap;
#[cfg(feature = "host")]
use tokens::{TokenGrant, Tokens, new_token, reject_namespaces, token_value};
#[cfg(feature = "host")]
use windows::{SshWindow, SshWindowKey, Window, WindowKey};

/// The store key leaves memory after this long with no traffic
#[cfg(feature = "host")]
const KEY_TTL_SECS: u64 = 300;
/* A ceiling on how long one approval can carry. Without it a caller names its own expiry and
a token becomes a password that never lapses, which is the thing this exists to avoid. */
#[cfg(feature = "host")]
pub(crate) const MAX_GRANT_SECS: u64 = 86_400;

#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Op {
    #[default]
    Get,
    List,
    /// Approve a set of secrets once and hand back a token that opens only those
    Grant,
    /// Approve one plugin action, named by `name` and `action`
    Plugin,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Request {
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
pub(crate) struct Response {
    pub ok: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[cfg(feature = "host")]
struct Broker {
    store: Store,
    // Boxed, so dropping it frees a block the wiping allocator clears, where `take` would leave a copy
    key: Option<Box<x25519::Identity>>,
    tokens: Tokens,
    key_at: u64,
    grants: Vec<Grant>,
    // In memory only, like tokens, so a restart ends every window
    windows: HashMap<WindowKey, Window>,
    /// The `[plugins.windows]` hash this run verified, set by an approval or a checked record
    approved: Option<String>,
    // In memory only, so a restart ends every signing window too
    ssh_windows: HashMap<SshWindowKey, SshWindow>,
    /// The `[ssh.windows]` hash this run verified, as `approved` is for plugins
    ssh_approved: Option<String>,
}

#[cfg(feature = "host")]
impl Broker {
    fn new(store: Store, tokens: Tokens) -> Self {
        Broker {
            store,
            key: None,
            key_at: 0,
            tokens,
            grants: Vec::new(),
            windows: HashMap::new(),
            approved: None,
            ssh_windows: HashMap::new(),
            ssh_approved: None,
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
            let _ = self.audit_by(agent, secret, decision, caller, "");
        }
        error
    }

    fn ask(&mut self, reason: &str) -> Result<()> {
        let key = self.store.unlock_with_se(reason)?;
        self.grants = project::load(&self.store, &key);
        self.key = Some(Box::new(key));
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
        origin: Origin,
    ) -> Result<String> {
        match request.op {
            Op::Get => self.handle_get(request, caller, cwd),
            Op::List => self.handle_list(request, caller),
            Op::Grant => self.handle_grant(request, caller),
            Op::Plugin => {
                // A tailnet caller is the host whois named, every caller on this Mac is one scope
                let scope = match origin {
                    Origin::Local => "local",
                    Origin::Tailnet => caller,
                };
                self.handle_plugin(request, caller, scope)
            }
        }
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
        if let Err(e) = ssh::rebuild(&self.store, &key) {
            eprintln!("{} could not refresh the SSH keys: {e:#}", clock());
        }
        Ok(names.join("\n"))
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
        let mut stamps = HashMap::new();
        for name in &wanted {
            let Some((id, secret)) = self.store.find(name, &key)? else {
                continue;
            };
            stamps.insert(name.clone(), (id.clone(), self.store.stamp(&id)?));
            values.insert(name.clone(), secret.value.clone());
        }
        if values.is_empty() {
            bail!("{} matched no secrets", request.names.join(", "));
        }

        let token = new_token();
        let grant = store::new_id();
        let granted: Vec<String> = values.keys().cloned().collect();
        self.tokens.lock().expect("tokens").insert(
            token.clone(),
            TokenGrant {
                values,
                stamps,
                expires: store::now() + ttl,
                grant: grant.clone(),
            },
        );
        for name in &granted {
            let to = key.to_public();
            append_audit_to(
                &self.store,
                &to,
                &request.agent,
                name,
                "granted",
                caller,
                &grant,
                "",
            )?;
        }
        Ok(format!("{token}\n{}", granted.join("\n")))
    }

    fn value_for_token(&self, token: &str, name: &str) -> Option<(String, String)> {
        token_value(&self.tokens, &self.store, token, name)
    }

    fn handle_get(
        &mut self,
        request: &Request,
        caller: &str,
        cwd: Option<&std::path::Path>,
    ) -> Result<String> {
        // A token is the narrowest thing that can answer, so it is tried first
        if !request.token.is_empty()
            && let Some((value, grant)) = self.value_for_token(&request.token, &request.name)
        {
            let to = self.store.recipient()?;
            append_audit_to(
                &self.store,
                &to,
                &request.agent,
                &request.name,
                "by token",
                caller,
                &grant,
                "",
            )?;
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
}

/* The port the broker answers on over the tailnet. Fixed rather than configurable: a client
would have to guess it, and a second knob is a second thing to get wrong. A client needs it
too, so it is not gated behind the host feature. */
pub(crate) const TAILNET_PORT: u16 = 8787;

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;

    #[test]
    fn a_grant_is_capped_at_a_day() {
        let asked: u64 = 7 * 86_400;
        assert_eq!(asked.min(MAX_GRANT_SECS), MAX_GRANT_SECS);
        assert_eq!(600u64.min(MAX_GRANT_SECS), 600);
    }
}
