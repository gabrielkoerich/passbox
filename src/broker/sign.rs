//! SSH signatures: the prompt, or the signing window that covers one key and one host key.

use super::Broker;
use super::audit::append_audit_to;
use super::server::clock;
use super::windows::{SshWindow, fingerprint, ssh_window_open};
use crate::{plugin, ssh, store};
use anyhow::{Result, anyhow, bail};
use std::fmt::Write as _;

impl Broker {
    /* A signature prompts unless a window from `[ssh.windows]` covers this key and host key. The
    prompt names the key by its comment, since its secret name is inside the ciphertext the prompt
    opens, and the store decides which key signs, not the list */
    pub(super) fn sign(
        &mut self,
        wanted: &ssh_key::PublicKey,
        data: &[u8],
        host: Option<&ssh_key::PublicKey>,
        agent: &str,
        caller: &str,
    ) -> Result<ssh_key::Signature> {
        let label = ssh::label(wanted);
        let slot = format!("ssh:{label}");
        let purpose = ssh::purpose(data);
        // A bad section opens no window, it never stops a login
        let policy = ssh::windows(&self.store).unwrap_or_else(|e| {
            eprintln!("{} {e:#}", clock());
            ssh::Windows::default()
        });
        let window_key = host.map(|h| (fingerprint(wanted), fingerprint(h)));
        if let Some(window_key) = &window_key
            && let Some(window) = ssh_window_open(
                &self.ssh_windows,
                &policy,
                self.ssh_approved.as_deref(),
                window_key,
                store::now(),
            )
        {
            let to = format!("to {} {}", window.host, window_key.1);
            let signed = signature::Signer::try_sign(&*window.private, data);
            self.audit_by(agent, &window.name, "by window", caller, &to)?;
            return signed.map_err(|e| anyhow!("could not sign: {e}"));
        }

        let known = host.map(|_| ssh::known_hosts()).unwrap_or_default();
        let listed = host.and_then(|h| policy.listed(h, &known));
        let shown = match (&listed, host) {
            (Some((name, _)), _) => Some(name.clone()),
            (None, Some(h)) => ssh::known_names(&known, h).into_iter().next(),
            (None, None) => None,
        };
        let to = shown
            .as_ref()
            .map(|n| format!(" to {n}"))
            .unwrap_or_default();
        let mut reason = format!("sign {purpose}{to} with SSH key {label} for {agent}");
        if let Some((name, secs)) = &listed {
            let span = plugin::span(*secs);
            let _ = write!(
                reason,
                ", and its logins to {name} for {span} without asking"
            );
        }

        let stored = ssh::approved(&self.store);
        // The prompt promises a window, so a record not yet checked against the store key is asked for again
        let verified = self.ssh_approved.as_deref() == Some(policy.hash.as_str())
            || self.key.as_deref().is_some_and(|k| {
                stored
                    .as_ref()
                    .is_some_and(|a| a.hash == policy.hash && a.verify_for("ssh", k))
            });
        let changed = listed.is_some() && !verified;
        if changed {
            reason = format!(
                "allow SSH windows {} for {agent}, then {reason}",
                policy.shown()
            );
        }

        self.ask(&reason)
            .map_err(|e| self.refused(agent, &[&slot], e, caller))?;
        let key = self.key.clone().expect("just unlocked");
        // Windows opened under the old section do not carry over to the new one
        if changed {
            ssh::approve(&self.store, &key, &policy.hash)?;
            self.ssh_windows.clear();
        }

        // A record this broker did not sign is ignored, so a forged one opens nothing
        let trusted = changed
            || verified
            || stored.is_some_and(|a| a.hash == policy.hash && a.verify_for("ssh", &key));
        self.ssh_approved = trusted.then(|| policy.hash.clone());
        let keys = ssh::keys(&self.store, &key)?;
        ssh::refresh(&self.store, &keys)?;
        let Some((name, private)) = keys
            .iter()
            .find(|(_, k)| k.public_key().key_data() == wanted.key_data())
        else {
            self.audit(&key, agent, &slot, "unknown", caller)?;
            bail!("no SSH key in the store matches {label}");
        };

        let mut args = match (&shown, &window_key) {
            (Some(n), Some((_, h))) => format!("to {n} {h}"),
            (None, Some((_, h))) => format!("to {h}"),
            _ => String::new(),
        };
        if let (true, Some((host_name, secs)), Some(window_key)) = (trusted, &listed, window_key) {
            let _ = write!(args, ", window {}", plugin::span(*secs));
            self.ssh_windows.insert(
                window_key,
                SshWindow {
                    opened: store::now(),
                    host: host_name.clone(),
                    name: name.clone(),
                    private: Box::new(private.clone()),
                },
            );
        }
        let to = key.to_public();
        append_audit_to(&self.store, &to, agent, name, "signed", caller, "", &args)?;
        signature::Signer::try_sign(private, data).map_err(|e| anyhow!("could not sign: {e}"))
    }
}
