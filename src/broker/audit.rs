//! The audit log: one encrypted record per release, refusal or window use.

#[cfg(feature = "host")]
use super::Broker;
use crate::crypto;
use crate::store::{self, Store};
use age::x25519;
use anyhow::Result;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct AuditRecord<'a> {
    at: u64,
    agent: &'a str,
    secret: &'a str,
    decision: &'a str,
    caller: &'a str,
    /// The approval a token read or a child came from, absent for everything else
    #[serde(skip_serializing_if = "str::is_empty")]
    grant: &'a str,
    /// A plugin call's arguments as its prompt showed them, absent for everything else
    #[serde(skip_serializing_if = "str::is_empty")]
    args: &'a str,
}

// One encrypted record per line, appended with O_APPEND so the broker and a CLI read can both
// write without a lock. The same format the broker writes, so `passbox audit` reads either
pub(crate) fn append_audit(
    store: &Store,
    agent: &str,
    secret: &str,
    decision: &str,
    caller: &str,
    args: &str,
) -> Result<()> {
    append_audit_to(
        store,
        &store.recipient()?,
        agent,
        secret,
        decision,
        caller,
        "",
        args,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one field of the record, named at every call"
)]
pub(super) fn append_audit_to(
    store: &Store,
    to: &x25519::Recipient,
    agent: &str,
    secret: &str,
    decision: &str,
    caller: &str,
    grant: &str,
    args: &str,
) -> Result<()> {
    let record = AuditRecord {
        at: store::now(),
        agent,
        secret,
        decision,
        caller,
        grant,
        args,
    };
    let line = crypto::encrypt_line(&serde_json::to_vec(&record)?, to)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(store.audit_path())?;
    writeln!(file, "{line}")?;
    Ok(())
}

#[cfg(feature = "host")]
impl Broker {
    /* A token read has no key by design, and the audit line only ever needed the public half,
    so the record is written to the store's recipient instead. Token reads stay auditable. */
    pub(super) fn audit_by(
        &self,
        agent: &str,
        secret: &str,
        decision: &str,
        caller: &str,
        args: &str,
    ) -> Result<()> {
        let to = self.store.recipient()?;
        append_audit_to(&self.store, &to, agent, secret, decision, caller, "", args)
    }

    pub(super) fn audit(
        &self,
        key: &x25519::Identity,
        agent: &str,
        secret: &str,
        decision: &str,
        caller: &str,
    ) -> Result<()> {
        self.audit_to(&key.to_public(), agent, secret, decision, caller)
    }

    pub(super) fn audit_to(
        &self,
        to: &x25519::Recipient,
        agent: &str,
        secret: &str,
        decision: &str,
        caller: &str,
    ) -> Result<()> {
        append_audit_to(&self.store, to, agent, secret, decision, caller, "", "")
    }
}
