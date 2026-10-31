//! The audit log: one encrypted record per release, refusal or window use.

#[cfg(feature = "host")]
use super::Broker;
use crate::crypto;
use crate::store::{self, Store};
use age::x25519;
use anyhow::Result;
use serde::Serialize;
use std::io::Write;

/// One audit line before it is stamped and encrypted. A call names only the fields it has
#[derive(Serialize, Default)]
pub(super) struct Entry<'a> {
    pub(super) agent: &'a str,
    pub(super) secret: &'a str,
    pub(super) decision: &'a str,
    pub(super) caller: &'a str,
    /// The approval a token read or a child came from, absent for everything else
    #[serde(skip_serializing_if = "str::is_empty")]
    pub(super) grant: &'a str,
    /// A plugin call's arguments as its prompt showed them, absent for everything else
    #[serde(skip_serializing_if = "str::is_empty")]
    pub(super) args: &'a str,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    at: u64,
    #[serde(flatten)]
    entry: &'a Entry<'a>,
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
        &Entry {
            agent,
            secret,
            decision,
            caller,
            args,
            ..Entry::default()
        },
    )
}

pub(super) fn append_audit_to(
    store: &Store,
    to: &x25519::Recipient,
    entry: &Entry<'_>,
) -> Result<()> {
    let record = AuditRecord {
        at: store::now(),
        entry,
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
        append_audit_to(
            &self.store,
            &to,
            &Entry {
                agent,
                secret,
                decision,
                caller,
                args,
                ..Entry::default()
            },
        )
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
        append_audit_to(
            &self.store,
            to,
            &Entry {
                agent,
                secret,
                decision,
                caller,
                ..Entry::default()
            },
        )
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;

    /// The JSON after the timestamp, which is the part of a record that is the same every run
    fn fields(record: &str) -> &str {
        let (at, rest) = record
            .split_once(',')
            .expect("a record has more than one field");
        assert!(
            at.starts_with("{\"at\":"),
            "the record does not start with at: {record}"
        );
        rest
    }

    /// `passbox audit` reads these lines back, so their shape is the format
    #[test]
    fn a_record_is_one_encrypted_json_line_without_an_empty_grant_or_args() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let key = x25519::Identity::generate();
        let to = key.to_public();
        append_audit_to(
            &store,
            &to,
            &Entry {
                agent: "claude",
                secret: "a/b",
                decision: "released",
                caller: "zsh < claude",
                ..Entry::default()
            },
        )
        .unwrap();
        append_audit_to(
            &store,
            &to,
            &Entry {
                agent: "job",
                secret: "a/b",
                decision: "by token",
                caller: "cron",
                grant: "g1",
                args: "q=1",
            },
        )
        .unwrap();

        let text = std::fs::read_to_string(store.audit_path()).unwrap();
        let records: Vec<String> = text
            .lines()
            .map(|l| String::from_utf8(crypto::decrypt_line(l, &key).unwrap().to_vec()).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            fields(&records[0]),
            r#""agent":"claude","secret":"a/b","decision":"released","caller":"zsh < claude"}"#
        );
        assert_eq!(
            fields(&records[1]),
            r#""agent":"job","secret":"a/b","decision":"by token","caller":"cron","grant":"g1","args":"q=1"}"#
        );
    }
}
